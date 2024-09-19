/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "rdmo.h"
#include "core/ucp_worker.h"

#include <core/ucp_ep.h>
#include <core/ucp_rkey.h>
#include <proto/proto_single.h>
#include <proto/proto_init.h>

#include <proto/proto_common.inl>
#include <rma/rma.inl>

#define RDMO_ENABLE_STAT    0
#define RDMO_FETCH_OFFSET   1

#if RDMO_ENABLE_STAT
static size_t max_outstanding = 0;
static size_t x               = 0;
static size_t prev_y          = 0;
static double sum_y           = 0;
static double res             = 0;


static inline void stat_reset()
{
    x      = 0;
    sum_y  = 0;
    res    = 0;
}
#endif /* ENABLE_RDMO_STAT */

static inline void stat_update(ucp_worker_h worker)
{
#if RDMO_ENABLE_STAT
    size_t y = worker->rdmo_outstanding;

    if (y > max_outstanding) {
        max_outstanding = y;
        if (max_outstanding % 100 == 0) {
            printf("worker %p: rdmo max outstanding %"PRIu64"\n", worker,
                   max_outstanding);
        }
    }

    sum_y += 0.5 * (prev_y + y);
    prev_y = y;
    if ((++x % 50000) == 0) {
        res = sum_y / x;
        printf("worker %p: rdmo outstanding stat %"PRIu64"\n",
               worker, (size_t)res);
        stat_reset();
    }
#endif /* ENABLE_RDMO_STAT */
}

ucs_status_ptr_t
ucp_rdmo_append_nbx(ucp_ep_h ep,
                    const void *buffer, size_t count,
                    uint64_t target, ucp_rkey_h target_rkey,
                    uint64_t append, ucp_rkey_h append_rkey,
                    const ucp_request_param_t *param)
{
#if HAVE_DOCA_UROM
    ucp_request_param_t am_param = *param;
    ucp_rdmo_append_hdr_t hdr;

    if (!(am_param.op_attr_mask & UCP_OP_ATTR_FIELD_FLAGS)) {
        am_param.op_attr_mask |= UCP_OP_ATTR_FIELD_FLAGS;
        am_param.flags         = 0;
    }

    am_param.flags |= UCP_AM_SEND_FLAG_REPLY |
                      UCP_AM_SEND_FLAG_COPY_HEADER |
                      UCP_AM_SEND_FLAG_EAGER;

    hdr.client_id   = ep->ext->remote_worker_id;
    hdr.target_addr = target;
    hdr.target_rkey = target_rkey->cache.rdmo_rkey;
    hdr.data_addr   = append;
    hdr.data_rkey   = append_rkey->cache.rdmo_rkey;  // should be available on DPU (imported)

    ucs_trace("target_addr %"PRIx64" target_key %"PRIx64,
              hdr.target_addr, hdr.target_rkey);
    return ucp_am_send_nbx(ep->ext->rdmo_eps[0], UCP_AM_ID_RDMO_APPEND, &hdr,
                           sizeof(hdr), buffer, count, &am_param);
#else /* HAVE_UROM */
    return UCS_STATUS_PTR(UCS_ERR_UNSUPPORTED);
#endif /* HAVE_UROM */
}

ucp_ep_h ucp_rdmo_dst_ep(ucp_worker_h worker, uint64_t id)
{
    ucp_ep_ext_t *ep_ext;

    khint_t i = kh_get(ucp_worker_eps_hash, &worker->eps_hash, id);
    if (i != kh_end(&worker->eps_hash)) {
        return kh_val(&worker->eps_hash, i);
    }

    /* TODO: optimize, try to reuse ptr_map ep_map */
    /* assume only 1 EP to the host */
    ucs_assertv(1 || ucs_list_length(&worker->all_eps) <= 2, "worker %p: all_ep %lu",
                worker, ucs_list_length(&worker->all_eps));
    ucs_list_for_each(ep_ext, &worker->all_eps, ep_list) {
        if (ep_ext->remote_worker_id == id) {
            return ep_ext->ep;
        }
    }

    return NULL;
}

static UCS_F_ALWAYS_INLINE void
ucp_rdmo_cache_put(ucp_worker_h worker,
                   const ucp_worker_rdmo_amo_cache_key_t *key,
                   const ucp_worker_rdmo_amo_cache_entry_t *entry)
{
    ucp_worker_rdmo_clients_cache_t *cache = &worker->rdmo_clients_cache;
    ucp_rdmo_client_cache_entry_t *client;
    ucp_rdmo_client_cache_t *targets;
    khint_t i;
    int r;

    i = kh_get(ucp_worker_rdmo_clients_cache, cache, key->client_id);
    if (i == kh_end(cache)) {
        ucs_queue_head_t *q = ucs_calloc(1, sizeof(ucs_queue_head_t),
                                         "rdmo_flush_ack_queue");
        ucs_queue_head_init(q);

        i = kh_put(ucp_worker_rdmo_clients_cache, cache, key->client_id, &r);
        ucs_assert(r >= 0);
        client = &kh_val(cache, i);
        kh_init_inplace(ucp_rdmo_client_cache, &client->targets);
        client->ep        = ucp_rdmo_dst_ep(worker, key->client_id);
        client->lock      = 0;
        client->pending_q = q;
    } else {
        client = &kh_val(cache, i);
    }

    ucs_assert(client->ep != NULL);
    targets = &client->targets;
    ucs_assert(kh_end(targets) ==
               kh_get(ucp_rdmo_client_cache, targets, key->target));

    i = kh_put(ucp_rdmo_client_cache, targets, key->target, &r);
    ucs_assert(r >= 0);
    kh_val(targets, i) = *entry;

    ucs_debug("client_id %"PRIx64": new cache entry %p target 0x%"PRIx64"[%d]",
              key->client_id, &kh_val(targets, i), key->target,
              kh_size(targets));
}

static UCS_F_ALWAYS_INLINE ucp_rdmo_client_cache_entry_t*
ucp_rdmo_cache_get_client(const ucp_worker_rdmo_clients_cache_t *cache,
                          uint64_t client_id)
{
    khint_t i = kh_get(ucp_worker_rdmo_clients_cache, cache, client_id);

    if (ucs_unlikely((i == kh_end(cache)))) {
        return NULL;
    }

    return &kh_val(cache, i);
}

static UCS_F_ALWAYS_INLINE ucp_worker_rdmo_amo_cache_entry_t*
ucp_rdmo_client_get_cache_entry(ucp_rdmo_client_cache_entry_t *client,
                                uint64_t target)
{
    khint_t i = kh_get(ucp_rdmo_client_cache, &client->targets, target);
    if (ucs_unlikely(i == kh_end(&client->targets))) {
        return NULL;
    }

    return &kh_val(&client->targets, i);
}

static UCS_F_ALWAYS_INLINE ucp_worker_rdmo_amo_cache_entry_t*
ucp_rdmo_cache_get(const ucp_worker_rdmo_clients_cache_t *cache,
                   const ucp_worker_rdmo_amo_cache_key_t *key)
{
    ucp_rdmo_client_cache_entry_t *client =
            ucp_rdmo_cache_get_client(cache, key->client_id);

    if (ucs_unlikely(client == NULL)) {
        return NULL;
    }

    return ucp_rdmo_client_get_cache_entry(client, key->target);
}

static UCS_F_ALWAYS_INLINE void
ucp_rdmo_client_del_cache_entry(ucp_rdmo_client_cache_entry_t *client,
                                uint64_t target)
{
    khint_t i = kh_get(ucp_rdmo_client_cache, &client->targets, target);

    ucs_assert(i != kh_end(&client->targets));
    kh_del(ucp_rdmo_client_cache, &client->targets, i);
}

void ucp_rdmo_cache_free(ucp_worker_rdmo_clients_cache_t *cache)
{
    ucp_rdmo_client_cache_entry_t client_cache;
    kh_foreach_value(cache, client_cache, {
        ucs_assert_always(kh_size(&client_cache.targets) == 0);
        kh_destroy_inplace(ucp_rdmo_client_cache, &client_cache.targets);
        ucs_assert_always(client_cache.lock == 0);
        ucs_free(client_cache.pending_q);
    });
    kh_clear(ucp_worker_rdmo_clients_cache, cache);
}

static void ucp_rdmo_append_put_callback(void *request, ucs_status_t status,
                                         void *user_data)
{
    ucp_request_t *req  = (ucp_request_t*)request - 1;
    ucp_worker_h worker = req->send.ep->worker;

    worker->rdmo_outstanding--;
    ucs_assert(worker->rdmo_outstanding >= 0);
    stat_update(worker);

    ucs_debug("complete put data %p", user_data);

    ucs_assert(status == UCS_OK);
#if UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF
    ucs_mpool_put_inline(user_data);
#else
    ucp_am_data_release(worker, user_data);
#endif
    ucp_request_free(request);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rdmo_append_put_data(ucp_ep_h ep,
                         ucp_worker_rdmo_amo_cache_entry_t *cache_entry,
                         void *data, size_t length)
{
#if UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF
    uint64_t *proxy_buf = ucs_mpool_get_inline(&cache_entry->ep->worker->rdmo_proxy_mp);
#endif /* UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF */

    ucp_request_param_t req_param = {
        .op_attr_mask             = UCP_OP_ATTR_FIELD_CALLBACK |
                                    UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send                  = ucp_rdmo_append_put_callback,
#if UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF
        .user_data                = proxy_buf
#else
        .user_data                = data
#endif /* UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF */
    };
    ucs_status_ptr_t ret_put;

#if UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF
    ucs_assert_always(proxy_buf != NULL);
    ucs_assert_always(length <= UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF_LEN);
    /* touch the buffer  */
    /* proxy_buf[0] = 0; */
    /*        or         */
    /* memcpy(proxy_buf, data, length); */
#endif /* UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF */

    ucs_debug("ep %p: append put %"PRIx64" offset %"PRIu64" data %p key %p",
              ep, cache_entry->append_buffer, cache_entry->append_offset, data,
              cache_entry->append_rkey);
    ret_put = ucp_put_nbx(ep,
#if UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF
                          proxy_buf,
#else
                          data,
#endif /* UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF */
                          length,
                          cache_entry->append_buffer +
                          cache_entry->append_offset,
                          cache_entry->append_rkey, &req_param);
    ucs_assertv_always((ret_put == NULL) ||
                       (UCS_PTR_STATUS(ret_put) == UCS_INPROGRESS),
                       "status: %s", ucs_status_string(UCS_PTR_STATUS(ret_put)));
    cache_entry->append_offset += length;
#if UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF
    return UCS_OK;
#else
    return UCS_INPROGRESS;
#endif /* UCP_RDMO_TEST_PERF_MPOOL_PROXY_BUF */
}

static ucs_status_t
ucp_rdmo_enqueue_data(ucp_worker_h worker, ucs_queue_head_t *pending_q,
                      const ucp_worker_rdmo_amo_cache_key_t *key,
                      void *data, size_t length)
{
    ucp_rdmo_cb_data_t *q_put = ucs_mpool_get_inline(&worker->rdmo_mp);

    if(ucs_unlikely(q_put == NULL)) {
        return UCS_ERR_NO_MEMORY;
    }

    q_put->pending_elem.type            = UCP_RDMO_PENDING_ELEM_PUT_DATA;
    q_put->pending_elem.put_data.key    = *key;
    q_put->pending_elem.put_data.data   = data;
    q_put->pending_elem.put_data.length = length;
    ucs_queue_push(pending_q, &q_put->pending_elem.q_elem);

    ucs_debug("client_id %"PRIx64" enqueue %"PRIu64" bytes",
              key->client_id, length);

    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
ucp_rdmo_flush_send_ack(ucp_ep_h ep,
                        const ucp_rdmo_flush_ack_hdr_t *ack)
{
    ucp_request_param_t param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
        .flags        = UCP_AM_SEND_FLAG_COPY_HEADER
    };
    void *request     = ucp_am_send_nbx(ep, UCP_AM_ID_RDMO_FLUSH_ACK, ack,
                                        sizeof(*ack), NULL, 0, &param);

    if (UCS_PTR_IS_PTR(request)) {
        ucp_request_free(request);
    } else {
        ucs_assert(!UCS_PTR_IS_ERR(request));
    }
}

static void
ucp_rdmo_client_flush_completion(void *request, ucs_status_t status,
                                 void *user_data)
{
    ucp_rdmo_cb_data_t *data     = user_data;
    ucp_rdmo_flush_elem_t *flush = &data->flush;
    ucp_rdmo_flush_ack_hdr_t hdr = {
        .ep     = flush->hdr_ep,
        .status = ucs_likely(flush->status == UCS_OK) ? status : flush->status
    };

    ucs_debug("flush completion req %p, send ack to 0x%"PRIx64,
              request, flush->hdr_ep);
    ucp_rdmo_flush_send_ack(flush->reply_ep, &hdr);
    if (UCS_PTR_IS_PTR(request)) {
        ucp_request_free(request);
    }

    ucs_mpool_put_inline(user_data);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rdmo_client_flush_ack(ucp_ep_h ep, ucp_ep_h reply_ep, uint64_t hdr_ep,
                          ucs_status_t status)
{
    ucp_rdmo_cb_data_t *user_data = ucs_mpool_get_inline(&ep->worker->rdmo_mp);
    ucp_request_param_t param     = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send      = ucp_rdmo_client_flush_completion,
        .user_data    = user_data
    };
    void *req;

    if (user_data == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    user_data->flush.reply_ep = reply_ep;
    user_data->flush.hdr_ep   = hdr_ep;
    user_data->flush.status   = status;

    req = ucp_ep_flush_nbx(ep, &param);
    ucs_debug("flushing for 0x%"PRIx64" returned %p", hdr_ep, req);
    if (!UCS_PTR_IS_PTR(req)) {
        ucp_rdmo_client_flush_completion(NULL, UCS_PTR_STATUS(req), user_data);
        return UCS_PTR_STATUS(req);
    }

    return UCS_OK;
}

static void
ucp_rdmo_cache_flush_offset_completion(void *request, ucs_status_t status,
                                       void *user_data)
{
    ucs_mpool_put_inline(user_data);
    if (request != NULL) {
        ucp_request_free(request);
    }
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rdmo_cache_flush_offset(ucp_ep_h ep,
                            ucp_worker_rdmo_amo_cache_entry_t *entry)
{
    ucp_rdmo_cb_data_t *user_data = ucs_mpool_get_inline(&ep->worker->rdmo_mp);

    ucp_request_param_t fast = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS |
                        UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA,
        .flags        = UCP_OP_ATTR_FLAG_FAST_CMPL,
        .cb.send      = ucp_rdmo_cache_flush_offset_completion,
        .user_data    = user_data

    };
    void *req;

    user_data->put_offset = entry->append_offset;

    ucs_debug("put target 0x%"PRIu64" offset_val %"PRIu64,
              entry->target_buffer, entry->append_offset);
    req = ucp_put_nbx(ep, &user_data->put_offset, sizeof(user_data->put_offset),
                      entry->target_buffer, entry->target_rkey, &fast);
    if (UCS_PTR_IS_PTR(req)) {
        return UCS_OK;
    }

    ucp_rdmo_cache_flush_offset_completion(NULL, UCS_PTR_STATUS(req), user_data);
    return UCS_PTR_STATUS(req);
}

static inline ucs_status_t
ucp_rdmo_client_flush(ucp_rdmo_client_cache_entry_t *client, ucp_ep_h reply_ep,
                      uint64_t hdr_ep, int del)
{
    ucs_status_t status = UCS_OK;
    ucs_status_t op_status;
    ucp_worker_rdmo_amo_cache_entry_t *entry;
    uint64_t target;

    ucs_assert_always(client->lock == 0);

    kh_foreach_key(&client->targets, target, {
        entry = ucp_rdmo_client_get_cache_entry(client, target);
        ucs_assert(entry != NULL);
        op_status = ucp_rdmo_cache_flush_offset(client->ep, entry);
        if (op_status != UCS_OK) {
            status = op_status;
        }

        if (del) {
            ucp_rdmo_client_del_cache_entry(client, target);
        }
    });

    /* all puts for targets are posted, flush client */
    op_status = ucp_rdmo_client_flush_ack(client->ep, reply_ep, hdr_ep, status);
    return ucs_likely(status == UCS_OK) ? op_status : status;
}

static inline void
ucp_rdmo_client_do_pending(ucp_rdmo_client_cache_entry_t *client)
{
    ucp_ep_h ep                            = client->ep;
    ucp_worker_rdmo_clients_cache_t *cache = &ep->worker->rdmo_clients_cache;
    ucp_rdmo_pending_elem_t *e;
    ucp_worker_rdmo_amo_cache_entry_t *entry;
    ucs_status_t status;

    ucs_queue_for_each_extract(e, client->pending_q, q_elem, 1) {
        if (ucs_likely(e->type == UCP_RDMO_PENDING_ELEM_PUT_DATA)) {
            entry  = ucp_rdmo_cache_get(cache, &e->put_data.key);
            ucs_assert_always(entry != NULL);
            status = ucp_rdmo_append_put_data(ep, entry, e->put_data.data,
                                              e->put_data.length);
        } else {
            ucs_assert(e->type == UCP_RDMO_PENDING_ELEM_CLIENT_FLUSH);
            ucp_rdmo_client_flush(client, e->flush.reply_ep, e->flush.hdr_ep, 0);
        }

        ucs_assert_always(!UCS_PTR_IS_ERR(status));
        ucs_mpool_put_inline(e);
    }
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rdmo_client_flush_handle_empty(const ucp_rdmo_client_cache_entry_t *client,
                                   ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    /* flush before any append */
    ucp_rdmo_flush_ack_hdr_t ack = {
        .ep     = hdr_ep,
        .status = UCS_OK
    };

    if ((client != NULL) && (kh_size(&client->targets) != 0)) {
        return UCS_ERR_NO_PROGRESS;
    }

    ucs_debug("client empty, send ack to 0x%"PRIx64, hdr_ep);
    ucp_rdmo_flush_send_ack(reply_ep, &ack);
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rdmo_client_flush_handle_locked(ucp_rdmo_client_cache_entry_t *client,
                                    ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    ucp_rdmo_cb_data_t *data;
    ucp_rdmo_pending_elem_t *elem;

    if (client->lock == 0) {
        return UCS_ERR_NO_PROGRESS;
    }

    data = ucs_mpool_get(&client->ep->worker->rdmo_mp);
    if (ucs_unlikely(data == NULL)) {
        return UCS_ERR_NO_MEMORY;
    }

    elem = &data->pending_elem;

    ucs_queue_push(client->pending_q, &elem->q_elem);
    elem->ep             = client->ep;
    elem->type           = UCP_RDMO_PENDING_ELEM_CLIENT_FLUSH;
    elem->flush.reply_ep = reply_ep;
    elem->flush.hdr_ep   = hdr_ep;
    return UCS_OK;
}

static ucs_status_t
ucp_rdmo_client_flush_start(ucp_worker_h worker, uint64_t client_id,
                                       ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    ucp_rdmo_client_cache_entry_t *client;
    ucs_status_t status;

    client = ucp_rdmo_cache_get_client(&worker->rdmo_clients_cache, client_id);
    status = ucp_rdmo_client_flush_handle_empty(client, reply_ep, hdr_ep);
    if (status != UCS_ERR_NO_PROGRESS) {
        return status;
    }

    status = ucp_rdmo_client_flush_handle_locked(client, reply_ep, hdr_ep);
    if (status != UCS_ERR_NO_PROGRESS) {
        return status;
    }

    ucp_rdmo_client_flush(client, reply_ep, hdr_ep, 1);
    return UCS_OK;
}

static void ucp_rdmo_offset_fetch_callback(void *request, ucs_status_t status,
                                           void *user_data)
{
    ucp_rdmo_cb_data_t *data                   = user_data;
    ucp_rdmo_fetch_offset_data_t *fetch_offset = &data->fetch_offset;
    ucp_worker_rdmo_amo_cache_key_t *key       = &fetch_offset->cache_key;
    ucp_rdmo_client_cache_entry_t* client;
    ucp_worker_rdmo_amo_cache_entry_t *entry;

    client = ucp_rdmo_cache_get_client(fetch_offset->cache, key->client_id);
    entry  = ucp_rdmo_client_get_cache_entry(client, key->target);

    ucs_debug("client_id %"PRIx64": got offset %"PRIu64" lock %u",
               key->client_id, fetch_offset->offset, client->lock);

    ucs_assert_always(status == UCS_OK);
    ucs_assert(entry != NULL);
    ucs_assert(entry->fetch_cb_data == user_data);
    ucs_assert(fetch_offset->offset != UINT64_MAX);

    entry->fetch_cb_data = NULL;
    entry->append_offset = fetch_offset->offset;

    ucs_assert_always(client->lock > 0);
    if (--client->lock == 0) {
        ucp_rdmo_client_do_pending(client);
    }

    ucs_mpool_put(data);
    ucp_request_free(request);
}

static ucs_status_t
ucp_rdmo_offset_fetch(ucp_rdmo_client_cache_entry_t *client,
                      const ucp_rdmo_append_hdr_t *append_hdr,
                      const ucp_worker_rdmo_amo_cache_key_t *cache_key,
                      ucp_rdmo_cb_data_t **cb_data_p)
{
    ucp_ep_h ep                 = client->ep;
    ucp_worker_h worker         = ep->worker;
    ucp_rdmo_cb_data_t *cb_data = ucs_mpool_get(&worker->rdmo_mp);
    ucp_request_param_t param   = {
        .op_attr_mask           = UCP_OP_ATTR_FIELD_CALLBACK |
                                  UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send                = ucp_rdmo_offset_fetch_callback,
        .user_data              = cb_data
    };
    ucp_worker_rdmo_clients_cache_t *cache = &worker->rdmo_clients_cache;
    ucs_status_ptr_t status_ptr;

    ++client->lock;

    ucs_assert_always(cb_data != NULL);
    cb_data->fetch_offset.offset    = UINT64_MAX;
    cb_data->fetch_offset.cache_key = *cache_key;
    cb_data->fetch_offset.cache     = cache;


    ucs_debug("client_id %"PRIx64": get offset start for target 0x%"PRIx64,
              append_hdr->client_id, append_hdr->target_addr);
    status_ptr = ucp_get_nbx(ep, &cb_data->fetch_offset.offset,
                             sizeof(cb_data->fetch_offset.offset),
                             append_hdr->target_addr,
                             (ucp_rkey_h)append_hdr->target_rkey, &param);
    if (ucs_unlikely(!UCS_PTR_IS_PTR(status_ptr))) {
        ucs_error("offset get ret value: %s",
                  ucs_status_string(UCS_PTR_STATUS(status_ptr)));
        return UCS_PTR_STATUS(status_ptr);
    }

    *cb_data_p = cb_data;
    return UCS_INPROGRESS;
}

ucs_status_t
ucp_rdmo_append_handler(void *arg, const void *header, size_t header_length,
                        void *data, size_t length,
                        const ucp_am_recv_param_t *param)
{
#if 0
    ucs_assert(0);
    return UCS_ERR_NOT_IMPLEMENTED;
#else

    ucp_worker_h worker                     = arg;
    const ucp_rdmo_append_hdr_t *append_hdr = header;
    ucp_worker_rdmo_amo_cache_key_t cache_key;
    ucp_rdmo_client_cache_entry_t *client;
    ucp_worker_rdmo_amo_cache_entry_t *cache_entry;
    ucs_status_t status;

    ucs_assert(worker->context->config.ext.proto_enable);

    ucs_info("worker %p: client %"PRIx64" append %"PRIu64, worker,
              append_hdr->client_id, length);
    worker->rdmo_outstanding++;
    stat_update(worker);

    cache_key.client_id = append_hdr->client_id;
    cache_key.target    = append_hdr->target_addr;
    cache_entry         = ucp_rdmo_cache_get(&worker->rdmo_clients_cache,
                                             &cache_key);
    if (ucs_unlikely(cache_entry == NULL)) {
        /* miss, init new entry */
        ucp_worker_rdmo_amo_cache_entry_t new_cache_entry = {
            .append_buffer   = append_hdr->data_addr,
#if RDMO_FETCH_OFFSET
            .append_offset   = UINT64_MAX,
#else
            .append_offset   = 0,
#endif /* RDMO_FETCH_OFFSET */
            .append_rkey     = (ucp_rkey_h)append_hdr->data_rkey,
            .target_buffer   = append_hdr->target_addr,
            .target_rkey     = (ucp_rkey_h)append_hdr->target_rkey,
            .fetch_cb_data   = NULL
        };

        ucp_rdmo_cache_put(worker, &cache_key, &new_cache_entry);
        cache_entry = ucp_rdmo_cache_get(&worker->rdmo_clients_cache, &cache_key);
        ucs_assert(cache_entry != NULL);
        ucs_debug("client %"PRIx64": miss cache entry target 0x%"PRIx64
                  " append rkey %p hdr_rkey %p",
                  cache_key.client_id, cache_key.target,
                  cache_entry->append_rkey, (ucp_rkey_h)append_hdr->data_rkey);
    } else {
        ucs_debug("client %"PRIx64": hit cache entry target 0x%"PRIx64
                  " append rkey %p hdr_rkey %p, offset %"PRIu64,
                  cache_key.client_id, cache_key.target,
                  cache_entry->append_rkey, (ucp_rkey_h)append_hdr->data_rkey,
                  cache_entry->append_offset);
    }

    client = ucp_rdmo_cache_get_client(&worker->rdmo_clients_cache,
                                       cache_key.client_id);
    if (RDMO_FETCH_OFFSET &&
        ucs_unlikely(cache_entry->append_offset == UINT64_MAX)) {
        if (cache_entry->fetch_cb_data == NULL) {
            status = ucp_rdmo_offset_fetch(
                    client, append_hdr, &cache_key,
                    (ucp_rdmo_cb_data_t **)&cache_entry->fetch_cb_data);
            ucs_assert_always(!UCS_STATUS_IS_ERR(status));
        }

        if (client->lock) {
            status = ucp_rdmo_enqueue_data(worker, client->pending_q,
                                           &cache_key, data, length);
            return UCS_INPROGRESS;
        }
    }

    return ucp_rdmo_append_put_data(client->ep, cache_entry, data, length);
#endif
}

ucs_status_t
ucp_rdmo_flush_handler(void *arg, const void *header, size_t header_length,
                       void *data, size_t length,
                       const ucp_am_recv_param_t *recv_param)
{
    ucp_worker_h worker                   = arg;
    const ucp_rdmo_flush_hdr_t *flush_hdr = header;

    ucs_debug("client_id %"PRIx64": got flush req from ep 0x%"PRIx64,
              flush_hdr->client_id, flush_hdr->ep);

    return ucp_rdmo_client_flush_start(worker, flush_hdr->client_id,
                                       recv_param->reply_ep, flush_hdr->ep);
}

ucs_status_t
ucp_rdmo_flush_ack_handler(void *arg, const void *header, size_t header_length,
                           void *data, size_t length,
                           const ucp_am_recv_param_t *param)
{
    const ucp_rdmo_flush_ack_hdr_t *hdr = header;
    ucp_ep_h ep                         = (ucp_ep_h)hdr->ep;

    ucs_assert(hdr->status == UCS_OK);

    ucs_debug("ep %p: got ack", ep);
    ucp_ep_rma_remote_request_completed(ep);

    return UCS_OK;
}

static ucs_status_t
ucp_proto_rdmo_append_proxy_init(const ucp_proto_init_params_t *init_params)
{
    ucp_proto_single_init_params_t params        = {
        .super.super         = *init_params,
        .super.latency       = 0,
        .super.overhead      = 0,
        .super.cfg_thresh    = UCS_MEMUNITS_AUTO,
        .super.cfg_priority  = 0,
        .super.min_length    = 0,
        .super.max_length    = SIZE_MAX,
        .super.min_iov       = 0,
        .super.min_frag_offs = UCP_PROTO_COMMON_OFFSET_INVALID,
        .super.max_frag_offs = UCP_PROTO_COMMON_OFFSET_INVALID, //ucs_offsetof(uct_iface_attr_t, cap.am.max_bcopy),
        .super.max_iov_offs  = UCP_PROTO_COMMON_OFFSET_INVALID,
        .super.hdr_size      = 0,
        .super.send_op       = UCT_EP_OP_ATOMIC_FETCH,
        .super.memtype_op    = UCT_EP_OP_LAST, //UCT_EP_OP_GET_SHORT,
        .super.flags         = /*UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY    |*/
                               UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY    |
                               UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS |
                               /*UCP_PROTO_COMMON_INIT_FLAG_ERR_HANDLING | */
                               UCP_PROTO_COMMON_INIT_FLAG_SINGLE_FRAG,
        .super.exclude_map   = 0,
        .lane_type           = UCP_LANE_TYPE_AMO,
        .tl_cap_flags        = UCT_IFACE_FLAG_PUT_SHORT |
                               UCT_IFACE_FLAG_PUT_ZCOPY |
                               UCT_IFACE_FLAG_ATOMIC_DEVICE
    };

    if (!(init_params->worker->context->config.features & UCP_FEATURE_RDMO_PROXY)) {
        return UCS_ERR_UNSUPPORTED;
    }

//    if  ((init_params->rkey_config_key != NULL) ||
//         (init_params->rkey_cfg_index  != 0)) {
//        return UCS_ERR_UNSUPPORTED;
//    }

    if ((init_params->select_param->dt_class != UCP_DATATYPE_CONTIG) ||
        !ucp_proto_init_check_op(init_params,
                                 UCS_BIT(UCP_OP_ID_RDMO_APPEND_PROXY))) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_single_init(&params);
}

static void
ucp_proto_rdmo_append_proxy_query(const ucp_proto_query_params_t *params,
                                  ucp_proto_query_attr_t *attr)
{
    ucs_assertv(0, "ucp_proto_rdmo_append_proxy_query: %s",
                ucs_status_string(UCS_ERR_NOT_IMPLEMENTED));
}

static ucs_status_t
ucp_proto_rdmo_append_proxy_progress(uct_pending_req_t *self)
{
    ucs_assertv(0, "ucp_proto_rdmo_append_proxy_progress: %s",
                ucs_status_string(UCS_ERR_NOT_IMPLEMENTED));
    return UCS_ERR_NOT_IMPLEMENTED;
}

static void
ucp_proto_rdmo_append_proxy_abort(ucp_request_t *request, ucs_status_t status)
{
    ucs_assertv(0, "ucp_proto_rdmo_append_proxy_abort: %s",
                ucs_status_string(UCS_ERR_NOT_IMPLEMENTED));
}

static ucs_status_t ucp_proto_rdmo_append_proxy_reset(ucp_request_t *request)
{
    ucs_assertv(0, "ucp_proto_rdmo_append_proxy_reset: %s",
                ucs_status_string(UCS_ERR_NOT_IMPLEMENTED));
    return UCS_ERR_NOT_IMPLEMENTED;
}

ucp_proto_t ucp_rdmo_append_proxy_proto = {
    .name     = "rdmo/append/proxy",
    .desc     = "TODO",
    .flags    = 0,
    .init     = ucp_proto_rdmo_append_proxy_init,
    .query    = ucp_proto_rdmo_append_proxy_query,
    .progress = {ucp_proto_rdmo_append_proxy_progress},
    .abort    = ucp_proto_rdmo_append_proxy_abort,
    .reset    = ucp_proto_rdmo_append_proxy_reset
};
