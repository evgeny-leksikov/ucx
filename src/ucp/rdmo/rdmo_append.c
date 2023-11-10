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
#if HAVE_UROM
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
    khint_t i = kh_get(ucp_worker_rdmo_clients_cache, cache, key->client_id);
    ucp_rdmo_client_cache_t *targets;
    int r;

    if (i == kh_end(cache)) {
        i = kh_put(ucp_worker_rdmo_clients_cache, cache, key->client_id, &r);
        ucs_assert(r >= 0);
        kh_val(cache, i).ep = ucp_rdmo_dst_ep(worker, key->client_id);
        kh_init_inplace(ucp_rdmo_client_cache, &kh_val(cache, i).targets);
    }

    ucs_assert_always(kh_val(cache, i).ep != NULL);
    targets = &kh_val(cache, i).targets;
    ucs_assert_always(kh_end(targets) ==
                      kh_get(ucp_rdmo_client_cache, targets, key->target));

    i = kh_put(ucp_rdmo_client_cache, targets, key->target, &r);
    ucs_assert(r >= 0);
    kh_val(targets, i) = *entry;

    ucs_info("client_id %"PRIx64": new cache entry %p target 0x%"PRIx64,
             key->client_id, &kh_val(targets, i), key->target);
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
ucp_rdmo_cache_get(const ucp_worker_rdmo_clients_cache_t *cache,
                   const ucp_worker_rdmo_amo_cache_key_t *key)
{
    ucp_rdmo_client_cache_entry_t *client =
            ucp_rdmo_cache_get_client(cache, key->client_id);
    khint_t i;

    if (ucs_unlikely(client == NULL)) {
        return NULL;
    }

    i = kh_get(ucp_rdmo_client_cache, &client->targets, key->target);
    if (ucs_unlikely((i == kh_end(cache)))) {
        return NULL;
    }

    return &kh_val(&client->targets, i);
}

static UCS_F_ALWAYS_INLINE void
ucp_rdmo_cache_del(ucp_worker_rdmo_clients_cache_t *cache,
                   const ucp_worker_rdmo_amo_cache_key_t *key)
{
    khint_t i = kh_get(ucp_worker_rdmo_clients_cache, cache, key->client_id);
    ucp_rdmo_client_cache_t *targets;

    ucs_assert_always(i != kh_end(cache));
    targets = &kh_val(cache, i).targets;
    i       = kh_get(ucp_rdmo_client_cache, targets, key->target);
    ucs_assert_always(i != kh_end(targets));

    kh_del(ucp_rdmo_client_cache, targets, i);
    ucs_info("client %"PRIx64": del cache entry target 0x%"PRIx64,
             key->client_id, key->target);
}

static void ucp_rdmo_append_put_callback(void *request, ucs_status_t status,
                                         void *user_data)
{
    ucp_request_t *req  = (ucp_request_t*)request - 1;
    ucp_worker_h worker = req->send.ep->worker;

    worker->rdmo_outstanding--;
    ucs_assert_always(worker->rdmo_outstanding >= 0);
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

    ucs_debug("put %"PRIx64" offset %"PRIu64" data %p",
              cache_entry->append_buffer, cache_entry->append_offset, data);
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
ucp_rdmo_enqueue_data(ucp_rdmo_cb_data_t *cb_data, void *data, size_t length)
{
    ucp_worker_h worker       = cb_data->fetch_offset.put_ep->worker;
    ucp_rdmo_cb_data_t *q_put = ucs_mpool_get_inline(&worker->rdmo_mp);

    if(ucs_unlikely(q_put == NULL)) {
        return UCS_ERR_NO_MEMORY;
    }

    q_put->queued_put.data   = data;
    q_put->queued_put.length = length;
    cb_data->fetch_offset.put_queue_len++;
    ucs_queue_push(&cb_data->fetch_offset.put_queue, &q_put->queued_put.q_elem);

    ucs_info("client_id %"PRIx64" enqueue %"PRIu64" bytes total %"PRIu64" data chunks",
             cb_data->fetch_offset.cache_key.client_id, length, 
             cb_data->fetch_offset.put_queue_len);

    return UCS_OK;
}

static inline void
ucp_rdmo_put_dequeued_data(ucp_ep_h ep,
                           ucp_worker_rdmo_amo_cache_entry_t *entry,
                           ucp_rdmo_cb_data_t *fetch_cb_data)
{
    ucs_queue_head_t *q = &fetch_cb_data->fetch_offset.put_queue;
    ucp_rdmo_queued_put_data_t *e;
    ucs_status_t status;

    ucs_info("client_id %"PRIx64" dequeue %"PRIu64" data chunks, entry %p needs flush %d",
             fetch_cb_data->fetch_offset.cache_key.client_id,
             fetch_cb_data->fetch_offset.put_queue_len,
             entry, entry->flush.is_requested);

    ucs_queue_for_each_extract(e, q, q_elem, 1) {
        fetch_cb_data->fetch_offset.put_queue_len--;
        status = ucp_rdmo_append_put_data(ep, entry, e->data, e->length);
        ucs_assert_always(!UCS_PTR_IS_ERR(status));
        ucs_mpool_put_inline(e);
    }
}

static UCS_F_ALWAYS_INLINE int
ucp_rdmo_cache_flush_offset(ucp_ep_h ep,
                            ucp_worker_rdmo_amo_cache_entry_t *entry,
                            ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    static const ucp_request_param_t dummy = {
        .op_attr_mask = 0
    };
    void *req;

    if (ucs_unlikely(entry->fetch_cb_data != NULL)) {
        ucs_info("entry %p: flush 0x%"PRIx64" to %p locked",
                 entry, hdr_ep, reply_ep);
        if (entry->flush.is_requested) {
            return UCS_ERR_NO_PROGRESS;
            ucs_assert_always(entry->flush.reply_ep == reply_ep);
            ucs_assert_always(entry->flush.hdr_ep   == hdr_ep);
        } else {
            entry->flush.is_requested = 1;
            entry->flush.reply_ep     = reply_ep;
            entry->flush.hdr_ep       = hdr_ep;
            return UCS_INPROGRESS;
        }
    }

    if (entry->flush.is_requested) {
        ucs_info("entry %p: flush 0x%"PRIx64" to %p unlocked",
                 entry, hdr_ep, reply_ep);
        entry->flush.is_requested = 0;
    }

    req = ucp_put_nbx(ep, &entry->append_offset, sizeof(entry->append_offset),
                      entry->target_buffer, entry->target_rkey, &dummy);
    if (UCS_PTR_IS_PTR(req)) {
        ucp_request_free(req);
    }

    return UCS_OK;
}

static void
ucp_rdmo_flush_send_ack(ucp_ep_h ep,
                        const ucp_rdmo_flush_ack_hdr_t *ack)
{
    ucp_request_param_t param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
        .flags        = UCP_AM_SEND_FLAG_COPY_HEADER
    };

    void *request = ucp_am_send_nbx(ep, UCP_AM_ID_RDMO_FLUSH_ACK, ack,
                                    sizeof(*ack), NULL, 0, &param);

    if (UCS_PTR_IS_PTR(request)) {
        ucp_request_free(request);
    } else {
        ucs_assert(!UCS_PTR_IS_ERR(request));
    }
}

static void
ucp_rdmo_target_flush_completion(void *request, ucs_status_t status,
                                 void *user_data)
{
    ucp_rdmo_cb_data_t *data   = user_data;
    data->flush_ack.hdr.status = status;

    ucs_assert(status == UCS_OK);

    ucs_info("flush completion, send ack to 0x%"PRIx64, data->flush_ack.hdr.ep);
    ucp_rdmo_flush_send_ack(data->flush_ack.ack_ep, &data->flush_ack.hdr);
    if (UCS_PTR_IS_PTR(request)) {
        ucp_request_free(request);
    }

    ucs_mpool_put_inline(user_data);
}

static void
ucp_rdmo_flush_client(ucp_ep_h ep, ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    ucp_rdmo_cb_data_t *user_data = ucs_mpool_get_inline(&ep->worker->rdmo_mp);
    ucp_request_param_t param     = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send      = ucp_rdmo_target_flush_completion,
        .user_data    = user_data
    };
    void *req;

    user_data->flush_ack.ack_ep     = reply_ep;
    user_data->flush_ack.hdr.ep     = hdr_ep;
    user_data->flush_ack.hdr.status = UCS_OK;

    req = ucp_ep_flush_nbx(ep, &param);
    ucs_info("flushing for 0x%"PRIx64" returned %p", hdr_ep, req);
    if (!UCS_PTR_IS_PTR(req)) {
        ucp_rdmo_target_flush_completion(NULL, UCS_PTR_STATUS(req), user_data);
    }
}

static inline ucs_status_t
ucp_rdmo_flush_entry(ucp_ep_h ep, ucp_worker_rdmo_amo_cache_entry_t *entry,
                     ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    ucs_status_t status;
    ucs_assert_always(entry != NULL);

    status = ucp_rdmo_cache_flush_offset(ep, entry, reply_ep, hdr_ep);
    if (status != UCS_OK) {
        /* locked by fetch offset, re-try on completion */
        return status;
    }

    if (entry->flush.is_requested) {
        ucs_assert_always(reply_ep == entry->flush.reply_ep);
        ucs_assert_always(hdr_ep   == entry->flush.hdr_ep);
    }

    ucp_rdmo_flush_client(ep, reply_ep, hdr_ep);

    return UCS_OK;
}

static ucs_status_t ucp_rdmo_try_flush(ucp_worker_h worker, uint64_t client_id,
                                       ucp_ep_h reply_ep, uint64_t hdr_ep)
{
    ucp_rdmo_client_cache_entry_t *client =
            ucp_rdmo_cache_get_client(&worker->rdmo_clients_cache, client_id);
    ucp_worker_rdmo_amo_cache_key_t cache_key = {
        .client_id = client_id,
        .target    = 0
    };
    ucp_worker_rdmo_amo_cache_entry_t *cache_entry;
    ucs_status_t status;

    if (ucs_unlikely(client == NULL) || (kh_size(&client->targets) == 0)) {
        /* flush before any append */
        ucp_rdmo_flush_ack_hdr_t ack = {
            .ep     = hdr_ep,
            .status = UCS_OK
        };

        ucs_info("client %"PRIx64": empty ack to ep 0x%"PRIx64, client_id, hdr_ep);
        ucp_rdmo_flush_send_ack(reply_ep, &ack);
        return UCS_OK;
    }

    kh_foreach_key(&client->targets, cache_key.target, {
        cache_entry = ucp_rdmo_cache_get(&worker->rdmo_clients_cache,
                                         &cache_key);
        ucs_assert_always(cache_entry != NULL);

        status = ucp_rdmo_flush_entry(client->ep, cache_entry, reply_ep, hdr_ep);
        if (status == UCS_ERR_NO_PROGRESS) {
            /* locked by fetch offset, re-try on completion */
            continue;
        } else if (status == UCS_INPROGRESS) {
            break;
        }

        ucp_rdmo_cache_del(&worker->rdmo_clients_cache, &cache_key);
    });

    if (kh_size(&client->targets) == 0) {
        /* all puts for targets are posted, flush client */
        ucp_rdmo_flush_client(client->ep, reply_ep, hdr_ep);
    }

    return UCS_OK;
}

static void ucp_rdmo_offset_fetch_callback(void *request, ucs_status_t status,
                                           void *user_data)
{
    ucp_rdmo_cb_data_t *fetch_cb_data = user_data;
    ucp_ep_h ep                       = fetch_cb_data->fetch_offset.put_ep;
    ucp_worker_h worker               = ep->worker;

    ucp_worker_rdmo_amo_cache_key_t *key     =
            &fetch_cb_data->fetch_offset.cache_key;
    ucp_worker_rdmo_amo_cache_entry_t *entry =
            ucp_rdmo_cache_get(&worker->rdmo_clients_cache, key);

    ucs_status_t s;

    ucs_info("client_id %"PRIx64": got offset %"PRIu64,
             key->client_id, fetch_cb_data->fetch_offset.offset);

    ucs_assert_always(status == UCS_OK);
    ucs_assert_always(entry != NULL);
    ucs_assert_always(entry->fetch_cb_data == fetch_cb_data);
    ucs_assert_always(fetch_cb_data->fetch_offset.offset != UINT64_MAX);

    entry->append_offset = fetch_cb_data->fetch_offset.offset;

    ucp_rdmo_put_dequeued_data(ep, entry, fetch_cb_data);
    if (entry->fetch_cb_data != NULL) {
        entry->fetch_cb_data = NULL;
        if (entry->flush.is_requested) {
            s = ucp_rdmo_flush_entry(ep, entry, entry->flush.reply_ep,
                                     entry->flush.hdr_ep);
            ucs_assert_always(s == UCS_OK);
            ucp_rdmo_cache_del(&worker->rdmo_clients_cache, key);
        }
    }

    ucs_mpool_put(fetch_cb_data);
    ucp_request_free(request);
}

static ucs_status_t
ucp_rdmo_offset_fetch(ucp_ep_h ep, const ucp_rdmo_append_hdr_t *append_hdr,
                      const ucp_worker_rdmo_amo_cache_key_t *cache_key,
                      ucp_rdmo_cb_data_t **cb_data_p)
{
    ucp_rdmo_cb_data_t *cb_data = ucs_mpool_get(&ep->worker->rdmo_mp);
    ucp_request_param_t param   = {
        .op_attr_mask           = UCP_OP_ATTR_FIELD_CALLBACK |
                                  UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send                = ucp_rdmo_offset_fetch_callback,
        .user_data              = cb_data
    };
    ucs_status_ptr_t status_ptr;

    ucs_assert_always(cb_data != NULL);
    ucs_queue_head_init(&cb_data->fetch_offset.put_queue);
    cb_data->fetch_offset.put_queue_len = 0;
    cb_data->fetch_offset.cache_key     = *cache_key;
    cb_data->fetch_offset.put_ep        = ep;
    cb_data->fetch_offset.offset        = UINT64_MAX;

    ucs_info("client_id %"PRIx64": get offset start for target 0x%"PRIx64,
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
    ucp_worker_rdmo_amo_cache_entry_t *cache_entry;
    ucp_ep_h ep;
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
            .fetch_cb_data   = NULL,
            .flush.is_requested = 0,
            .flush.reply_ep     = 0,
            .flush.hdr_ep       = 0
        };

        ucp_rdmo_cache_put(worker, &cache_key, &new_cache_entry);
        cache_entry = ucp_rdmo_cache_get(&worker->rdmo_clients_cache, &cache_key);
        ucs_assert_always(cache_entry != NULL);
    } else {
        ucs_info("client %"PRIx64": hit cache entry", cache_key.client_id);
    }

    ep = ucp_rdmo_cache_get_client(&worker->rdmo_clients_cache,
                                   cache_key.client_id)->ep;
    if (RDMO_FETCH_OFFSET &&
        ucs_unlikely(cache_entry->append_offset == UINT64_MAX)) {
        if (cache_entry->fetch_cb_data == NULL) {
            status = ucp_rdmo_offset_fetch(
                    ep, append_hdr, &cache_key,
                    (ucp_rdmo_cb_data_t **)&cache_entry->fetch_cb_data);
            ucs_assert_always(!UCS_STATUS_IS_ERR(status));
        }

        if (cache_entry->fetch_cb_data != NULL) {
            status = ucp_rdmo_enqueue_data(cache_entry->fetch_cb_data,
                                           data, length);
            return UCS_INPROGRESS;
        }
    }

    return ucp_rdmo_append_put_data(ep, cache_entry, data, length);
#endif
}

ucs_status_t
ucp_rdmo_flush_handler(void *arg, const void *header, size_t header_length,
                       void *data, size_t length,
                       const ucp_am_recv_param_t *recv_param)
{
    ucp_worker_h worker                   = arg;
    const ucp_rdmo_flush_hdr_t *flush_hdr = header;

    ucs_info("client_id %"PRIx64": got flush req from ep 0x%"PRIx64,
             flush_hdr->client_id, flush_hdr->ep);

    ucp_rdmo_try_flush(worker, flush_hdr->client_id, recv_param->reply_ep,
                       flush_hdr->ep);
    return UCS_OK;
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
