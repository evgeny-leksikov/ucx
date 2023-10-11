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

ucs_status_ptr_t ucp_rdmo_append_nbx(ucp_ep_h ep,
                                     const void *buffer, size_t count,
                                     uint64_t target, ucp_rkey_h target_rkey,
                                     uint64_t append, ucp_rkey_h append_rkey)
{
#if HAVE_UROM
    ucp_request_param_t am_param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
        .flags        = UCP_AM_SEND_FLAG_REPLY | UCP_AM_SEND_FLAG_COPY_HEADER |
                        UCP_AM_SEND_FLAG_EAGER
    };
    ucp_rdmo_append_hdr_t hdr;

#if 0
    hdr.rdmo.id    = ep->ext->remote_worker_id;
    hdr.rdmo.op_id = UROM_RDMO_OP_APPEND;
    hdr.rdmo.flags = 0;
    hdr.append.ptr_addr  = target;
    hdr.append.ptr_rkey  = target_rkey->cache.rdmo_rkey;
    hdr.append.data_rkey = append_rkey->cache.rdmo_rkey;  // should be available on DPU (imported)

    return ucp_am_send_nbx(ep->ext->rdmo_eps[0], 0, &hdr, sizeof(hdr), buffer,
                           count, &am_param);
#else
    hdr.client_id   = ep->ext->remote_worker_id;
    hdr.target_addr = target;
    hdr.target_rkey = target_rkey->cache.rdmo_rkey;
    hdr.data_addr   = append;
    hdr.data_rkey   = append_rkey->cache.rdmo_rkey;  // should be available on DPU (imported)

    return ucp_am_send_nbx(ep->ext->rdmo_eps[0], UCP_AM_ID_RDMO_APPEND, &hdr,
                           sizeof(hdr), buffer, count, &am_param);
#endif

#else /* HAVE_UROM */
    return UCS_STATUS_PTR(UCS_ERR_UNSUPPORTED);
#endif /* HAVE_UROM */
}

static UCS_F_ALWAYS_INLINE void
ucp_rdmo_cache_put(ucp_worker_rdmo_amo_cache_t *cache,
                   const ucp_worker_rdmo_amo_cache_key_t *key,
                   const ucp_worker_rdmo_amo_cache_entry_t *entry)
{
    ucs_assert(kh_end(cache) == kh_get(ucp_worker_rdmo_amo_cache, cache, *key));

    {
        int r;
        khint_t i = kh_put(ucp_worker_rdmo_amo_cache, cache, *key, &r);
        ucs_assert(r >= 0);
        kh_val(cache, i) = *entry;
    }
}

static UCS_F_ALWAYS_INLINE ucp_worker_rdmo_amo_cache_entry_t*
ucp_rdmo_cache_get(const ucp_worker_rdmo_amo_cache_t *cache,
                   const ucp_worker_rdmo_amo_cache_key_t *key)
{
    khint_t i = kh_get(ucp_worker_rdmo_amo_cache, cache, *key);

    if (ucs_unlikely((i == kh_end(cache)))) {
        return NULL;
    }

    return &kh_val(cache, i);
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

static void ucp_rdmo_append_put_callback(void *request, ucs_status_t status,
                                         void *user_data)
{
    ucp_request_t *req = (ucp_request_t*)request - 1;

    req->send.ep->worker->rdmo_outstanding--;

    ucs_debug("complete put data %p", user_data);

    ucs_assert(status == UCS_OK);
    ucp_am_data_release(req->send.ep->worker, user_data);
    ucp_request_free(request);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_rdmo_append_put_data(ucp_worker_rdmo_amo_cache_entry_t *cache_entry,
                         void *data, size_t length)
{
    ucp_request_param_t req_param = {
        .op_attr_mask             = UCP_OP_ATTR_FIELD_CALLBACK |
                                    UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send                  = ucp_rdmo_append_put_callback,
        .user_data                = data
    };
    ucs_status_ptr_t ret_put;

    ucs_debug("put %"PRIx64" offset %"PRIu64" data %p",
              cache_entry->append_buffer, cache_entry->append_offset, data);
    ret_put = ucp_put_nbx(cache_entry->ep, data, length,
                          cache_entry->append_buffer +
                          cache_entry->append_offset,
                          cache_entry->append_rkey, &req_param);
    ucs_assertv_always((ret_put == NULL) ||
                       (UCS_PTR_STATUS(ret_put) == UCS_INPROGRESS),
                       "status: %s", ucs_status_string(UCS_PTR_STATUS(ret_put)));
    cache_entry->append_offset += length;
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

    ucs_assert(worker->context->config.ext.proto_enable);

    worker->rdmo_outstanding++;

    cache_key.id     = append_hdr->client_id;
    cache_key.target = append_hdr->target_addr;
    cache_entry = ucp_rdmo_cache_get(&worker->rdmo_amo_cache, &cache_key);
    if (ucs_unlikely(cache_entry == NULL)) {
        /* miss, init new entry */
        ucp_worker_rdmo_amo_cache_entry_t new_cache_entry = {
            .ep            = ucp_rdmo_dst_ep(worker, append_hdr->client_id),
            .append_buffer = append_hdr->data_addr,
            .append_offset = 0,
            .append_rkey   = (ucp_rkey_h)append_hdr->data_rkey,
            .target_buffer = append_hdr->target_addr,
            .target_rkey   = (ucp_rkey_h)append_hdr->target_rkey
        };

        ucs_assert(new_cache_entry.ep != NULL);

        ucp_rdmo_cache_put(&worker->rdmo_amo_cache,
                           &cache_key, &new_cache_entry);
        cache_entry = ucp_rdmo_cache_get(&worker->rdmo_amo_cache, &cache_key);
        ucs_assert_always(cache_entry != NULL);
    }

    return ucp_rdmo_append_put_data(cache_entry, data, length);
#endif
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
ucp_rdmo_cache_entry_flush_completion(void *request, ucs_status_t status,
                                       void *user_data)
{
    ucp_rdmo_cb_data_t *data     = user_data;
    ucp_rdmo_flush_ack_hdr_t hdr = {
        .flush  = data->flush.hdr,
        .status = status
    };

    ucs_assert(status == UCS_OK);

    ucs_debug("req %p flush completion, send ack", request);
    ucp_rdmo_flush_send_ack(data->flush.ack_ep, &hdr);
    if (UCS_PTR_IS_PTR(request)) {
        ucp_request_free(request);
    }

    ucs_mpool_put_inline(user_data);
}

static UCS_F_ALWAYS_INLINE void
ucp_rdmo_cache_flush_entry(const ucp_worker_rdmo_amo_cache_entry_t *entry)
{
    static const ucp_request_param_t param   = {
        .op_attr_mask = 0
    };

    void *put_req;

    ucs_debug("flush tgt %"PRIx64" val %"PRIu64,
              entry->target_buffer, entry->append_offset);

    put_req = ucp_put_nbx(entry->ep, &entry->append_offset,
                          sizeof(entry->append_offset), entry->target_buffer,
                          entry->target_rkey, &param);
    if (UCS_PTR_IS_PTR(put_req)) {
        ucp_request_free(put_req);
    }
}

ucs_status_t
ucp_rdmo_flush_handler(void *arg, const void *header, size_t header_length,
                       void *data, size_t length,
                       const ucp_am_recv_param_t *recv_param)
{
    ucp_worker_h worker                      = arg;
    const ucp_rdmo_flush_hdr_t *flush_hdr    = header;
    ucp_rdmo_cb_data_t *user_data = ucs_mpool_get_inline(&worker->rdmo_mp);
    ucp_request_param_t param     = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                        UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send      = ucp_rdmo_cache_entry_flush_completion,
        .user_data    = user_data
    };
    ucp_worker_rdmo_amo_cache_entry_t cache_entry;
    void *request;
    ucs_assert(user_data != NULL);

    user_data->flush.ack_ep = recv_param->reply_ep;
    user_data->flush.hdr    = *flush_hdr;

    kh_foreach_value(&worker->rdmo_amo_cache, cache_entry,
                     ucp_rdmo_cache_flush_entry(&cache_entry));
    kh_clear(ucp_worker_rdmo_amo_cache, &worker->rdmo_amo_cache);

    request = ucp_worker_flush_nbx(worker, &param);
    if (request == NULL) {
        ucp_rdmo_cache_entry_flush_completion(NULL, UCS_OK, user_data);
    }

    return UCS_OK;
}

ucs_status_t
ucp_rdmo_flush_ack_handler(void *arg, const void *header, size_t header_length,
                           void *data, size_t length,
                           const ucp_am_recv_param_t *param)
{
    const ucp_rdmo_flush_ack_hdr_t *hdr = header;
    ucp_ep_h ep                         = (ucp_ep_h)hdr->flush.ep;

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
