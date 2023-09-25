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

ucs_status_ptr_t ucp_rdmo_append_nbx(ucp_ep_h ep,
                                     const void *buffer, size_t count,
                                     uint64_t target, ucp_rkey_h target_rkey,
                                     ucp_rkey_h append_rkey)
{
#if HAVE_UROM
    ucp_request_param_t am_param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
        .flags        = UCP_AM_SEND_FLAG_REPLY | UCP_AM_SEND_FLAG_COPY_HEADER
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
    hdr.client_id = ep->ext->remote_worker_id;
    hdr.ptr_addr  = target;
    hdr.ptr_rkey  = target_rkey->cache.rdmo_rkey;
    hdr.data_rkey = append_rkey->cache.rdmo_rkey;  // should be available on DPU (imported)

    return ucp_am_send_nbx(ep->ext->rdmo_eps[0], UCP_AM_ID_RDMO_APPEND, &hdr,
                           sizeof(hdr), buffer, count, &am_param);
#endif

#else /* HAVE_UROM */
    return UCS_STATUS_PTR(UCS_ERR_UNSUPPORTED);
#endif /* HAVE_UROM */
}

ucp_ep_h ucp_rdmo_dst_ep(ucp_worker_h worker, uint64_t id)
{
    ucp_ep_ext_t *ep_ext;


    /* TODO: optimize, try to reuse ptr_map ep_map */
    /* assume only 1 EP to the host */
    ucs_assert(ucs_list_length(&worker->all_eps) <= 2);
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
    ucs_assert(status == UCS_OK);
    ucs_mpool_put_inline(user_data);
    ucp_request_free(request);
}

static void ucp_rdmo_append_fadd_callback(void *request, ucs_status_t status,
                                         void *user_data)
{
    ucp_rdmo_append_user_data_t *append_data = user_data;
    ucp_request_param_t req_param            = {
        .op_attr_mask                        = UCP_OP_ATTR_FIELD_CALLBACK |
                                               UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.send                             = ucp_rdmo_append_put_callback,
        .user_data                           = user_data
    };
    ucs_status_ptr_t ret_put;

    ucs_assert(status == UCS_OK);

    ucp_request_free(request);
    ret_put = ucp_put_nbx(append_data->ep, append_data->data,
                          append_data->data_length, append_data->data_buffer,
                          append_data->data_rkey, &req_param);
    ucs_assert(UCS_PTR_STATUS(ret_put) == UCS_INPROGRESS);
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
    ucp_rkey_h ptr_rkey                     = (void*)append_hdr->ptr_rkey;
    ucp_request_param_t req_param           = {
        .op_attr_mask                       = UCP_OP_ATTR_FIELD_DATATYPE |
                                              UCP_OP_ATTR_FIELD_CALLBACK |
                                              UCP_OP_ATTR_FIELD_MEMORY_TYPE,
        .cb.send                            = ucp_rdmo_append_fadd_callback,
        .datatype                           = ucp_dt_make_contig(sizeof(uint64_t)),
        .memory_type                        = UCS_MEMORY_TYPE_HOST
    };
    ucp_rdmo_append_user_data_t *user_data;
    ucp_ep_h ep;
    ucs_status_ptr_t ret_add;

    ucs_assert(worker->context->config.ext.proto_enable);

    ep = ucp_rdmo_dst_ep(worker, append_hdr->client_id);
    ucs_assert_always(ep != NULL);

    user_data = ucs_mpool_get_inline(&worker->rdmo_mp);
    ucs_assert(user_data != NULL);

    user_data->ep          = ep;
    user_data->data_rkey   = (ucp_rkey_h)append_hdr->data_rkey;
    user_data->data        = data;
    user_data->data_buffer = 0;
    user_data->data_length = length;

    req_param.op_attr_mask |= UCP_OP_ATTR_FIELD_REPLY_BUFFER |
                              UCP_OP_ATTR_FIELD_USER_DATA;
    req_param.reply_buffer  = &user_data->data_buffer;
    req_param.user_data     = user_data;

    ret_add = ucp_atomic_op_nbx(ep, UCP_ATOMIC_OP_ADD, &length, 1,
                                append_hdr->ptr_addr, ptr_rkey, &req_param);
    ucs_assert(UCS_PTR_STATUS(ret_add) == UCS_INPROGRESS);

    return UCS_PTR_IS_PTR(ret_add) ? UCS_INPROGRESS : UCS_OK;
#endif
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
