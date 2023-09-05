/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "rdmo.h"
#include "core/ucp_worker.h"

#include <core/ucp_ep.h>
#include <core/ucp_rkey.h>

//ucs_status_ptr_t
//ucp_rdmo_append(ucp_ep_h ep, const void *buffer, size_t count, ucp_rkey_h rkey,
//                const ucp_request_param_t *param)
//{
////    ucp_rdmo_append_hdr_t hdr  = {
////        .client_id = ep->ext->remote_ep_id, /* TODO: should be dst host worker uuid? */
////        .ptr_addr  = remote_addr,
////        .ptr_rkey  = rkey->cache.rma_rkey,
////        .data_rkey = 0/* TODO:register */
////    };
//
//    ucp_request_param_t am_param = {    
//        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
//        .flags        = UCP_AM_SEND_FLAG_REPLY | UCP_AM_SEND_FLAG_COPY_HEADER
//    };
//    ucp_rdmo_append_hdr_t hdr;
//
//    hdr.rdmo.id    = ep->ext->remote_ep_id;
//    hdr.rdmo.op_id = UROM_RDMO_OP_APPEND;
//    hdr.rdmo.flags = 0;
//    hdr.append.ptr_addr  = (uintptr_t)param->reply_buffer;
//    hdr.append.ptr_rkey  = param->reply_memh; // ???
//    hdr.append.data_rkey = rkey->cache.rma_rkey;
//
//    return ucp_am_send_nbx(ep->ext->rdmo_eps[0], 0, &hdr, sizeof(hdr), buffer,
//                           count, &am_param);
//}

ucs_status_ptr_t ucp_rdmo_append_nbx(ucp_ep_h ep,
                                     const void *buffer, size_t count,
                                     uint64_t target, ucp_rkey_h target_rkey,
                                     ucp_rkey_h append_rkey)
{
    ucp_request_param_t am_param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_FLAGS,
        .flags        = UCP_AM_SEND_FLAG_REPLY | UCP_AM_SEND_FLAG_COPY_HEADER
    };
    ucp_rdmo_append_hdr_t hdr;

    hdr.rdmo.id    = ep->worker->uuid;
    hdr.rdmo.op_id = UROM_RDMO_OP_APPEND;
    hdr.rdmo.flags = 0;
    hdr.append.ptr_addr  = target;
    hdr.append.ptr_rkey  = target_rkey->cache.rma_rkey;
    hdr.append.data_rkey = append_rkey->cache.rma_rkey;  // should be available on DPU (imported)

    return ucp_am_send_nbx(ep->ext->rdmo_eps[0], 0, &hdr, sizeof(hdr), buffer,
                           count, &am_param);
}
