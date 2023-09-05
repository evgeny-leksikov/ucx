/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RDMO_H_
#define UCP_RDMO_H_

#include <ucp/core/ucp_types.h>
#include <ucs/type/status.h>

#if HAVE_UROM
#include <urom/api/urom.h>


typedef struct ucp_rdmo_append_hdr {
    urom_rdmo_hdr_t        rdmo;
    urom_rdmo_append_hdr_t append;

//    uint64_t    client_id;
//
//    uint32_t    op_id; /* looks redundant */
//    uint32_t    flags; /* looks redundant */
//
//    uint64_t    ptr_addr;
//    uint64_t    ptr_rkey;
//    uint64_t    data_rkey;
} UCS_S_PACKED ucp_rdmo_append_hdr_t;

#endif

//ucs_status_ptr_t
//ucp_rdmo_append(ucp_ep_h ep, const void *buffer,  size_t count, ucp_rkey_h rkey,
//                const ucp_request_param_t *param);

#endif /* UCP_RDMO_H_ */