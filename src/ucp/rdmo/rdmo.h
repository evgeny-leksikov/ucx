/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RDMO_H_
#define UCP_RDMO_H_

#include <ucp/core/ucp_types.h>
#include <ucs/type/status.h>

#if 0
#if HAVE_UROM
#include <urom/api/urom.h>


typedef struct ucp_rdmo_append_hdr {
    urom_rdmo_hdr_t        rdmo;
    urom_rdmo_append_hdr_t append;
} UCS_S_PACKED ucp_rdmo_append_hdr_t;
#endif

#else
typedef struct ucp_rdmo_append_hdr {
    uint64_t    client_id;
    uint64_t    ptr_addr;
    uint64_t    ptr_rkey;
    uint64_t    data_rkey;
} UCS_S_PACKED ucp_rdmo_append_hdr_t;

typedef struct ucp_rdmo_append_user_data {
    ucp_ep_h    ep;
    void        *data;
    uint64_t    data_buffer;
    ucp_rkey_h  data_rkey;
    size_t      data_length;
} ucp_rdmo_append_user_data_t;
#endif


ucs_status_t
ucp_rdmo_append_handler(void *arg, const void *header, size_t header_length,
                        void *data, size_t length,
                        const ucp_am_recv_param_t *param);

#endif /* UCP_RDMO_H_ */