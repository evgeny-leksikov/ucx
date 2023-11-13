/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RDMO_H_
#define UCP_RDMO_H_

#include <ucp/core/ucp_types.h>
#include <ucp/core/ucp_worker.h>
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
    uint64_t    target_addr;
    uint64_t    target_rkey;
    uint64_t    data_addr;
    uint64_t    data_rkey;
} UCS_S_PACKED ucp_rdmo_append_hdr_t;


typedef struct ucp_rdmo_flush_hdr {
    uint64_t    ep;
    uint64_t    client_id;
} UCS_S_PACKED ucp_rdmo_flush_hdr_t;


typedef struct ucp_rdmo_flush_ack_hdr {
    uint64_t    ep;
    uint8_t     status;
} UCS_S_PACKED ucp_rdmo_flush_ack_hdr_t;

typedef struct ucp_rdmo_queued_put_data {
    void             *data;
    size_t           length;
    ucs_queue_elem_t q_elem;
} ucp_rdmo_queued_put_data_t;

typedef struct ucp_rdmo_ack_elem {
    ucs_queue_elem_t                elem;
    uint64_t                        client_id;
    ucp_ep_h                        reply_ep;
    uint64_t                        hdr_ep;
} ucp_rdmo_ack_elem_t;

typedef struct ucp_rdmo_op_data {
    union {
        struct {
            ucs_queue_head_t                put_queue;
            size_t                          put_queue_len;
            ucp_worker_rdmo_amo_cache_key_t cache_key;
            ucp_ep_h                        put_ep;
            uint64_t                        offset;
        } fetch_offset;

        struct {
            ucp_ep_h                 reply_ep;
            ucp_rdmo_flush_ack_hdr_t hdr;
        } flush;

        ucp_rdmo_queued_put_data_t queued_put;
        ucp_rdmo_ack_elem_t        queued_ack;
        ucs_queue_head_t           pending_flush_acks;
        uint64_t                   put_offset;
    };
} ucp_rdmo_cb_data_t;

#endif


ucs_status_t
ucp_rdmo_append_handler(void *arg, const void *header, size_t header_length,
                        void *data, size_t length,
                        const ucp_am_recv_param_t *param);

ucs_status_t
ucp_rdmo_flush_handler(void *arg, const void *header, size_t header_length,
                       void *data, size_t length,
                       const ucp_am_recv_param_t *param);

ucs_status_t
ucp_rdmo_flush_ack_handler(void *arg, const void *header, size_t header_length,
                           void *data, size_t length,
                           const ucp_am_recv_param_t *param);

void ucp_rdmo_cache_free(ucp_worker_rdmo_clients_cache_t *cache);

#endif /* UCP_RDMO_H_ */