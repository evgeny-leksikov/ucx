/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RDMO_H_
#define UCP_RDMO_H_

#include <ucp/core/ucp_types.h>
#include <ucs/type/status.h>


ucs_status_ptr_t
ucp_rdmo_append(ucp_ep_h ep, ucp_rdmo_op_t opcode, const void *buffer,
                size_t count, uint64_t remote_addr, ucp_rkey_h rkey,
                const ucp_request_param_t *param);


#endif /* UCP_RDMO_H_ */