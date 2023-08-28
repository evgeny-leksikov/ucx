/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "rdmo.h"

ucs_status_ptr_t
ucp_rdmo_append(ucp_ep_h ep, ucp_rdmo_op_t opcode, const void *buffer,
                size_t count, uint64_t remote_addr, ucp_rkey_h rkey,
                const ucp_request_param_t *param)
{
    return UCS_STATUS_PTR(UCS_ERR_NOT_IMPLEMENTED);
}
