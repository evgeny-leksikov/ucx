/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2023. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "rdmo.h"
#include <ucp/api/ucp.h>
#include <ucs/profile/profile.h>

#include <ucp/core/ucp_request.inl>

UCS_PROFILE_FUNC(ucs_status_ptr_t, ucp_rdmo_nbx,
                 (ep, opcode, buffer, count, remote_addr, rkey, param),
                 ucp_ep_h ep, ucp_rdmo_op_t opcode, const void *buffer,
                 size_t count, uint64_t remote_addr, ucp_rkey_h rkey,
                 const ucp_request_param_t *param)
{
    UCP_REQUEST_CHECK_PARAM(param);
    if (ENABLE_PARAMS_CHECK &&
        ucs_unlikely(!(param->op_attr_mask & UCP_OP_ATTR_FIELD_DATATYPE))) {
        ucs_error("missing rdmo operation datatype");
        return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM);
    }

    if (ENABLE_PARAMS_CHECK &&
        ucs_unlikely(opcode != UCP_RDMO_OP_APPEND)) {
        ucs_error("invalid rdmo operation");
        return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM);
    }

    if (ENABLE_PARAMS_CHECK &&
        ucs_unlikely(!(param->op_attr_mask & UCP_OP_ATTR_FIELD_MEMH))) {
        ucs_error("user's memory handle is not set");
        return UCS_STATUS_PTR(UCS_ERR_INVALID_PARAM);
    }

    return ucp_rdmo_append(ep, opcode, buffer, count, remote_addr, rkey, param);
}
