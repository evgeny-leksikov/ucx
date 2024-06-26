/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2001-2019. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <core/ucp_ep.h>



ucs_status_ptr_t
ucp_rdmo_append_nbx(ucp_ep_h ep,
                    const void *buffer, size_t count,
                    uint64_t target, ucp_rkey_h target_rkey,
                    uint64_t append, ucp_rkey_h append_rkey,
                    const ucp_request_param_t *param)
{
    return UCS_STATUS_PTR(UCS_ERR_NOT_IMPLEMENTED);
}
