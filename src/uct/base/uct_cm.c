/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "uct_cm.h"

#include <ucs/sys/math.h>
#include <uct/base/uct_md.h>


ucs_status_t uct_cm_open(const uct_cm_params_t *params, uct_cm_h *cm_p)
{
    uct_md_component_t *mdc;
    ucs_status_t status;

    if (!ucs_test_all_flags(params->field_mask,
                            UCT_CM_PARAM_FIELD_MD_NAME |
                            UCT_CM_PARAM_FIELD_WORKER)) {
        return UCS_ERR_INVALID_PARAM;
    }

    status = uct_find_md_component(params->md_name, &mdc);
    if (status != UCS_OK) {
        return status;
    }
    return mdc->cm_open(params, cm_p);
}

void uct_cm_close(uct_cm_h cm)
{
    cm->ops->close(cm);
}

ucs_status_t uct_cm_query(uct_cm_h cm, uct_cm_attr_t *cm_attr)
{
    return cm->ops->cm_query(cm, cm_attr);
}

UCS_CLASS_INIT_FUNC(uct_listener_t, uct_cm_h cm)
{
    self->cm = cm;
    return UCS_OK;
}

UCS_CLASS_CLEANUP_FUNC(uct_listener_t)
{
}

UCS_CLASS_DEFINE(uct_listener_t, void);
UCS_CLASS_DEFINE_NEW_FUNC(uct_listener_t, void, uct_cm_h);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_listener_t, void);

ucs_status_t uct_listener_create(const uct_listener_params_t *params,
                                 uct_listener_h *listener_p)
{
    if (!ucs_test_all_flags(params->field_mask,
                            UCT_LISTENER_PARAM_FIELD_CM       |
                            UCT_LISTENER_PARAM_FIELD_SOCKADDR |
                            UCT_LISTENER_PARAM_FIELD_CONN_REQUEST_CB)) {
        return UCS_ERR_INVALID_PARAM;
    }

    return params->cm->ops->listener_create(params, listener_p);
}

ucs_status_t uct_listener_reject(uct_listener_h listener,
                                 uct_conn_request_h conn_request)
{
    return listener->cm->ops->listener_reject(listener, conn_request);
}

void uct_listener_destroy(uct_listener_h listener)
{
    listener->cm->ops->listener_destroy(listener);
}
