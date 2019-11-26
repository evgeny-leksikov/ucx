/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "rdmacm_cm_ep.h"
#include <ucs/arch/bitops.h>


const char* uct_rdmacm_cm_ep_str(uct_rdmacm_cm_ep_t *cep, char *str,
                                 size_t max_len)
{
    char flags_buf[UCT_RDMACM_EP_FLAGS_STRING_LEN];

    static const char *ep_flag_to_str[] = {
        [ucs_ilog2(UCT_RDMACM_CM_EP_ON_CLIENT)]            = "client",
        [ucs_ilog2(UCT_RDMACM_CM_EP_ON_SERVER)]            = "server",
        [ucs_ilog2(UCT_RDMACM_CM_EP_CONNECTED)]            = "connected",
        [ucs_ilog2(UCT_RDMACM_CM_EP_DISCONNECTING)]        = "disconnecting",
        [ucs_ilog2(UCT_RDMACM_CM_EP_GOT_DISCONNECT_EVENT)] = "got_disconnect_event",
        [ucs_ilog2(UCT_RDMACM_CM_EP_FAILED)]               = "failed",
        NULL
    };

    ucs_flags_str(flags_buf, sizeof(flags_buf), cep->flags, ep_flag_to_str);
    ucs_snprintf_safe(str, max_len, "rdmacm_ep %p, flags %s" , cep, flags_buf);
    return str;
}

void uct_rdmacm_cm_ep_client_connect_cb(uct_rdmacm_cm_ep_t *cep,
                                        uct_cm_remote_data_t *remote_data,
                                        ucs_status_t status)
{
    cep->wireup.client.connect_cb(&cep->super.super, cep->user_data,
                                  remote_data, status);
}

void uct_rdmacm_cm_ep_server_connect_cb(uct_rdmacm_cm_ep_t *cep,
                                        ucs_status_t status)
{
    cep->wireup.server.connect_cb(&cep->super.super, cep->user_data, status);
}

void uct_rdmacm_cm_ep_error_cb(uct_rdmacm_cm_ep_t *cep,
                               uct_cm_remote_data_t *remote_data,
                               ucs_status_t status)
{
    UCS_ASYNC_BLOCK(uct_rdmacm_cm_ep_get_async(cep));

    if (cep->flags & UCT_RDMACM_CM_EP_FAILED) {
        goto out;
    }

    cep->status = status;
    cep->flags |= UCT_RDMACM_CM_EP_FAILED;

    if (cep->flags & UCT_RDMACM_CM_EP_CONNECTED) {
        cep->disconnect_cb(&cep->super.super, cep->user_data);
        cep->flags &= ~UCT_RDMACM_CM_EP_CONNECTED;
        ucs_assert(ucs_queue_is_empty(&cep->ops));
    } else {
        ucs_assert(status != UCS_OK);
        if (cep->flags & UCT_RDMACM_CM_EP_ON_CLIENT) {
            uct_rdmacm_cm_ep_client_connect_cb(cep, remote_data, status);
        } else {
            ucs_assert(cep->flags & UCT_RDMACM_CM_EP_ON_SERVER);
            uct_rdmacm_cm_ep_server_connect_cb(cep, status);
        }

        uct_rdmacm_cm_ep_invoke_completions(cep, status);
    }

out:
    UCS_ASYNC_UNBLOCK(uct_rdmacm_cm_ep_get_async(cep));
}

static void uct_rdmacm_cm_ep_destroy_dummy_cq_qp(uct_rdmacm_cm_ep_t *cep)
{
    int ret;

    if (cep->qp != NULL) {
        ret = ibv_destroy_qp(cep->qp);
        if (ret != 0) {
            ucs_warn("ibv_destroy_qp() returned %d: %m", ret);
        }
    }

    if (cep->cq != NULL) {
        ret = ibv_destroy_cq(cep->cq);
        if (ret != 0) {
            ucs_warn("ibv_destroy_cq() returned %d: %m", ret);
        }
    }

    cep->qp = NULL;
    cep->cq = NULL;
}

static ucs_status_t uct_rdmacm_cm_create_dummy_cq_qp(struct rdma_cm_id *id,
                                                     struct ibv_cq **cq_p,
                                                     struct ibv_qp **qp_p)
{
    struct ibv_qp_init_attr qp_init_attr;
    ucs_status_t status;
    struct ibv_cq *cq;
    struct ibv_qp *qp;

    /* Create a dummy completion queue */
    cq = ibv_create_cq(id->verbs, 1, NULL, NULL, 0);
    if (cq == NULL) {
        ucs_error("ibv_create_cq() failed: %m");
        status =  UCS_ERR_IO_ERROR;
        goto err;
    }

    /* Create a dummy UD qp */
    memset(&qp_init_attr, 0, sizeof(qp_init_attr));
    qp_init_attr.send_cq = cq;
    qp_init_attr.recv_cq = cq;
    qp_init_attr.qp_type = IBV_QPT_UD;
    qp_init_attr.cap.max_send_wr  = 2;
    qp_init_attr.cap.max_recv_wr  = 2;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;

    qp = ibv_create_qp(id->pd, &qp_init_attr);
    if (qp == NULL) {
        ucs_error("failed to create a dummy ud qp. %m");
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_cq;
    }

    ucs_debug("created ud QP %p with qp_num: 0x%x and cq %p on rdmacm_id %p",
              qp, qp->qp_num, cq, id);

    *cq_p = cq;
    *qp_p = qp;

    return UCS_OK;

err_destroy_cq:
    ibv_destroy_cq(cq);
err:
    return status;
}

ucs_status_t
uct_rdamcm_cm_ep_set_qp_num(struct rdma_conn_param *conn_param,
                            uct_rdmacm_cm_ep_t *cep)
{
    ucs_status_t status;
    struct ibv_qp *qp;
    struct ibv_cq *cq;

    /* create a dummy qp in order to get a unique qp_num to provide to librdmacm */
    status = uct_rdmacm_cm_create_dummy_cq_qp(cep->id, &cq, &qp);
    if (status != UCS_OK) {
        return status;
    }

    cep->cq             = cq;
    cep->qp             = qp;
    conn_param->qp_num  = qp->qp_num;
    return UCS_OK;
}

ucs_status_t uct_rdmacm_cm_ep_conn_param_init(uct_rdmacm_cm_ep_t *cep,
                                              struct rdma_conn_param *conn_param)
{
    uct_rdmacm_priv_data_hdr_t *hdr;
    ucs_status_t               status;
    char                       dev_name[UCT_DEVICE_NAME_MAX];
    ssize_t                    priv_data_ret;
    char                       ep_str[UCT_RDMACM_EP_STRING_LEN];

    uct_rdmacm_cm_id_to_dev_name(cep->id, dev_name);

    /* Pack data to send inside rdmacm's conn_param to the remote peer */
    hdr           = (uct_rdmacm_priv_data_hdr_t*)conn_param->private_data;
    priv_data_ret = cep->wireup.priv_pack_cb(cep->user_data, dev_name, hdr + 1);

    if (priv_data_ret < 0) {
        ucs_assert(priv_data_ret > UCS_ERR_LAST);
        status = (ucs_status_t)priv_data_ret;
        ucs_error("%s: rdma_cm private data pack function failed with error: %s",
                  uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                  ucs_status_string(status));

        goto err;
    } else if (priv_data_ret > uct_rdmacm_cm_get_max_conn_priv()) {
        status = UCS_ERR_EXCEEDS_LIMIT;
        ucs_error("%s: rdma_cm private data pack function returned %zd "
                  "(max: %zu)", uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                  priv_data_ret, uct_rdmacm_cm_get_max_conn_priv());
        goto err;
    }

    ucs_assert_always(priv_data_ret <= UINT8_MAX);
    hdr->length = (uint8_t)priv_data_ret;
    hdr->status = UCS_OK;

    status = uct_rdamcm_cm_ep_set_qp_num(conn_param, cep);
    if (status != UCS_OK) {
        goto err;
    }

    conn_param->private_data_len = sizeof(*hdr) + hdr->length;

    return UCS_OK;

err:
    return status;
}

static ucs_status_t uct_rdamcm_cm_ep_client_init(uct_rdmacm_cm_ep_t *cep,
                                                 const uct_ep_params_t *params)
{
    uct_rdmacm_cm_t *rdmacm_cm = uct_rdmacm_cm_ep_get_cm(cep);
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];
    char ep_str[UCT_RDMACM_EP_STRING_LEN];
    ucs_status_t status;

    cep->flags                   |= UCT_RDMACM_CM_EP_ON_CLIENT;
    cep->wireup.client.connect_cb = params->sockaddr_connect_cb.client;

    ucs_trace("%s: rdma_create_id on client (rdmacm %p, event_channel=%p)",
              uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
              rdmacm_cm, rdmacm_cm->ev_ch);

    if (rdma_create_id(rdmacm_cm->ev_ch, &cep->id, cep, RDMA_PS_TCP)) {
        ucs_error("rdma_create_id() failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto err;
    }

    /* rdma_resolve_addr needs to be called last in the ep_create flow to
     * prevent a race where there are uninitialized fields used when the
     * RDMA_CM_EVENT_ROUTE_RESOLVED event is already received in the the async
     * thread. Therefore, all ep fields have to be initialized before this
     * function is called. */
    ucs_trace("%s: rdma_resolve_addr on cm_id %p",
              uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN), cep->id);
    if (rdma_resolve_addr(cep->id, NULL, (struct sockaddr *)params->sockaddr->addr,
                          1000/* TODO */)) {
        ucs_error("rdma_resolve_addr() to dst addr %s failed: %m",
                  ucs_sockaddr_str((struct sockaddr *)params->sockaddr->addr,
                                   ip_port_str, UCS_SOCKADDR_STRING_LEN));
        status = UCS_ERR_IO_ERROR;
        goto err_destroy_id;
    }

    return UCS_OK;

err_destroy_id:
    uct_rdmacm_cm_destroy_id(cep->id);
err:
    return status;
}

static ucs_status_t uct_rdamcm_cm_ep_server_init(uct_rdmacm_cm_ep_t *cep,
                                                 const uct_ep_params_t *params)
{
    struct rdma_cm_event   *event = (struct rdma_cm_event *)params->conn_request;
    uct_rdmacm_cm_t        *cm    = uct_rdmacm_cm_ep_get_cm(cep);
    struct rdma_conn_param conn_param;
    ucs_status_t           status;
    char                   ep_str[UCT_RDMACM_EP_STRING_LEN];

    cep->flags |= UCT_RDMACM_CM_EP_ON_SERVER;

    if (event->listen_id->channel != cm->ev_ch) {
        /* the server will open the ep to the client on a different CM.
         * not the one on which its listener is listening on */
        if (rdma_migrate_id(event->id, cm->ev_ch)) {
            ucs_error("failed to migrate id %p to event_channel %p (cm=%p)",
                      event->id, cm->ev_ch, cm);
            uct_rdmacm_cm_reject(event->id);
            status = UCS_ERR_IO_ERROR;
            goto err_server_cb;
        }

        ucs_debug("%s: migrated id %p from event_channel=%p to "
                  "new cm %p (event_channel=%p)",
                  uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                  event->id, event->listen_id->channel, cm, cm->ev_ch);
    }

    cep->wireup.server.connect_cb = params->sockaddr_connect_cb.server;
    cep->id                       = event->id;
    cep->id->context              = cep;

    memset(&conn_param, 0, sizeof(conn_param));
    conn_param.private_data = ucs_alloca(uct_rdmacm_cm_get_max_conn_priv() +
                                         sizeof(uct_rdmacm_priv_data_hdr_t));

    status = uct_rdmacm_cm_ep_conn_param_init(cep, &conn_param);
    if (status != UCS_OK) {
        uct_rdmacm_cm_reject(event->id);
        goto err_server_cb;
    }

    ucs_trace("%s: rdma_accept on cm_id %p",
              uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
              event->id);

    if (rdma_accept(event->id, &conn_param)) {
        ucs_error("rdma_accept(on id=%p) failed: %m", event->id);
        uct_rdmacm_cm_ep_destroy_dummy_cq_qp(cep);
        status = UCS_ERR_IO_ERROR;
        goto err_server_cb;
    }

    uct_rdmacm_cm_ack_event(event);
    return UCS_OK;

err_server_cb:
    uct_rdmacm_cm_ep_error_cb(cep, NULL, status);
    uct_rdmacm_cm_destroy_id(event->id);
    uct_rdmacm_cm_ack_event(event);
    return status;
}

ucs_status_t uct_rdmacm_cm_ep_disconnect(uct_ep_h ep, unsigned flags)
{
    uct_rdmacm_cm_ep_t *cep = ucs_derived_of(ep, uct_rdmacm_cm_ep_t);
    char ep_str[UCT_RDMACM_EP_STRING_LEN];
    char ip_port_str[UCS_SOCKADDR_STRING_LEN];

    ucs_assert(ucs_queue_is_empty(&cep->ops));
    if (ucs_unlikely(cep->flags & UCT_RDMACM_CM_EP_DISCONNECTING)) {
        if (cep->flags & UCT_RDMACM_CM_EP_CONNECTED) {
            ucs_debug("%s: duplicate call of uct_ep_disconnect on an ep "
                      "that was not disconnected yet (id=%p to peer %s).",
                      uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                      cep->id, ucs_sockaddr_str(rdma_get_peer_addr(cep->id),
                                                ip_port_str,
                                                UCS_SOCKADDR_STRING_LEN));
            return UCS_INPROGRESS;
        } else {
            ucs_error("%s: duplicate call of uct_ep_disconnect on a "
                      "disconnected ep (id=%p to peer %s)",
                      uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                      cep->id, ucs_sockaddr_str(rdma_get_peer_addr(cep->id),
                                                ip_port_str,
                                                UCS_SOCKADDR_STRING_LEN));
            return UCS_ERR_NOT_CONNECTED;
        }
    }

    if (!(cep->flags & UCT_RDMACM_CM_EP_CONNECTED)) {
        ucs_debug("%s: calling uct_ep_disconnect on an ep that is not "
                  "connected yet (id=%p to peer %s)",
                  uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                  cep->id, ucs_sockaddr_str(rdma_get_peer_addr(cep->id),
                                            ip_port_str,
                                            UCS_SOCKADDR_STRING_LEN));
        return UCS_ERR_BUSY;
    }

    if (rdma_disconnect(cep->id)) {
        ucs_error("%s: (id=%p) failed to disconnect from peer %p",
                  uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
                  cep->id, ucs_sockaddr_str(rdma_get_peer_addr(cep->id), ip_port_str,
                                            UCS_SOCKADDR_STRING_LEN));
        return UCS_ERR_IO_ERROR;
    }

    cep->flags |= UCT_RDMACM_CM_EP_DISCONNECTING;

    ucs_debug("%s: (id=%p) disconnecting from peer :%s",
              uct_rdmacm_cm_ep_str(cep, ep_str, UCT_RDMACM_EP_STRING_LEN),
              cep->id, ucs_sockaddr_str(rdma_get_peer_addr(cep->id), ip_port_str,
                                        UCS_SOCKADDR_STRING_LEN));
    return UCS_OK;
}

ucs_status_t uct_rdmacm_cm_ep_flush(uct_ep_h ep, unsigned flags,
                                    uct_completion_t *comp)
{
    uct_rdmacm_cm_ep_t *cep        = ucs_derived_of(ep, uct_rdmacm_cm_ep_t);
    ucs_status_t status;
    uct_rdmacm_ep_op_t *op;

    UCS_ASYNC_BLOCK(uct_rdmacm_cm_ep_get_async(cep));

    if (cep->flags & (UCT_RDMACM_CM_EP_CONNECTED            |
                      UCT_RDMACM_CM_EP_DISCONNECTING        |
                      UCT_RDMACM_CM_EP_GOT_DISCONNECT_EVENT |
                      UCT_RDMACM_CM_EP_FAILED)) {
        status = cep->status;
        goto out;
    }

    status = UCS_INPROGRESS;

    if (comp == NULL) {
        goto out;
    }

    op = ucs_malloc(sizeof(*op), "uct_rdmacm_cm_ep_flush op");
    if (op == NULL) {
        ucs_error("failed to allocate flush op");
        status = UCS_ERR_NO_MEMORY;
        goto out;
    }

    op->user_comp = comp;
    ucs_queue_push(&cep->ops, &op->queue_elem);

out:
    UCS_ASYNC_UNBLOCK(uct_rdmacm_cm_ep_get_async(cep));
    return status;
}

UCS_CLASS_INIT_FUNC(uct_rdmacm_cm_ep_t, const uct_ep_params_t *params)
{
    ucs_status_t status;
    char ep_str[UCT_RDMACM_EP_STRING_LEN];

    if (!(params->field_mask & UCT_EP_PARAM_FIELD_CM)) {
        ucs_error("UCT_EP_PARAM_FIELD_CM is not set. field_mask 0x%lx",
                  params->field_mask);
        return UCS_ERR_INVALID_PARAM;
    }

    if (!(params->field_mask & UCT_EP_PARAM_FIELD_SOCKADDR_CB_FLAGS) ||
        !(params->sockaddr_cb_flags & UCT_CB_FLAG_ASYNC)) {
        ucs_error("UCT_EP_PARAM_FIELD_SOCKADDR_CB_FLAGS and UCT_CB_FLAG_ASYNC "
                  "should be set");
        return UCS_ERR_UNSUPPORTED;
    }

    if (!(params->field_mask & (UCT_EP_PARAM_FIELD_SOCKADDR |
                                UCT_EP_PARAM_FIELD_CONN_REQUEST))) {
        ucs_error("neither UCT_EP_PARAM_FIELD_SOCKADDR nor "
                  "UCT_EP_PARAM_FIELD_CONN_REQUEST is set. field_mask 0x%lx",
                  params->field_mask);
        return UCS_ERR_INVALID_PARAM;
    }

    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &params->cm->iface);

    self->wireup.priv_pack_cb = (params->field_mask &
                                 UCT_EP_PARAM_FIELD_SOCKADDR_PACK_CB) ?
                                params->sockaddr_pack_cb : NULL;
    self->disconnect_cb       = (params->field_mask &
                                 UCT_EP_PARAM_FIELD_SOCKADDR_DISCONNECT_CB) ?
                                params->disconnect_cb : NULL;
    self->user_data           = (params->field_mask &
                                 UCT_EP_PARAM_FIELD_USER_DATA) ?
                                params->user_data : NULL;
    self->cq                  = NULL;
    self->qp                  = NULL;
    self->flags               = 0;
    self->status              = UCS_OK;
    ucs_queue_head_init(&self->ops);

    if (params->field_mask & UCT_EP_PARAM_FIELD_SOCKADDR) {
        status = uct_rdamcm_cm_ep_client_init(self, params);
    } else if (params->field_mask & UCT_EP_PARAM_FIELD_CONN_REQUEST) {
        status = uct_rdamcm_cm_ep_server_init(self, params);
    } else {
        ucs_error("either UCT_EP_PARAM_FIELD_SOCKADDR or UCT_EP_PARAM_FIELD_CONN_REQUEST "
                  "has to be provided");
        status = UCS_ERR_INVALID_PARAM;
    }

    if (status == UCS_OK) {
        ucs_debug("%s: created an endpoint on rdmacm %p id: %p",
                  uct_rdmacm_cm_ep_str(self, ep_str, UCT_RDMACM_EP_STRING_LEN),
                  uct_rdmacm_cm_ep_get_cm(self), self->id);
    }

    return status;
}

UCS_CLASS_CLEANUP_FUNC(uct_rdmacm_cm_ep_t)
{
    uct_rdmacm_cm_t *rdmacm_cm     = uct_rdmacm_cm_ep_get_cm(self);
    uct_priv_worker_t *worker_priv = ucs_derived_of(rdmacm_cm->super.iface.worker,
                                                    uct_priv_worker_t);
    char ep_str[UCT_RDMACM_EP_STRING_LEN];

    ucs_trace("%s: destroy ep on cm %p (worker_priv=%p)",
              uct_rdmacm_cm_ep_str(self, ep_str, UCT_RDMACM_EP_STRING_LEN),
              rdmacm_cm, worker_priv);

    UCS_ASYNC_BLOCK(worker_priv->async);

    uct_rdmacm_cm_ep_destroy_dummy_cq_qp(self);

    /* rdma_destroy_id() cleans all events not yet reported on progress thread,
     * so no events would be reported to the user after destroying the id */
    uct_rdmacm_cm_destroy_id(self->id);

    UCS_ASYNC_UNBLOCK(worker_priv->async);
}

UCS_CLASS_DEFINE(uct_rdmacm_cm_ep_t, uct_base_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_rdmacm_cm_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_rdmacm_cm_ep_t, uct_ep_t);

void uct_rdmacm_cm_ep_invoke_completions(uct_rdmacm_cm_ep_t *ep,
                                         ucs_status_t status)
{
    uct_rdmacm_ep_op_t *op;

    UCS_ASYNC_BLOCK(uct_rdmacm_cm_ep_get_async(ep));

    ucs_queue_for_each_extract(op, &ep->ops, queue_elem, 1) {
        uct_invoke_completion(op->user_comp, status);
        ucs_free(op);
    }

    UCS_ASYNC_UNBLOCK(uct_rdmacm_cm_ep_get_async(ep));
}
