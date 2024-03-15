/**
* Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2024. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif


#include "gga_mlx5.h"

#include <uct/base/uct_iface.h>
#include <uct/ib/base/ib_md.h>
#include <uct/ib/rc/accel/rc_mlx5.h>

#include <uct/ib/rc/accel/rc_mlx5.inl>

typedef struct {
    uct_ib_md_packed_mkey_t packed_mkey;
    uct_ib_mlx5_devx_mem_t  *memh;
    uct_rkey_bundle_t       rkey_ob;
} uct_gga_mlx5_rkey_handle_t;

/**
 * GGA MLX5 EP cleanup context
 */
typedef struct {
    uct_rc_iface_qp_cleanup_ctx_t super; /* Base class */
    uct_ib_mlx5_qp_t              qp; /* Main QP */
    uct_ib_mlx5_mmio_reg_t        *reg; /* Doorbell register */
} uct_gga_mlx5_iface_qp_cleanup_ctx_t;


typedef struct {
    uct_rc_mlx5_base_ep_t   super;
} uct_gga_mlx5_ep_t;


static UCS_CLASS_INIT_FUNC(uct_gga_mlx5_ep_t, const uct_ep_params_t *params)
{
    UCS_CLASS_CALL_SUPER_INIT(uct_rc_mlx5_base_ep_t, params);
    return UCS_OK;
}


static UCS_CLASS_CLEANUP_FUNC(uct_gga_mlx5_ep_t)
{
    uct_rc_mlx5_iface_common_t *iface =
            ucs_derived_of(self->super.super.super.super.iface,
                           uct_rc_mlx5_iface_common_t);
    uct_gga_mlx5_iface_qp_cleanup_ctx_t *cleanup_ctx;
    uint16_t outstanding, wqe_count;

    cleanup_ctx = ucs_malloc(sizeof(*cleanup_ctx), "gga_qp_cleanup_ctx");
    ucs_assert_always(cleanup_ctx != NULL);
    cleanup_ctx->qp    = self->super.tx.wq.super;
    cleanup_ctx->reg   = self->super.tx.wq.reg;

    uct_rc_txqp_purge_outstanding(&iface->super, &self->super.super.txqp,
                                  UCS_ERR_CANCELED, self->super.tx.wq.sw_pi, 1);

    (void)uct_ib_mlx5_modify_qp_state(&iface->super.super,
                                      &self->super.tx.wq.super, IBV_QPS_ERR);

    /* Keep only one unreleased CQ credit per WQE, so we will not have CQ
       overflow. These CQ credits will be released by error CQE handler. */
    outstanding = self->super.tx.wq.bb_max - self->super.super.txqp.available;
    wqe_count   = uct_ib_mlx5_txwq_num_posted_wqes(&self->super.tx.wq,
                                                   outstanding);
    ucs_assert(outstanding >= wqe_count);
    uct_rc_ep_cleanup_qp(&self->super.super, &cleanup_ctx->super,
                         self->super.tx.wq.super.qp_num,
                         outstanding - wqe_count);
}


UCS_CLASS_DEFINE(uct_gga_mlx5_ep_t, uct_rc_mlx5_base_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_gga_mlx5_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_gga_mlx5_ep_t, uct_ep_t);


/**
 * GGA mlx5 interface configuration
 */
typedef struct uct_gga_mlx5_iface_config {
    uct_rc_iface_config_t             super;
    uct_rc_mlx5_iface_common_config_t rc_mlx5_common;
} uct_gga_mlx5_iface_config_t;


ucs_config_field_t uct_gga_mlx5_iface_config_table[] = {
  {"GGA_", "", NULL,
   ucs_offsetof(uct_gga_mlx5_iface_config_t, super),
   UCS_CONFIG_TYPE_TABLE(uct_rc_iface_config_table)},

  {"GGA_", "", NULL,
   ucs_offsetof(uct_gga_mlx5_iface_config_t, rc_mlx5_common),
   UCS_CONFIG_TYPE_TABLE(uct_rc_mlx5_common_config_table)},

  {NULL}
};

static int
uct_gga_mlx5_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                   const uct_iface_is_reachable_params_t *params)
{
    /* TODO: pack and test XGVMI ID to address */
    return uct_ib_iface_is_reachable_v2(tl_iface, params);
}

static UCS_F_ALWAYS_INLINE unsigned
uct_rc_mlx5_iface_progress(void *arg, int flags)
{
    uct_rc_mlx5_iface_common_t *iface = arg;
    unsigned count;

    count = uct_rc_mlx5_iface_common_poll_rx(iface, flags);
    if (!uct_rc_iface_poll_tx(&iface->super, count)) {
        return count;
    }

    return count + uct_rc_mlx5_iface_poll_tx(iface, flags);
}

static unsigned uct_gga_mlx5_iface_progress_ll(void *arg)
{
    return uct_rc_mlx5_iface_progress(arg, UCT_IB_MLX5_POLL_FLAG_HAS_EP |
                                           UCT_IB_MLX5_POLL_FLAG_LINKED_LIST |
                                           UCT_IB_MLX5_POLL_FLAG_CQE_ZIP);
}

static unsigned uct_gga_mlx5_iface_progress_cyclic_zip(void *arg)
{
    return uct_rc_mlx5_iface_progress(arg, UCT_IB_MLX5_POLL_FLAG_HAS_EP |
                                           UCT_IB_MLX5_POLL_FLAG_CQE_ZIP);
}

static unsigned uct_gga_mlx5_iface_progress_cyclic(void *arg)
{
    return uct_rc_mlx5_iface_progress(arg, UCT_IB_MLX5_POLL_FLAG_HAS_EP);
}

static ucs_status_t
uct_gga_mlx5_iface_init_rx(uct_rc_iface_t *rc_iface,
                           const uct_rc_iface_common_config_t *rc_config)
{
    uct_rc_mlx5_iface_common_t *iface    = ucs_derived_of(rc_iface,
                                                          uct_rc_mlx5_iface_common_t);
    uct_ib_mlx5_md_t *md                 = ucs_derived_of(rc_iface->super.super.md,
                                                          uct_ib_mlx5_md_t);
    ucs_status_t status;

    ucs_assert(!UCT_RC_MLX5_TM_ENABLED(iface));
    ucs_assert(!UCT_RC_MLX5_MP_ENABLED(iface));

    if (ucs_test_all_flags(md->flags, UCT_IB_MLX5_MD_FLAG_RMP |
                                      UCT_IB_MLX5_MD_FLAG_DEVX_RC_SRQ)) {
        status = uct_rc_mlx5_devx_init_rx(iface, rc_config);
    } else {
        status = uct_rc_mlx5_common_iface_init_rx(iface, rc_config);
    }

    if (status != UCS_OK) {
        return status;
    }

    if (iface->config.srq_topo == UCT_RC_MLX5_SRQ_TOPO_LIST) {
        iface->super.progress = uct_gga_mlx5_iface_progress_ll;
    } else if (iface->cq[UCT_IB_DIR_RX].zip || iface->cq[UCT_IB_DIR_TX].zip) {
        iface->super.progress = uct_gga_mlx5_iface_progress_cyclic_zip;
    } else {
        iface->super.progress = uct_gga_mlx5_iface_progress_cyclic;
    }
    return UCS_OK;
}

/* TODO: del code duplication */
static void uct_gga_mlx5_iface_cleanup_rx(uct_rc_iface_t *rc_iface)
{
    uct_rc_mlx5_iface_common_t *iface = ucs_derived_of(rc_iface, uct_rc_mlx5_iface_common_t);
    uct_ib_mlx5_md_t *md              = ucs_derived_of(rc_iface->super.super.md,
                                                       uct_ib_mlx5_md_t);

    uct_rc_mlx5_destroy_srq(md, &iface->rx.srq);
}

typedef struct {
    uct_rc_mlx5_iface_common_t  super;
} uct_gga_mlx5_iface_t;

typedef struct uct_gga_mlx5_ep_address {
    uct_ib_uint24_t  qp_num;
    uint8_t          atomic_mr_id;
    uint8_t          flags;
} UCS_S_PACKED uct_gga_mlx5_ep_address_t;

static void
uct_gga_mlx5_iface_qp_cleanup(uct_rc_iface_qp_cleanup_ctx_t *rc_cleanup_ctx)
{
    uct_gga_mlx5_iface_qp_cleanup_ctx_t *cleanup_ctx =
            ucs_derived_of(rc_cleanup_ctx, uct_gga_mlx5_iface_qp_cleanup_ctx_t);
    uct_rc_mlx5_iface_common_t *iface =
            ucs_derived_of(cleanup_ctx->super.iface, uct_rc_mlx5_iface_common_t);
    uct_ib_mlx5_md_t *md =
            ucs_derived_of(iface->super.super.super.md, uct_ib_mlx5_md_t);

    UCS_STATIC_ASSERT(HAVE_DECL_MLX5DV_INIT_OBJ);

    uct_ib_mlx5_destroy_qp(md, &cleanup_ctx->qp);
    uct_ib_mlx5_qp_mmio_cleanup(&cleanup_ctx->qp, cleanup_ctx->reg);
}

static uct_rc_iface_ops_t uct_gga_mlx5_iface_ops = {
    .super = {
        .super = {
            .iface_estimate_perf   = uct_rc_iface_estimate_perf,
            .iface_vfs_refresh     = uct_rc_iface_vfs_refresh,
            .ep_query              = (uct_ep_query_func_t)ucs_empty_function,
            .ep_invalidate         = uct_rc_mlx5_base_ep_invalidate,
            .ep_connect_to_ep_v2   = uct_rc_mlx5_ep_connect_to_ep_v2,
            .iface_is_reachable_v2 = uct_gga_mlx5_iface_is_reachable_v2,
            .ep_is_connected       = uct_rc_mlx5_base_ep_is_connected
        },
        .create_cq      = uct_rc_mlx5_iface_common_create_cq,
        .destroy_cq     = uct_rc_mlx5_iface_common_destroy_cq,
        .event_cq       = uct_rc_mlx5_iface_common_event_cq,
        .handle_failure = uct_rc_mlx5_iface_handle_failure,
    },
    .init_rx         = uct_gga_mlx5_iface_init_rx,
    .cleanup_rx      = uct_gga_mlx5_iface_cleanup_rx,
    .fc_ctrl         = uct_rc_mlx5_base_ep_fc_ctrl,
    .fc_handler      = uct_rc_iface_fc_handler,
    .cleanup_qp      = uct_gga_mlx5_iface_qp_cleanup,
    .ep_post_check   = uct_rc_mlx5_base_ep_post_check,
    .ep_vfs_populate = uct_rc_mlx5_base_ep_vfs_populate
};

static UCS_CLASS_DECLARE_DELETE_FUNC(uct_gga_mlx5_iface_t, uct_iface_t);

static ucs_status_t
uct_gga_mlx5_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *iface_attr)
{
    uct_rc_mlx5_iface_common_t *iface = ucs_derived_of(tl_iface, uct_rc_mlx5_iface_common_t);
    uct_rc_iface_t *rc_iface          = &iface->super;
    size_t max_am_inline              = UCT_IB_MLX5_AM_MAX_SHORT(0);
    size_t max_put_inline             = UCT_IB_MLX5_PUT_MAX_SHORT(0);
    ucs_status_t status;
    size_t ep_addr_len;

#if HAVE_IBV_DM
    if (iface->dm.dm != NULL) {
        max_am_inline  = ucs_max(iface->dm.dm->seg_len, UCT_IB_MLX5_AM_MAX_SHORT(0));
        max_put_inline = ucs_max(iface->dm.dm->seg_len, UCT_IB_MLX5_PUT_MAX_SHORT(0));
    }
#endif

    status = uct_rc_iface_query(rc_iface, iface_attr,
                                max_put_inline,
                                max_am_inline,
                                UCT_IB_MLX5_AM_ZCOPY_MAX_HDR(0),
                                UCT_IB_MLX5_AM_ZCOPY_MAX_IOV,
                                sizeof(uct_rc_hdr_t),
                                UCT_RC_MLX5_RMA_MAX_IOV(0));
    if (status != UCS_OK) {
        return status;
    }

    if (uct_rc_iface_flush_rkey_enabled(&iface->super)) {
        ep_addr_len = sizeof(uct_gga_mlx5_ep_address_t) + sizeof(uint16_t);
    } else {
        ep_addr_len = sizeof(uct_gga_mlx5_ep_address_t);
    }

    uct_rc_mlx5_iface_common_query(&rc_iface->super, iface_attr, max_am_inline,
                                   0);
    iface_attr->cap.flags     |= UCT_IFACE_FLAG_EP_CHECK;
    iface_attr->latency.m     += 1e-9; /* 1 ns per each extra QP */
    iface_attr->ep_addr_len    = ep_addr_len;
    iface_attr->iface_addr_len = sizeof(uint8_t);

    /* Disable not implemented caps */
    iface_attr->cap.flags &=
            ~(UCT_IFACE_FLAG_AM_SHORT        | UCT_IFACE_FLAG_AM_BCOPY        |
              UCT_IFACE_FLAG_AM_ZCOPY        | UCT_IFACE_FLAG_PUT_SHORT       |
              UCT_IFACE_FLAG_PUT_BCOPY       | UCT_IFACE_FLAG_GET_SHORT       |
              UCT_IFACE_FLAG_GET_BCOPY       | UCT_IFACE_FLAG_GET_ZCOPY       |
              UCT_IFACE_FLAG_TAG_EAGER_SHORT | UCT_IFACE_FLAG_TAG_EAGER_BCOPY |
              UCT_IFACE_FLAG_TAG_EAGER_ZCOPY | UCT_IFACE_FLAG_TAG_RNDV_ZCOPY);
    iface_attr->cap.atomic32.op_flags  =
    iface_attr->cap.atomic32.fop_flags =
    iface_attr->cap.atomic64.op_flags  =
    iface_attr->cap.atomic64.fop_flags = 0;

    iface_attr->cap.put.max_short       = 0;
    iface_attr->cap.put.max_bcopy       = 0;
    iface_attr->cap.put.min_zcopy       = 1;
    iface_attr->cap.put.max_zcopy       =
            uct_ib_iface_port_attr(&rc_iface->super)->max_msg_sz;
    iface_attr->cap.put.opt_zcopy_align = UCS_SYS_CACHE_LINE_SIZE;
    iface_attr->cap.put.align_mtu       = UCS_SYS_PCI_MAX_PAYLOAD;
    iface_attr->cap.put.max_iov         = 1;

    return UCS_OK;
}

static void uct_gga_mlx5_iface_progress_enable(uct_iface_h tl_iface, unsigned flags)
{
    uct_rc_mlx5_iface_common_t *iface = ucs_derived_of(tl_iface, uct_rc_mlx5_iface_common_t);

    if (flags & UCT_PROGRESS_RECV) {
        uct_rc_mlx5_iface_common_prepost_recvs(iface);
    }

    uct_base_iface_progress_enable_cb(&iface->super.super.super,
                                      iface->super.progress, flags);
}

static ucs_status_t
uct_gga_mlx5_rkey_resolve(uct_ib_mlx5_md_t *md, uct_rkey_t rkey)
{
    uct_md_h uct_md                         = &md->super.super;
    uct_rkey_bundle_t *rkey_bundle          = (uct_rkey_bundle_t*)rkey;
    uct_gga_mlx5_rkey_handle_t *rkey_handle = rkey_bundle->handle;
    uct_md_mem_attach_params_t atach_params = { 0 };
    uct_md_mkey_pack_params_t repack_params = { 0 };
    uct_ib_md_packed_mkey_t repack_mkey;
    ucs_status_t status;

//    ucs_assert(iov_count == 1);

    if (rkey_handle->memh != NULL) {
        return UCS_OK;
    }

    status = uct_ib_mlx5_devx_mem_attach(uct_md, &rkey_handle->packed_mkey,
                                         &atach_params,
                                         (uct_mem_h *)&rkey_handle->memh);
    if (status != UCS_OK) {
        return status;
    }

    status = uct_ib_mlx5_devx_mkey_pack(uct_md, (uct_mem_h)rkey_handle->memh,
                                        NULL, 0, &repack_params, &repack_mkey);
    if (status != UCS_OK) {
        return status;
    }

    return uct_rkey_unpack(&uct_ib_component, &repack_mkey,
                           &rkey_handle->rkey_ob);
}

static ucs_status_t
uct_gga_mlx5_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov, size_t iovcnt,
                          uint64_t remote_addr, uct_rkey_t rkey,
                          uct_completion_t *comp)
{
    UCT_RC_MLX5_EP_DECL(tl_ep, iface, ep);
    uct_ib_mlx5_md_t *md = ucs_derived_of(iface->super.super.super.md,
                                          uct_ib_mlx5_md_t);

    uct_rkey_bundle_t *rkey_bundle          = (uct_rkey_bundle_t*)rkey;
    uct_gga_mlx5_rkey_handle_t *rkey_handle = rkey_bundle->handle;

    ucs_status_t status;

    status = uct_gga_mlx5_rkey_resolve(md, rkey);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    UCT_CHECK_LENGTH(uct_iov_total_length(iov, iovcnt), 0, UCT_IB_MAX_MESSAGE_SIZE,
                     "put_zcopy");
    UCT_RC_CHECK_RES(&iface->super, &ep->super.super);

    uct_rc_mlx5_ep_fence_put(iface, &ep->super.tx.wq,
                             &rkey_handle->rkey_ob.rkey, &remote_addr,
                             ep->super.super.atomic_mr_offset);

    status = uct_rc_mlx5_base_ep_zcopy_post(&ep->super, MLX5_OPCODE_MMO,
                                            iov, iovcnt, 0ul, 0, NULL, 0,
                                            remote_addr,
                                            rkey_handle->rkey_ob.rkey, 0ul, 0, 0,
                                            MLX5_WQE_CTRL_CQ_UPDATE,
                                            uct_rc_ep_send_op_completion_handler,
                                            0, comp);
    UCT_TL_EP_STAT_OP_IF_SUCCESS(status, &ep->super.super.super, PUT, ZCOPY,
                                 uct_iov_total_length(iov, iovcnt));
    uct_rc_ep_enable_flush_remote(&ep->super.super);
    return status;
}

static uct_iface_ops_t uct_gga_mlx5_iface_tl_ops = {
    .ep_put_short             = ucs_empty_function_return_unsupported,
//    .ep_put_bcopy             = ucs_empty_function_return_unsupported,
    .ep_put_zcopy             = uct_gga_mlx5_ep_put_zcopy,
    .ep_get_bcopy             = ucs_empty_function_return_unsupported,
    .ep_get_zcopy             = ucs_empty_function_return_unsupported,
//    .ep_am_short              = ucs_empty_function_return_unsupported,
//    .ep_am_short_iov          = ucs_empty_function_return_unsupported,
//    .ep_am_bcopy              = ucs_empty_function_return_unsupported,
//    .ep_am_zcopy              = ucs_empty_function_return_unsupported,
    .ep_atomic_cswap64        = ucs_empty_function_return_unsupported,
    .ep_atomic_cswap32        = ucs_empty_function_return_unsupported,
    .ep_atomic64_post         = ucs_empty_function_return_unsupported,
    .ep_atomic32_post         = ucs_empty_function_return_unsupported,
    .ep_atomic64_fetch        = ucs_empty_function_return_unsupported,
    .ep_atomic32_fetch        = ucs_empty_function_return_unsupported,
    .ep_pending_add           = uct_rc_ep_pending_add,
    .ep_pending_purge         = uct_rc_ep_pending_purge,
    .ep_flush                 = uct_rc_mlx5_base_ep_flush,
    .ep_fence                 = ucs_empty_function_return_unsupported,
    .ep_check                 = uct_rc_ep_check,
    .ep_create                = UCS_CLASS_NEW_FUNC_NAME(uct_gga_mlx5_ep_t),
    .ep_destroy               = UCS_CLASS_DELETE_FUNC_NAME(uct_gga_mlx5_ep_t),
    .ep_get_address           = uct_rc_mlx5_ep_get_address,
    .ep_connect_to_ep         = uct_base_ep_connect_to_ep,
#if IBV_HW_TM
    .ep_tag_eager_short       = ucs_empty_function_return_unsupported,
    .ep_tag_eager_bcopy       = (uct_ep_tag_eager_bcopy_func_t)ucs_empty_function_return_unsupported,
    .ep_tag_eager_zcopy       = ucs_empty_function_return_unsupported,
    .ep_tag_rndv_zcopy        = ucs_empty_function_return_unsupported_ptr,
    .ep_tag_rndv_request      = ucs_empty_function_return_unsupported,
    .ep_tag_rndv_cancel       = ucs_empty_function_return_unsupported,
    .iface_tag_recv_zcopy     = ucs_empty_function_return_unsupported,
    .iface_tag_recv_cancel    = ucs_empty_function_return_unsupported,
#endif
    .iface_flush              = uct_rc_iface_flush,
    .iface_fence              = uct_rc_iface_fence,
    .iface_progress_enable    = uct_gga_mlx5_iface_progress_enable,
    .iface_progress_disable   = uct_base_iface_progress_disable,
    .iface_progress           = uct_rc_iface_do_progress,
    .iface_event_fd_get       = uct_rc_mlx5_iface_event_fd_get,
    .iface_event_arm          = uct_rc_mlx5_iface_arm,
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_gga_mlx5_iface_t),
    .iface_query              = uct_gga_mlx5_iface_query,
    .iface_get_address        = ucs_empty_function_return_success,
    .iface_get_device_address = uct_ib_iface_get_device_address,
    .iface_is_reachable       = uct_base_iface_is_reachable
};

UCS_CLASS_INIT_FUNC(uct_gga_mlx5_iface_t,
                    uct_md_h tl_md, uct_worker_h worker,
                    const uct_iface_params_t *params,
                    const uct_iface_config_t *tl_config)
{
    uct_gga_mlx5_iface_config_t *config =
            ucs_derived_of(tl_config, uct_gga_mlx5_iface_config_t);
    uct_ib_mlx5_md_t *md                = ucs_derived_of(tl_md, uct_ib_mlx5_md_t);
    uct_ib_iface_init_attr_t init_attr  = {};
    ucs_status_t status;

    if (!(md->flags & UCT_IB_MLX5_MD_FLAG_MMO_DMA)) {
        return UCS_ERR_UNSUPPORTED;
    }

    init_attr.fc_req_size           = sizeof(uct_rc_pending_req_t);
    init_attr.flags                 = UCT_IB_CQ_IGNORE_OVERRUN | UCT_IB_IS_GGA;
    init_attr.cq_len[UCT_IB_DIR_TX] = config->super.tx_cq_len;
    init_attr.qp_type               = IBV_QPT_RC;
    init_attr.max_rd_atomic         = 0;

    uct_ib_mlx5_parse_cqe_zipping(md, &config->rc_mlx5_common.super,
                                  &init_attr);

    UCS_CLASS_CALL_SUPER_INIT(uct_rc_mlx5_iface_common_t,
                              &uct_gga_mlx5_iface_tl_ops, &uct_gga_mlx5_iface_ops,
                              tl_md, worker, params, &config->super.super,
                              &config->rc_mlx5_common, &init_attr);

    self->super.super.config.tx_moderation = ucs_min(config->super.tx_cq_moderation,
                                                     self->super.tx.bb_max / 4);

    status = uct_rc_init_fc_thresh(&config->super, &self->super.super);
    if (status != UCS_OK) {
        return status;
    }

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_gga_mlx5_iface_t)
{
    uct_base_iface_progress_disable(&self->super.super.super.super.super,
                                    UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);
}

UCS_CLASS_DEFINE(uct_gga_mlx5_iface_t, uct_rc_mlx5_iface_common_t);

static UCS_CLASS_DEFINE_NEW_FUNC(uct_gga_mlx5_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t*,
                                 const uct_iface_config_t*);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_gga_mlx5_iface_t, uct_iface_t);

static ucs_status_t
uct_ib_mlx5_gga_mkey_pack(uct_md_h uct_md, uct_mem_h uct_memh,
                          void *address, size_t length,
                          const uct_md_mkey_pack_params_t *params,
                          void *mkey_buffer)
{
    uct_md_mkey_pack_params_t gga_params = *params;
    ucs_status_t status;
    uct_ib_md_packed_mkey_t *mkey UCS_V_UNUSED;

    gga_params.field_mask |= UCT_MD_MKEY_PACK_FIELD_FLAGS;
    gga_params.flags      |= UCT_MD_MKEY_PACK_FLAG_EXPORT;

    status = uct_ib_mlx5_devx_mkey_pack(uct_md, uct_memh, address, length,
                                        &gga_params, mkey_buffer);
    if (status != UCS_OK) {
        return status;
    }

    mkey = (uct_ib_md_packed_mkey_t*)mkey_buffer;
    ucs_assert(mkey->flags & UCT_IB_PACKED_MKEY_FLAG_EXPORTED);
    mkey->flags |= UCT_IB_PACKED_MKEY_FLAG_GGA;

    return UCS_OK;
}

ucs_status_t
uct_ib_mlx5_gga_rkey_unpack(const uct_ib_md_packed_mkey_t *mkey,
                            uct_rkey_t *rkey_p, void **handle_p)
{
    uct_rkey_bundle_t *rkey_bundle;
    uct_gga_mlx5_rkey_handle_t *rkey_handle;

    ucs_assert(mkey->flags & UCT_IB_PACKED_MKEY_FLAG_EXPORTED);

    rkey_bundle = ucs_malloc(sizeof(*rkey_bundle), "gga_rkey_bundle");
    if (rkey_bundle == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    rkey_handle = ucs_malloc(sizeof(*rkey_handle), "gga_rkey_handle");
    if (rkey_handle == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    rkey_handle->packed_mkey    = *mkey;
    /* memh and rkey_ob will be initialized on demand */
    rkey_handle->memh           = NULL;
    rkey_handle->rkey_ob.rkey   = UCT_INVALID_RKEY;
    rkey_handle->rkey_ob.handle = NULL;
    rkey_handle->rkey_ob.type   = NULL;

    rkey_bundle->handle      = rkey_handle;
    rkey_bundle->rkey        = (uintptr_t)rkey_bundle;
    rkey_bundle->type        = NULL;

    *rkey_p   = rkey_bundle->rkey;
    *handle_p = rkey_bundle->handle;
    return UCS_OK;
}

static ucs_status_t uct_ib_mlx5_gga_md_open(struct ibv_device *ibv_device,
                                            const uct_ib_md_config_t *md_config,
                                            struct uct_ib_md **md_p);

static uct_ib_md_ops_t uct_ib_mlx5_gga_md_ops = {
    .super = {
        .close              = uct_ib_mlx5_devx_md_close,
        .query              = uct_ib_mlx5_devx_md_query,
        .mem_alloc          = uct_ib_mlx5_devx_device_mem_alloc,
        .mem_free           = uct_ib_mlx5_devx_device_mem_free,
        .mem_reg            = uct_ib_mlx5_devx_mem_reg,
        .mem_dereg          = uct_ib_mlx5_devx_mem_dereg,
        .mem_attach         = uct_ib_mlx5_devx_mem_attach,
        .mem_advise         = uct_ib_mem_advise,
        .mkey_pack          = uct_ib_mlx5_gga_mkey_pack,
        .detect_memory_type = ucs_empty_function_return_unsupported,
    },
    .open = uct_ib_mlx5_gga_md_open,
};

static ucs_status_t uct_ib_mlx5_gga_md_open(struct ibv_device *ibv_device,
                                            const uct_ib_md_config_t *md_config,
                                            struct uct_ib_md **md_p)
{
    ucs_status_t status;

    if (md_config->devx == UCS_NO) {
        return UCS_ERR_UNSUPPORTED;
    }

    status = uct_ib_mlx5_devx_md_open(ibv_device, md_config, md_p);
    if (status != UCS_OK) {
        return status;
    }

    (*md_p)->super.ops = &uct_ib_mlx5_gga_md_ops.super;
    (*md_p)->name = UCT_IB_MD_NAME(gga);
    return UCS_OK;
}

UCT_IB_MD_DEFINE_ENTRY(gga, uct_ib_mlx5_gga_md_ops);

static ucs_status_t
uct_gga_mlx5_query_tl_devices(uct_md_h md,
                              uct_tl_device_resource_t **tl_devices_p,
                              unsigned *num_tl_devices_p)
{
    uct_ib_mlx5_md_t *mlx5_md = ucs_derived_of(md, uct_ib_mlx5_md_t);
    uint32_t check_flags      = UCT_IB_MLX5_MD_FLAG_DEVX                       |
                                UCT_IB_MLX5_MD_FLAG_INDIRECT_XGVMI |
                                UCT_IB_MLX5_MD_FLAG_MMO_DMA;

    ucs_info("gga q dev: md name %s vs %s, flags 0x%x & 0x%x = 0x%x",
             mlx5_md->super.name, UCT_IB_MD_NAME(gga), mlx5_md->flags,
             check_flags, mlx5_md->flags & check_flags);

    if (strcmp(mlx5_md->super.name, UCT_IB_MD_NAME(gga)) ||
        !ucs_test_all_flags(mlx5_md->flags, check_flags)) {
        return UCS_ERR_NO_DEVICE;
    }

    return uct_ib_device_query_ports(&mlx5_md->super.dev,
                                     UCT_IB_DEVICE_FLAG_MLX5_PRM, tl_devices_p,
                                     num_tl_devices_p);
}

UCT_TL_DEFINE_ENTRY(&uct_ib_component, gga_mlx5, uct_gga_mlx5_query_tl_devices,
                    uct_gga_mlx5_iface_t, "GGA_MLX5_",
                    uct_gga_mlx5_iface_config_table,
                    uct_gga_mlx5_iface_config_t);
