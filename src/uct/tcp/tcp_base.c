/**
* Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2020. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "tcp_base.h"

#include <ucs/sys/string.h>

ucs_status_t ucs_tcp_base_set_syn_cnt(int fd, int tcp_syn_cnt)
{
    if (tcp_syn_cnt != UCS_ULUNITS_AUTO) {
        ucs_socket_setopt(fd, IPPROTO_TCP, TCP_SYNCNT, (const void*)&tcp_syn_cnt,
                          sizeof(int));
    }

    /* return UCS_OK anyway since setting TCP_SYNCNT is done on best effort */
    return UCS_OK;
}

int uct_tcp_keepalive_is_enabled(const uct_tcp_keepalive_config_t *config)
{
#if UCT_TCP_EP_KEEPALIVE
    return (config->idle != UCS_TIME_INFINITY) &&
           (config->cnt != UCS_ULUNITS_INF) &&
           (config->intvl != UCS_TIME_INFINITY);
#else /* UCT_TCP_EP_KEEPALIVE */
    return 0;
#endif /* UCT_TCP_EP_KEEPALIVE */
}

static int uct_tcp_time_seconds(ucs_time_t time_val, int auto_val, int max_val)
{
    if (time_val == UCS_TIME_AUTO) {
        return auto_val;
    } else if (time_val == UCS_TIME_INFINITY) {
        return max_val;
    }

    return ucs_min(max_val, ucs_max(1l, ucs_time_to_sec(time_val)));
}

ucs_status_t
uct_tcp_keepalive_enable(int fd, const uct_tcp_keepalive_config_t *config)
{
#if UCT_TCP_EP_KEEPALIVE
    const int optval = 1;
    int idle_sec;
    int intvl_sec;
    int keepalive_cnt;
    ucs_status_t status;

    if (!uct_tcp_keepalive_is_enabled(config)) {
        return UCS_OK;
    }

    idle_sec  = uct_tcp_time_seconds(config->idle,
                                     UCT_TCP_DEFAULT_KEEPALIVE_IDLE, INT16_MAX);
    intvl_sec = uct_tcp_time_seconds(config->intvl,
                                     UCT_TCP_DEFAULT_KEEPALIVE_INTVL,
                                     INT16_MAX);

    status = ucs_socket_setopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl_sec,
                               sizeof(intvl_sec));
    if (status != UCS_OK) {
        return status;
    }

    if (config->cnt != UCS_ULUNITS_AUTO) {
        if (config->cnt == UCS_ULUNITS_INF) {
            keepalive_cnt = INT8_MAX;
        } else {
            keepalive_cnt = ucs_min(INT8_MAX, config->cnt);
        }

        status = ucs_socket_setopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                                   &keepalive_cnt, sizeof(keepalive_cnt));
        if (status != UCS_OK) {
            return status;
        }
    }

    status = ucs_socket_setopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_sec,
                               sizeof(idle_sec));
    if (status != UCS_OK) {
        return status;
    }

    return ucs_socket_setopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval,
                             sizeof(optval));
#else /* UCT_TCP_EP_KEEPALIVE */
    return UCS_OK;
#endif /* UCT_TCP_EP_KEEPALIVE */
}
