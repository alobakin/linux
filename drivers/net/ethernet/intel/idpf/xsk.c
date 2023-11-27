// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/xsk.h>

#include "idpf.h"
#include "xsk.h"

/**
 * idpf_xsk_pool_setup - set up an XSk pool
 * @vport: current vport of interest
 * @bpf: pointer to the pool data
 *
 * Return: 0 on success, -errno on failure.
 */
int idpf_xsk_pool_setup(struct idpf_vport *vport, struct netdev_bpf *bpf)
{
	struct xsk_buff_pool *pool = bpf->xsk.pool;
	u32 qid = bpf->xsk.queue_id;
	bool restart;
	int ret;

	ret = libeth_xsk_setup_pool(vport->netdev, qid, pool);
	if (ret) {
		NL_SET_ERR_MSG_FMT_MOD(bpf->extack,
				       "%s: failed to configure XSk pool for pair %u: %pe",
				       netdev_name(vport->netdev), qid, &ret);
		return ret;
	}

	restart = netif_running(vport->netdev) && idpf_xdp_is_prog_ena(vport);
	if (!restart)
		return 0;

	ret = idpf_qp_restart(vport, qid);
	if (ret) {
		NL_SET_ERR_MSG_FMT_MOD(bpf->extack,
				       "%s: failed to reconfigure queue pair %u: %pe",
				       netdev_name(vport->netdev), qid, &ret);
		goto err_dis;
	}

	return 0;

err_dis:
	libeth_xsk_setup_pool(vport->netdev, qid, false);

	return ret;
}
