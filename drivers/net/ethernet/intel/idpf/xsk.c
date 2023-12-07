// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation */

#include <net/libeth/xsk.h>

#include "idpf.h"
#include "xdp.h"
#include "xsk.h"

static void idpf_xsk_tx_timer(struct work_struct *work);

static void idpf_xsk_setup_txq(const struct idpf_vport *vport,
			       struct idpf_tx_queue *txq)
{
	struct xsk_buff_pool *pool;
	u32 qid;

	idpf_queue_clear(XSK, txq);

	if (!idpf_queue_has(XDP, txq))
		return;

	qid = txq->idx - vport->xdp_txq_offset;

	pool = xsk_get_pool_from_qid(vport->netdev, qid);
	if (!pool || !pool->dev)
		return;

	txq->pool = pool;
	libeth_xdpsq_init_timer(txq->timer, txq, &txq->xdp_lock,
				idpf_xsk_tx_timer);

	idpf_queue_assign(NOIRQ, txq, xsk_uses_need_wakeup(pool));
	idpf_queue_set(XSK, txq);
}

static void idpf_xsk_setup_complq(const struct idpf_vport *vport,
				  struct idpf_compl_queue *complq)
{
	const struct xsk_buff_pool *pool;
	u32 qid;

	idpf_queue_clear(XSK, complq);

	if (!idpf_queue_has(XDP, complq))
		return;

	qid = complq->txq_grp->txqs[0]->idx - vport->xdp_txq_offset;

	pool = xsk_get_pool_from_qid(vport->netdev, qid);
	if (!pool || !pool->dev)
		return;

	idpf_queue_set(XSK, complq);
}

/**
 * idpf_xsk_setup_queue - set xsk_pool pointer from netdev to the queue structure
 * @vport: vport this queue belongs to
 * @q: queue to use
 * @type: queue type
 *
 * Assigns pointer to xsk_pool field in queue struct if it is supported in
 * netdev, NULL otherwise.
 */
void idpf_xsk_setup_queue(const struct idpf_vport *vport, void *q,
			  enum virtchnl2_queue_type type)
{
	if (!idpf_xdp_is_prog_ena(vport))
		return;

	switch (type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		idpf_xsk_setup_txq(vport, q);
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		idpf_xsk_setup_complq(vport, q);
		break;
	default:
		break;
	}
}

void idpf_xsk_clear_queue(void *q, enum virtchnl2_queue_type type)
{
	struct idpf_compl_queue *complq;
	struct idpf_tx_queue *txq;

	switch (type) {
	case VIRTCHNL2_QUEUE_TYPE_TX:
		txq = q;
		if (!idpf_queue_has_clear(XSK, txq))
			return;

		idpf_queue_set(NOIRQ, txq);
		txq->dev = txq->netdev->dev.parent;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		complq = q;
		idpf_queue_clear(XSK, complq);
		break;
	default:
		break;
	}
}

/**
 * idpf_xsk_clean_xdpq - clean an XSk Tx queue
 * @xdpq: XSk Tx queue
 */
void idpf_xsk_clean_xdpq(struct idpf_tx_queue *xdpq)
{
	struct libeth_xdpsq_napi_stats ss = { };
	u32 ntc = xdpq->next_to_clean;
	struct xdp_frame_bulk bq;
	struct libeth_cq_pp cp = {
		.dev	= xdpq->pool->dev,
		.bq	= &bq,
		.xss	= &ss,
	};
	u32 xsk_frames = 0;

	xdp_frame_bulk_init(&bq);
	rcu_read_lock();

	while (ntc != xdpq->next_to_use) {
		struct libeth_sqe *sqe = &xdpq->tx_buf[ntc];

		if (sqe->type)
			libeth_xdp_complete_tx(sqe, &cp);
		else
			xsk_frames++;

		if (unlikely(++ntc == xdpq->desc_count))
			ntc = 0;
	}

	xdp_flush_frame_bulk(&bq);
	rcu_read_unlock();

	if (xsk_frames)
		xsk_tx_completed(xdpq->pool, xsk_frames);
}

static noinline u32 idpf_xsksq_complete_slow(struct idpf_tx_queue *xdpsq,
					     u32 done)
{
	struct libeth_xdpsq_napi_stats ss = { };
	u32 ntc = xdpsq->next_to_clean;
	u32 cnt = xdpsq->desc_count;
	struct xdp_frame_bulk bq;
	struct libeth_cq_pp cp = {
		.dev	= xdpsq->pool->dev,
		.bq	= &bq,
		.xss	= &ss,
		.napi	= true,
	};
	u32 xsk_frames = 0;

	xdp_frame_bulk_init(&bq);

	for (u32 i = 0; likely(i < done); i++) {
		struct libeth_sqe *sqe = &xdpsq->tx_buf[ntc];

		if (sqe->type)
			libeth_xdp_complete_tx(sqe, &cp);
		else
			xsk_frames++;

		if (unlikely(++ntc == cnt))
			ntc = 0;
	}

	xdp_flush_frame_bulk(&bq);

	xdpsq->next_to_clean = ntc;
	xdpsq->xdp_tx -= cp.xdp_tx;

	libeth_xdpsq_napi_stats_add(&xdpsq->xstats, &ss);

	return xsk_frames;
}

/**
 * idpf_clean_xdp_irq_zc - produce AF_XDP descriptors to CQ
 * @_xdpq: XDP Tx queue
 * @budget: maximum number of descriptors to clean
 *
 * Return: number of cleaned descriptors.
 */
static __always_inline u32 idpf_clean_xdp_irq_zc(void *_xdpq, u32 budget)
{
	struct idpf_tx_queue *xdpq = _xdpq;
	u32 tx_ntc = xdpq->next_to_clean;
	u32 tx_cnt = xdpq->desc_count;
	u32 done_frames;
	u32 xsk_frames;

	done_frames = idpf_xdpsq_poll(xdpq, budget);
	if (unlikely(!done_frames))
		return 0;

	if (likely(!xdpq->xdp_tx)) {
		tx_ntc += done_frames;
		if (tx_ntc >= tx_cnt)
			tx_ntc -= tx_cnt;

		xdpq->next_to_clean = tx_ntc;
		xsk_frames = done_frames;

		goto finalize;
	}

	xsk_frames = idpf_xsksq_complete_slow(xdpq, done_frames);
	if (xsk_frames)
finalize:
		xsk_tx_completed(xdpq->pool, xsk_frames);

	xdpq->pending -= done_frames;

	return done_frames;
}

static u32 idpf_xsk_xmit_prep(void *_xdpq, struct libeth_xdpsq *sq)
{
	struct idpf_tx_queue *xdpq = _xdpq;

	*sq = (struct libeth_xdpsq){
		.pool		= xdpq->pool,
		.sqes		= xdpq->tx_buf,
		.descs		= xdpq->desc_ring,
		.count		= xdpq->desc_count,
		.lock		= &xdpq->xdp_lock,
		.ntu		= &xdpq->next_to_use,
		.pending	= &xdpq->pending,
	};

	/* The queue is cleaned, the budget is already known, optimize out
	 * the second min() by passing the type limit.
	 */
	return U32_MAX;
}

/**
 * idpf_xsk_xmit - send XSk frames
 * @xsksq: XSk queue to produce the HW Tx descriptors on
 *
 * Return: %true if there's no more work to be done, %false otherwise.
 */
bool idpf_xsk_xmit(struct idpf_tx_queue *xsksq)
{
	u32 free;

	libeth_xdpsq_lock(&xsksq->xdp_lock);

	free = xsksq->desc_count - xsksq->pending;
	if (unlikely(free < xsksq->thresh))
		free += idpf_clean_xdp_irq_zc(xsksq, xsksq->thresh);

	return libeth_xsk_xmit_do_bulk(xsksq->pool, xsksq,
				       min(free, xsksq->thresh),
				       libeth_xsktmo, idpf_xsk_xmit_prep,
				       idpf_xdp_tx_xmit, idpf_xdp_tx_finalize);
}

LIBETH_XDP_DEFINE_START();
LIBETH_XDP_DEFINE_TIMER(static idpf_xsk_tx_timer, idpf_clean_xdp_irq_zc);
LIBETH_XDP_DEFINE_END();

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
