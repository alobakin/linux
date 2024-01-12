// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2023 Intel Corporation */

#include <linux/net/intel/libie/xsk.h>

#include "idpf.h"
#include "idpf_xsk.h"

/**
 * idpf_xsk_setup_queue - set xsk_pool pointer from netdev to the queue structure
 * @q: queue to use
 * @t: queue type
 *
 * Assigns pointer to xsk_pool field in queue struct if it is supported in
 * netdev, NULL otherwise.
 */
void idpf_xsk_setup_queue(struct idpf_queue *q, enum virtchnl2_queue_type t)
{
	struct idpf_vport_user_config_data *cfg_data;
	struct idpf_vport *vport = q->vport;
	struct xsk_buff_pool *pool;
	bool is_rx = false;
	int qid;

	__clear_bit(__IDPF_Q_XSK, q->flags);

	if (!idpf_xdp_is_prog_ena(q->vport))
		return;

	switch (t) {
	case VIRTCHNL2_QUEUE_TYPE_RX:
		is_rx = true;
		qid = q->idx;
		break;
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		is_rx = true;
		qid = q->rxq_grp->splitq.rxq_sets[0]->rxq.idx;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX:
		qid = q->idx - q->vport->xdp_txq_offset;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		qid = q->txq_grp->txqs[0]->idx - q->vport->xdp_txq_offset;
		break;
	default:
		return;
	}

	if (!is_rx && !test_bit(__IDPF_Q_XDP, q->flags))
		return;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;

	if (!test_bit(qid, cfg_data->af_xdp_zc_qps))
		return;

	pool = xsk_get_pool_from_qid(q->vport->netdev, qid);

	if (pool && is_rx && !xsk_buff_can_alloc(pool, 1))
		return;

	if (is_rx)
		q->xsk_rx = pool;
	else
		q->xsk_tx = pool;

	__set_bit(__IDPF_Q_XSK, q->flags);
}

void idpf_xsk_clear_queue(struct idpf_queue *q)
{
	struct device *dev;

	if (!__test_and_clear_bit(__IDPF_Q_XSK, q->flags))
		return;

	switch (q->q_type) {
	case VIRTCHNL2_QUEUE_TYPE_RX:
	case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
		dev = q->xsk_rx->dev;
		q->xsk_rx = NULL;
		q->dev = dev;
		break;
	case VIRTCHNL2_QUEUE_TYPE_TX:
	case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
		dev = q->xsk_tx->dev;
		q->xsk_tx = NULL;
		q->dev = dev;
		break;
	}
}

/**
 * idpf_qp_cfg_qs - Configure all queues contained from a given array.
 * @vport: vport structure
 * @qs: an array of queues to configure
 * @num_qs: number of queues in the 'qs' array
 *
 * Returns 0 in case of success, false otherwise.
 */
static int
idpf_qp_cfg_qs(struct idpf_vport *vport, struct idpf_queue **qs, int num_qs)
{
	bool splitq = idpf_is_queue_model_split(vport->rxq_model);
	int i, err;

	for (i = 0; i < num_qs; i++) {
		const struct idpf_bufq_set *sets;
		struct idpf_queue *q = qs[i];
		enum libie_rx_buf_type qt;
		u32 ts;

		switch (q->q_type) {
		case VIRTCHNL2_QUEUE_TYPE_RX:
			err = idpf_rx_desc_alloc(q, false, vport->rxq_model);
			if (err) {
				netdev_err(vport->netdev, "Could not allocate buffer for RX queue.\n");
				break;
			}
			if (!splitq)
				err = idpf_rx_bufs_init(q, LIBIE_RX_BUF_MTU);
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			err = idpf_rx_desc_alloc(q, true, vport->rxq_model);
			if (err)
				break;

			sets = q->rxq_grp->splitq.bufq_sets;
			qt = q->idx ? LIBIE_RX_BUF_SHORT : LIBIE_RX_BUF_MTU;
			ts = q->idx ? sets[q->idx - 1].bufq.truesize >> 1 : 0;
			q->truesize = ts;

			err = idpf_rx_bufs_init(q, qt);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX:
			err = idpf_tx_desc_alloc(q, true);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
			err = idpf_tx_desc_alloc(q, false);
			break;
		}

		if (err)
			return err;
	}

	return 0;
}

/**
 * idpf_qp_clean_qs - Clean all queues contained from a given array.
 * @vport: vport structure
 * @qs: an array of queues to clean
 * @num_qs: number of queues in the 'qs' array
 */
static void
idpf_qp_clean_qs(struct idpf_vport *vport, struct idpf_queue **qs, int num_qs)
{
	for (u32 i = 0; i < num_qs; i++) {
		struct idpf_queue *q = qs[i];

		switch (q->q_type) {
		case VIRTCHNL2_QUEUE_TYPE_RX:
			idpf_rx_desc_rel(q, false, vport->rxq_model);
			break;
		case VIRTCHNL2_QUEUE_TYPE_RX_BUFFER:
			idpf_rx_desc_rel(q, true, vport->rxq_model);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX:
			idpf_tx_desc_rel(q, true);
			q->txq_grp->num_completions_pending = 0;
			writel(q->next_to_use, q->tail);
			break;
		case VIRTCHNL2_QUEUE_TYPE_TX_COMPLETION:
			idpf_tx_desc_rel(q, false);
			q->num_completions = 0;
			break;
		}
	}
}

/**
 * idpf_trigger_sw_intr - trigger a software interrupt
 * @hw: pointer to the HW structure
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
static void
idpf_trigger_sw_intr(struct idpf_hw *hw, struct idpf_q_vector *q_vector)
{
	struct idpf_intr_reg *intr = &q_vector->intr_reg;
	u32 val;

	val = intr->dyn_ctl_intena_m | intr->dyn_ctl_itridx_m | /* set no itr*/
	      intr->dyn_ctl_swint_trig_m |intr->dyn_ctl_sw_itridx_ena_m;

	writel(val, intr->dyn_ctl);
}

/**
 * idpf_qvec_ena_irq - Enable IRQ for given queue vector
 * @q_vector: queue vector
 */
static void
idpf_qvec_ena_irq(struct idpf_q_vector *q_vector)
{
	/* Write the default ITR values */
	if (q_vector->num_rxq)
		idpf_vport_intr_write_itr(q_vector, q_vector->rx_itr_value,
					  false);
	if (q_vector->num_txq)
		idpf_vport_intr_write_itr(q_vector, q_vector->tx_itr_value,
					  true);
	if (q_vector->num_rxq || q_vector->num_txq)
		idpf_vport_intr_update_itr_ena_irq(q_vector);
}

/**
 * idpf_insert_txqs_from_grp - Insert all tx and buffer queues from txq group
 *			       to a given array.
 * @vport: vport structure
 * @txq: pointer to a tx queue
 * @qs: pointer to an element of array where tx queues should be inserted
 *
 * Returns the number of queues that has been inserted to an output 'qs'
 * array.
 * Note that the caller of this function must ensure that there is enough space
 * in the 'qs' array to insert all the queues from the rx queue group.
 */
static int
idpf_insert_txqs_from_grp(struct idpf_vport *vport,
			  struct idpf_queue *txq,
			  struct idpf_queue **qs)
{
	int qs_idx = 0;

	if (!idpf_is_queue_model_split(vport->txq_model)) {
		qs[qs_idx++] = txq;
	} else {
		struct idpf_txq_group *txq_grp = txq->txq_grp;
		int i;

		for (i = 0; i < txq_grp->num_txq; i++)
			qs[qs_idx++] = txq_grp->txqs[i];

		for (i = 0; i < IDPF_COMPLQ_PER_GROUP; i++)
			qs[qs_idx++] = &txq_grp->complq[i];
	}

	return qs_idx;
}

/**
 * idpf_insert_rxqs_from_grp - Insert all rx and buffer queues from rxq group
 *			       to a given array.
 * @vport: vport structure
 * @rxq: pointer to a rx queue
 * @qs: pointer to an element of array where rx queues should be inserted
 *
 * Returns the number of queues that has been inserted to an output 'qs'
 * array.
 * Note that the caller of this function must ensure that there is enough space
 * in the 'qs' array to insert all the queues from the rx queue group.
 */
static int
idpf_insert_rxqs_from_grp(struct idpf_vport *vport,
			  struct idpf_queue *rxq,
			  struct idpf_queue **qs)
{
	int qs_idx = 0;

	if (!idpf_is_queue_model_split(vport->rxq_model)) {
		qs[qs_idx++] = rxq;
	} else {
		struct idpf_rxq_group *rxq_grp = rxq->rxq_grp;
		int i;

		for (i = 0; i < rxq_grp->splitq.num_rxq_sets; i++)
			qs[qs_idx++] = &rxq_grp->splitq.rxq_sets[i]->rxq;

		for (i = 0; i < vport->num_bufqs_per_qgrp; i++)
			qs[qs_idx++] = &rxq_grp->splitq.bufq_sets[i].bufq;
	}

	return qs_idx;
}

/**
 * idpf_count_rxqs_in_grp - Returns the number of rx queues in rx queue group
 *			    containing a given rx queue.
 * @vport: vport structure
 * @rxq: pointer to a rx queue
 *
 * Returns the number of rx queues in the rx queue group associated with
 * a given rx queue. Or, in case of singleq mode, 1, because rx queues
 * are not grouped.
 */
static int
idpf_count_rxqs_in_grp(struct idpf_vport *vport, struct idpf_queue *rxq)
{
	if (!idpf_is_queue_model_split(vport->rxq_model))
		return 1;

	return rxq->rxq_grp->splitq.num_rxq_sets + vport->num_bufqs_per_qgrp;
}

/**
 * idpf_count_txqs_in_grp - Returns the number of tx queues in tx queue group
 *			    containing a given tx queue.
 * @vport: vport structure
 * @txq: pointer to a tx queue
 *
 * Returns the number of tx queues in the tx queue group associated with
 * a given tx queue. Or, in case of singleq mode, 1, because tx queues
 * are not grouped.
 */
static int
idpf_count_txqs_in_grp(struct idpf_vport *vport, struct idpf_queue *txq)
{
	if (!idpf_is_queue_model_split(vport->txq_model))
		return 1;

	return txq->txq_grp->num_txq + IDPF_COMPLQ_PER_GROUP;
}

/**
 * idpf_create_queue_list - Creates a list of queues associated with a given
 *			    queue index.
 * @vport: vport structure
 * @q_idx: index of queue pair to establish XSK socket
 * @num_qs: number of queues in returned array.
 *
 * Returns a pointer to a dynamically allocated array of pointers to all
 * queues associated with a given queue index (q_idx).
 * Please note that the caller is responsible to free the memory allocated
 * by this function using 'kfree()'.
 * NULL-pointer will be returned in case of error.
 */
static struct idpf_queue **
idpf_create_queue_list(struct idpf_vport *vport, u16 q_idx, int *num_qs)
{
	struct idpf_queue *rxq, *txq, *xdpq = NULL;
	struct idpf_queue **qs;
	int qs_idx;

	*num_qs = 0;

	if (q_idx >= vport->num_rxq || q_idx >= vport->num_txq)
		return NULL;

	rxq = idpf_find_rxq(vport, q_idx);
	txq = idpf_find_txq(vport, q_idx);

	*num_qs += idpf_count_rxqs_in_grp(vport, rxq);
	*num_qs += idpf_count_txqs_in_grp(vport, txq);

	if (idpf_xdp_is_prog_ena(vport)) {
		xdpq = vport->txqs[q_idx + vport->xdp_txq_offset];
		*num_qs += idpf_count_txqs_in_grp(vport, xdpq);
	}

	qs = kcalloc(*num_qs, sizeof(*qs), GFP_KERNEL);
	if (!qs)
		return NULL;

	qs_idx = 0;
	qs_idx += idpf_insert_txqs_from_grp(vport, txq, &qs[qs_idx]);

	if (xdpq)
		qs_idx += idpf_insert_txqs_from_grp(vport, xdpq, &qs[qs_idx]);

	qs_idx += idpf_insert_rxqs_from_grp(vport, rxq, &qs[qs_idx]);

	if (*num_qs != qs_idx) {
		kfree(qs);
		*num_qs = 0;
		qs = NULL;
	}

	return qs;
}

/**
 * idpf_qp_dis - Disables queues associated with a queue pair
 * @vport: vport structure
 * @q_vector: interrupt vector mapped to a given queue pair
 * @qs: array of pointers to queues to enable
 * @num_qs: number of queues in 'qs' array
 * @q_idx: index of queue pair to enable
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_qp_dis(struct idpf_vport *vport, struct idpf_q_vector *q_vector,
		       struct idpf_queue **qs, int num_qs, u16 q_idx)
{
	int err = 0;

	netif_stop_subqueue(vport->netdev, q_idx);

	err = idpf_send_disable_vport_msg(vport);
	if (err) {
		netdev_err(vport->netdev, "Could not disable vport, error = %d\n",
			   err);
		goto err_send_msg;
	}
	err = idpf_send_disable_selected_queues_msg(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not disable queues for index %d, error = %d\n",
			   q_idx, err);
		goto err_send_msg;
	}

	napi_disable(&q_vector->napi);
	writel(0, q_vector->intr_reg.dyn_ctl);
	idpf_qp_clean_qs(vport, qs, num_qs);

	return 0;

err_send_msg:
	netif_start_subqueue(vport->netdev, q_idx);

	return err;
}

/**
 * idpf_qp_ena - Enables queues associated with a queue pair
 * @vport: vport structure
 * @q_vector: interrupt vector mapped to a given queue pair
 * @qs: array of pointers to queues to enable
 * @num_qs: number of queues in 'qs' array
 * @q_idx: index of queue pair to enable
 *
 * Returns 0 on success, negative on failure.
 */
static int idpf_qp_ena(struct idpf_vport *vport, struct idpf_q_vector *q_vector,
		       struct idpf_queue **qs, int num_qs, u16 q_idx)
{
	int err;

	err = idpf_qp_cfg_qs(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not initialize queues for index %d, error = %d\n",
			   q_idx, err);
		return err;
	}

	napi_enable(&q_vector->napi);
	idpf_qvec_ena_irq(q_vector);

	err = idpf_send_config_selected_queues_msg(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not configure queues for index %d, error = %d\n",
			   q_idx, err);
		return err;
	}

	err = idpf_send_enable_selected_queues_msg(vport, qs, num_qs);
	if (err) {
		netdev_err(vport->netdev, "Could not enable queues for index %d, error = %d\n",
			   q_idx, err);
		return err;
	}

	err = idpf_send_enable_vport_msg(vport);
	if (err) {
		netdev_err(vport->netdev, "Could not enable vport, error = %d\n",
			   err);
		return err;
	}

	netif_start_subqueue(vport->netdev, q_idx);

	return 0;
}

/**
 * idpf_xsk_pool_disable - disables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int idpf_xsk_pool_disable(struct idpf_vport *vport, u16 qid)
{
	struct idpf_vport_user_config_data *cfg_data;

	if (!vport->rxq_grps)
		return -EINVAL;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;

	return libie_xsk_disable_pool(vport->netdev, qid,
				      cfg_data->af_xdp_zc_qps);
}
/**
 * idpf_xsk_pool_enable - enables a BUFF POOL region
 * @vport: vport to allocate the buffer pool on
 * @qid: queue id
 *
 * Returns 0 on success, negative on error
 */
static int idpf_xsk_pool_enable(struct idpf_vport *vport, u16 qid)
{
	struct idpf_vport_user_config_data *cfg_data;

	cfg_data = &vport->adapter->vport_config[vport->idx]->user_config;

	return libie_xsk_enable_pool(vport->netdev, qid,
				     cfg_data->af_xdp_zc_qps);
}

/**
 * idpf_xsk_pool_setup - enable/disable a BUFF POOL region
 * @vport: current vport of interest
 * @pool: pointer to a requested BUFF POOL region
 * @qid: queue id
 *
 * Returns 0 on success, negative on failure
 */
int idpf_xsk_pool_setup(struct idpf_vport *vport, struct xsk_buff_pool *pool,
			u32 qid)
{
	bool if_running, pool_present = !!pool;
	int err = 0, pool_failure = 0, num_qs;
	struct idpf_q_vector *q_vector;
	struct idpf_queue *rxq, **qs;

	if_running = netif_running(vport->netdev) &&
		     idpf_xdp_is_prog_ena(vport);

	if (if_running) {
		rxq = idpf_find_rxq(vport, qid);
		q_vector = rxq->q_vector;

		qs = idpf_create_queue_list(vport, qid, &num_qs);
		if (!qs) {
			err = -ENOMEM;
			goto xsk_exit;
		}

		err = idpf_qp_dis(vport, q_vector, qs, num_qs, qid);
		if (err) {
			netdev_err(vport->netdev, "Cannot disable queues for XSK setup, error = %d\n",
				   err);
			goto xsk_pool_if_up;
		}
	}

	pool_failure = pool_present ? idpf_xsk_pool_enable(vport, qid) :
				      idpf_xsk_pool_disable(vport, qid);

	if (!idpf_xdp_is_prog_ena(vport))
		netdev_warn(vport->netdev, "RSS may schedule pkts to q occupied by AF XDP\n");

xsk_pool_if_up:
	if (if_running) {
		err = idpf_qp_ena(vport, q_vector, qs, num_qs, qid);
		if (!err && pool_present)
			napi_schedule(&rxq->q_vector->napi);
		else if (err)
			netdev_err(vport->netdev,
				   "Could not enable queues after XSK setup, error = %d\n",
				   err);
		kfree(qs);
	}

	if (pool_failure) {
		netdev_err(vport->netdev, "Could not %sable BUFF POOL, error = %d\n",
			   pool_present ? "en" : "dis", pool_failure);
		err = pool_failure;
	}

xsk_exit:
	return err;
}

/**
 * idpf_xsk_clean_xdpq - Clean the XDP Tx queue and its buffer pool queues
 * @xdpq: XDP_Tx queue
 */
void idpf_xsk_clean_xdpq(struct idpf_queue *xdpq)
{
	u32 ntc = xdpq->next_to_clean, ntu = xdpq->next_to_use;
	struct device *dev = xdpq->xsk_tx->dev;
	struct libie_sq_onstack_stats ss = { };
	struct xdp_frame_bulk bq;
	u32 xsk_frames = 0;

	xdp_frame_bulk_init(&bq);
	rcu_read_lock();

	while (ntc != ntu) {
		struct libie_tx_buffer *tx_buf = &xdpq->tx_buf[ntc];

		if (tx_buf->type)
			libie_xdp_complete_tx_buf(tx_buf, dev, false, &bq,
						  &xdpq->xdp_tx_active, &ss);
		else
			xsk_frames++;

		if (unlikely(++ntc >= xdpq->desc_count))
			ntc = 0;
	}

	xdp_flush_frame_bulk(&bq);
	rcu_read_unlock();

	if (xsk_frames)
		xsk_tx_completed(xdpq->xsk_tx, xsk_frames);
}

/**
 * idpf_clean_xdp_irq_zc - produce AF_XDP descriptors to CQ
 * @complq: completion queue associated with zero-copy Tx queue
 */
static u32 idpf_clean_xdp_irq_zc(struct idpf_queue *complq)
{
	struct idpf_splitq_4b_tx_compl_desc *last_rs_desc;
	struct device *dev = complq->xsk_tx->dev;
	struct libie_sq_onstack_stats ss = { };
	int complq_budget = complq->desc_count;
	u32 ntc = complq->next_to_clean;
	struct idpf_queue *xdpq = NULL;
	struct xdp_frame_bulk bq;
	u32 done_frames = 0;
	u32 xsk_frames = 0;
	u32 tx_ntc, cnt;
	bool gen_flag;
	int head, i;

	last_rs_desc = &complq->comp_4b[ntc];
	gen_flag = test_bit(__IDPF_Q_GEN_CHK, complq->flags);

	do {
		int ctype = idpf_parse_compl_desc(last_rs_desc, complq,
						  &xdpq, gen_flag);

		if (likely(ctype == IDPF_TXD_COMPLT_RS)) {
			head = le16_to_cpu(last_rs_desc->q_head_compl_tag.q_head);
			goto fetch_next_desc;
		}

		switch (ctype) {
		case IDPF_TXD_COMPLT_SW_MARKER:
			idpf_tx_handle_sw_marker(xdpq);
			break;
		case -ENODATA:
			goto clean_xdpq;
		case -EINVAL:
			goto fetch_next_desc;
		default:
			dev_err(&xdpq->vport->adapter->pdev->dev,
				"Unsupported completion type for XSK\n");
			goto fetch_next_desc;
		}

fetch_next_desc:
		last_rs_desc++;
		ntc++;
		if (unlikely(ntc == complq->desc_count)) {
			ntc = 0;
			last_rs_desc = &complq->comp_4b[0];
			gen_flag = !gen_flag;
			change_bit(__IDPF_Q_GEN_CHK, complq->flags);
		}
		prefetch(last_rs_desc);
		complq_budget--;
	} while (likely(complq_budget));

clean_xdpq:
	complq->next_to_clean = ntc;

	if (!xdpq)
		return 0;

	libie_xdp_sq_lock(&xdpq->xdp_lock);

	cnt = xdpq->desc_count;
	tx_ntc = xdpq->next_to_clean;
	done_frames = head >= tx_ntc ? head - tx_ntc :
				       head + cnt - tx_ntc;
	if (!done_frames)
		return 0;

	if (likely(!xdpq->xdp_tx_active)) {
		xsk_frames = done_frames;
		goto xsk;
	}

	xdp_frame_bulk_init(&bq);

	for (i = 0; i < done_frames; i++) {
		struct libie_tx_buffer *tx_buf = &xdpq->tx_buf[tx_ntc];

		if (tx_buf->type)
			libie_xdp_complete_tx_buf(tx_buf, dev, true, &bq,
						  &xdpq->xdp_tx_active,
						  &ss);
		else
			xsk_frames++;

		if (unlikely(++tx_ntc == cnt))
			tx_ntc = 0;
	}

	xdp_flush_frame_bulk(&bq);

xsk:
	xdpq->next_to_clean += done_frames;
	if (xdpq->next_to_clean >= cnt)
		xdpq->next_to_clean -= cnt;

	if (xsk_frames)
		xsk_tx_completed(xdpq->xsk_tx, xsk_frames);

	libie_xdp_sq_unlock(&xdpq->xdp_lock);

	return done_frames;
}

/**
 * idpf_xsk_xmit_pkt - produce a single HW Tx descriptor out of AF_XDP desc
 * @desc: AF_XDP descriptor to pull the DMA address and length from
 * @sq: XDP queue to produce the HW Tx descriptor on
 */
static void idpf_xsk_xmit_pkt(struct libie_xdp_tx_desc desc,
			      const struct libie_xdp_tx_queue *sq)
{
	union idpf_tx_flex_desc *tx_desc = sq->desc_ring;
	struct idpf_tx_splitq_params tx_params = {
		.dtype		= IDPF_TX_DESC_DTYPE_FLEX_L2TAG1_L2TAG2,
		.eop_cmd	= IDPF_TX_DESC_CMD_EOP,
	};

	tx_desc = &tx_desc[sq->cached_ntu];
	tx_desc->q.buf_addr = cpu_to_le64(desc.addr);

	idpf_tx_splitq_build_desc(tx_desc, &tx_params,
				  tx_params.eop_cmd | tx_params.offload.td_cmd,
				  desc.len);
}

static u32 idpf_xsk_xmit_prep(void *_xdpq, struct libie_xdp_tx_queue *sq)
{
	struct idpf_queue *xdpq = _xdpq;

	libie_xdp_sq_lock(&xdpq->xdp_lock);

	*sq = (struct libie_xdp_tx_queue){
		.pool		= xdpq->xsk_tx,
		.tx_buf		= xdpq->tx_buf,
		.desc_ring	= xdpq->desc_ring,
		.desc_count	= xdpq->desc_count,
		.xdp_lock	= &xdpq->xdp_lock,
		.next_to_use	= &xdpq->next_to_use,
	};

	return IDPF_DESC_UNUSED(xdpq);
}

/**
 * idpf_xmit_xdpq_zc - take entries from XSK Tx queue and place them onto HW Tx queue
 * @xdpq: XDP queue to produce the HW Tx descriptors on
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
static bool idpf_xmit_xdpq_zc(struct idpf_queue *xdpq)
{
	u32 budget;

	budget = min_t(u32, IDPF_DESC_UNUSED(xdpq), IDPF_QUEUE_QUARTER(xdpq));

	return libie_xsk_xmit_do_bulk(xdpq, xdpq->xsk_tx, budget,
				      idpf_xsk_xmit_prep, idpf_xsk_xmit_pkt,
				      idpf_xdp_tx_finalize);
}

/**
 * idpf_xmit_zc - perform xmit from all XDP queues assigned to the completion queue
 * @complq: Completion queue associated with one or more XDP queues
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
bool idpf_xmit_zc(struct idpf_queue *complq)
{
	struct idpf_txq_group *xdpq_grp = complq->txq_grp;
	bool result = true;
	int i;

	idpf_clean_xdp_irq_zc(complq);

	for (i = 0; i < xdpq_grp->num_txq; i++)
		result &= idpf_xmit_xdpq_zc(xdpq_grp->txqs[i]);

	return result;
}
