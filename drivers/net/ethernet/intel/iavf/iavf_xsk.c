// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. */

#include <linux/bpf_trace.h>
#include <linux/filter.h>
#include <linux/net/intel/libie/rx.h>
#include <net/xdp_sock_drv.h>
#include <net/xdp_sock.h>
#include "iavf.h"
#include "iavf_trace.h"
#include "iavf_xsk.h"

#define IAVF_CRIT_LOCK_WAIT_TIMEOUT_MS	1000
#define IAVF_VC_MSG_TIMEOUT_MS		3000

/**
 * iavf_max_xdp_queues_count - Returns the maximal number of XDP queues
 *			       that can be created for current configuration
 *			       of a given adapter.
 * @adapter: adapter where XDP socket will be set up
 */
static u32
iavf_max_xdp_queues_count(struct iavf_adapter *adapter)
{
	u32 max_qp_num = adapter->vsi_res->num_queue_pairs;
	u32 num_active_queues = adapter->num_active_queues;

	return num_active_queues * 2 > max_qp_num ? max_qp_num / 2 :
						    num_active_queues;
}

/**
 * iavf_qp_clean_rings - Cleans all the rings of a given index
 * @adapter: adapter that contains rings of interest
 * @q_idx: ring index in array
 */
static void
iavf_qp_clean_rings(struct iavf_adapter *adapter, u16 q_idx)
{
	iavf_clean_tx_ring(&adapter->tx_rings[q_idx]);
	if (iavf_adapter_xdp_active(adapter)) {
		synchronize_rcu();
		iavf_clean_tx_ring(&adapter->xdp_rings[q_idx]);
	}
	iavf_clean_rx_ring(&adapter->rx_rings[q_idx]);
}

/**
 * iavf_qvec_toggle_napi - Enables/disables NAPI for a given q_vector
 * @adapter: adapter that has netdev
 * @q_vector: q_vector that has NAPI context
 * @enable: true for enable, false for disable
 */
static void
iavf_qvec_toggle_napi(struct iavf_adapter *adapter,
		      struct iavf_q_vector *q_vector, bool enable)
{
	if (!adapter->vsi.netdev || !q_vector)
		return;

	if (enable)
		napi_enable(&q_vector->napi);
	else
		napi_disable(&q_vector->napi);
}

/**
 * iavf_trigger_sw_intr - trigger a software interrupt
 * @adapter: adapter of interest
 * @q_vector: interrupt vector to trigger the software interrupt for
 */
static void
iavf_trigger_sw_intr(struct iavf_adapter *adapter,
		     struct iavf_q_vector *q_vector)
{
        struct iavf_hw *hw = &adapter->hw;

        wr32(hw, IAVF_VFINT_DYN_CTLN1(q_vector->reg_idx),
             (IAVF_VFINT_DYN_CTLN1_INTENA_MASK |
              IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK |
              IAVF_VFINT_DYN_CTLN1_SWINT_TRIG_MASK |
              IAVF_VFINT_DYN_CTLN1_SW_ITR_INDX_ENA_MASK));

        iavf_flush(hw);
}

/**
 * iavf_qvec_dis_irq - Mask off queue interrupt generation on given ring
 * @adapter: the adapter that contains queue vector being un-configured
 * @q_vector: queue vector
 */
static void
iavf_qvec_dis_irq(struct iavf_adapter *adapter, struct iavf_q_vector *q_vector)
{
	int base = adapter->vsi.base_vector;
	struct iavf_hw *hw = &adapter->hw;
	u16 reg = q_vector->reg_idx;

	wr32(hw, IAVF_VFINT_DYN_CTLN1(reg), 0);
	synchronize_irq(adapter->msix_entries[reg + base].vector);
	iavf_flush(hw);
}

/**
 * iavf_qvec_ena_irq - Enable IRQ for given queue vector
 * @adapter: the adapter that contains queue vector
 * @q_vector: queue vector
 */
static void
iavf_qvec_ena_irq(struct iavf_adapter *adapter, struct iavf_q_vector *q_vector)
{
	struct iavf_hw *hw = &adapter->hw;

	if (adapter)
		if (adapter->state == __IAVF_DOWN)
			return;

	wr32(hw, IAVF_VFINT_DYN_CTLN1(q_vector->reg_idx),
	     IAVF_VFINT_DYN_CTLN1_INTENA_MASK |
	     IAVF_VFINT_DYN_CTLN1_ITR_INDX_MASK);

	iavf_flush(hw);
}

/**
 * iavf_qp_dis - Disables a queue pair
 * @adapter: adapter of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int iavf_qp_dis(struct iavf_adapter *adapter, u16 q_idx)
{
	struct iavf_vsi *vsi = &adapter->vsi;
	struct iavf_ring *rx_ring, *xdp_ring;
	struct iavf_q_vector *q_vector;
	u32 rx_queues, tx_queues;
	int err;

	if (q_idx >= adapter->num_active_queues)
		return -EINVAL;

	rx_ring = &adapter->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	rx_queues = BIT(q_idx);
	tx_queues = rx_queues;

	netif_tx_stop_queue(netdev_get_tx_queue(vsi->netdev, q_idx));

	iavf_qvec_toggle_napi(adapter, q_vector, false);
	iavf_qvec_dis_irq(adapter, q_vector);

	xdp_ring = &adapter->xdp_rings[q_idx];

	tx_queues |= BIT(xdp_ring->queue_index);

	err = iavf_disable_selected_queues(adapter, rx_queues, tx_queues, true);
	if (err)
		goto dis_exit;

	iavf_qp_clean_rings(adapter, q_idx);
	if (!(rx_ring->flags & IAVF_TXRX_FLAGS_XSK)) {
		struct device *dev = rx_ring->pool->p.dev;

		libie_rx_page_pool_destroy(rx_ring->pool, &rx_ring->rq_stats);
		rx_ring->dev = dev;
	}
dis_exit:
	return err;
}

/**
 * iavf_qp_ena - Enables a queue pair
 * @adapter: adapter of interest
 * @q_idx: ring index in array
 *
 * Returns 0 on success, negative on failure.
 */
static int iavf_qp_ena(struct iavf_adapter *adapter, u16 q_idx)
{
	struct iavf_vsi *vsi = &adapter->vsi;
	struct iavf_ring *rx_ring, *xdp_ring;
	struct iavf_q_vector *q_vector;
	u32 rx_queues, tx_queues;
	int ret, err = 0;

	if (q_idx >= adapter->num_active_queues)
		return -EINVAL;

	xdp_ring = &adapter->xdp_rings[q_idx];
	rx_ring = &adapter->rx_rings[q_idx];
	q_vector = rx_ring->q_vector;

	rx_queues = BIT(q_idx);
	tx_queues = rx_queues;
	tx_queues |= BIT(xdp_ring->queue_index);

	iavf_xsk_setup_xdp_ring(xdp_ring);
	iavf_xsk_setup_rx_ring(rx_ring);

	if (!(rx_ring->flags & IAVF_TXRX_FLAGS_XSK)) {
		rx_ring->pool = libie_rx_page_pool_create(rx_ring->netdev,
							  rx_ring->count,
							  true);
		if (IS_ERR(rx_ring->pool)) {
			err = PTR_ERR(rx_ring->pool);
			goto ena_exit;
		}
	}

	iavf_configure_rx_ring(adapter, rx_ring);

	/* Use 'tx_queues' mask as a queue pair mask to configure
	 * also an extra XDP Tx queue.
	 */
	err = iavf_configure_selected_queues(adapter, tx_queues, true);
	if (err)
		goto ena_exit;

	err = iavf_enable_selected_queues(adapter, rx_queues, tx_queues, true);
	if (err)
		goto ena_exit;

	ret = iavf_poll_for_link_status(adapter, IAVF_XDP_LINK_TIMEOUT_MS);
	if (ret < 0) {
		err = ret;
		dev_err(&adapter->pdev->dev,
			"cannot bring the link up, error: %d\n", err);
		goto ena_exit;
	} else if (!ret) {
		err = -EBUSY;
		dev_err(&adapter->pdev->dev,
			"pf returned link down status, error: %d\n", err);
		goto ena_exit;
	}

	iavf_qvec_toggle_napi(adapter, q_vector, true);
	iavf_qvec_ena_irq(adapter, q_vector);

	netif_tx_start_queue(netdev_get_tx_queue(vsi->netdev, q_idx));
ena_exit:
	return err;
}

/**
 * iavf_xsk_pool_disable - disable a buffer pool region
 * @adapter: Current adapter
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int iavf_xsk_pool_disable(struct iavf_adapter *adapter, u16 qid)
{
	struct xsk_buff_pool *pool = xsk_get_pool_from_qid(adapter->vsi.netdev,
							   qid);
	if (!pool)
		return -EINVAL;

	clear_bit(qid, adapter->af_xdp_zc_qps);
	xsk_pool_dma_unmap(pool, LIBIE_RX_DMA_ATTR);

	return 0;
}

/**
 * iavf_xsk_pool_enable - enable a buffer pool region
 * @adapter: Current adapter
 * @pool: pointer to a requested buffer pool region
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
static int
iavf_xsk_pool_enable(struct iavf_adapter *adapter, struct xsk_buff_pool *pool,
		     u16 qid)
{
	struct iavf_vsi *vsi = &adapter->vsi;
	int err;

	if (qid >= vsi->netdev->real_num_rx_queues ||
	    qid >= vsi->netdev->real_num_tx_queues)
		return -EINVAL;

	err = xsk_pool_dma_map(pool, &adapter->pdev->dev, LIBIE_RX_DMA_ATTR);
	if (err)
		return err;

	set_bit(qid, adapter->af_xdp_zc_qps);

	return 0;
}

/**
 * iavf_xsk_pool_setup - enable/disable a buffer pool region depending
 * 			 on its state
 * @adapter: Current adapter
 * @pool: buffer pool to enable/associate to a ring, NULL to disable
 * @qid: queue ID
 *
 * Returns 0 on success, negative on failure
 */
int iavf_xsk_pool_setup(struct iavf_adapter *adapter,
			struct xsk_buff_pool *pool, u32 qid)
{
	bool if_running, pool_present = !!pool;
	struct iavf_vsi *vsi = &adapter->vsi;
	int ret = 0, pool_failure = 0;

	if (qid >= iavf_max_xdp_queues_count(adapter)) {
		netdev_err(vsi->netdev, "Wrong queue index for XDP.\n");
		pool_failure = -EINVAL;
		goto failure;
	}

	if_running = netif_running(vsi->netdev) &&
		     iavf_adapter_xdp_active(adapter);

	if (if_running) {
		if (iavf_lock_timeout(&adapter->crit_lock,
				      IAVF_CRIT_LOCK_WAIT_TIMEOUT_MS))
			return -EBUSY;

		ret = iavf_process_pending_pf_msg(adapter,
						  IAVF_VC_MSG_TIMEOUT_MS);
		if (ret)
			goto xsk_pool_if_up;

		ret = iavf_qp_dis(adapter, qid);
		if (ret) {
			netdev_err(vsi->netdev, "iavf_qp_dis error = %d\n", ret);
			goto xsk_pool_if_up;
		}
	}

	pool_failure = pool_present ? iavf_xsk_pool_enable(adapter, pool, qid) :
				      iavf_xsk_pool_disable(adapter, qid);

xsk_pool_if_up:
	if (if_running) {
		ret = iavf_qp_ena(adapter, qid);
		mutex_unlock(&adapter->crit_lock);
		if (!ret && pool_present)
			napi_schedule(&adapter->rx_rings[qid].q_vector->napi);
		else if (ret)
			netdev_err(vsi->netdev, "iavf_qp_ena error = %d\n", ret);
	}

failure:
	if (pool_failure) {
		netdev_err(vsi->netdev, "Could not %sable buffer pool, error = %d\n",
			   pool_present ? "en" : "dis", pool_failure);
		return pool_failure;
	}

	return ret;
}

/**
 * iavf_clean_xdp_tx_buf - Free and unmap XDP Tx buffer
 * @xdp_ring: XDP Tx ring
 * @tx_buf: Tx buffer to clean
 */
static void
iavf_clean_xdp_tx_buf(struct iavf_ring *xdp_ring, struct iavf_tx_buffer *tx_buf)
{
	switch (tx_buf->xdp_type) {
	case IAVF_XDP_BUFFER_FRAME:
		dma_unmap_single(xdp_ring->dev, dma_unmap_addr(tx_buf, dma),
				 dma_unmap_len(tx_buf, len), DMA_TO_DEVICE);
		dma_unmap_len_set(tx_buf, len, 0);
		xdp_return_frame(tx_buf->xdpf);
		tx_buf->xdpf = NULL;
		break;
	case IAVF_XDP_BUFFER_TX:
		xsk_buff_free(tx_buf->xdp);
		break;
	}

	xdp_ring->xdp_tx_active--;
	tx_buf->xdp_type = IAVF_XDP_BUFFER_NONE;
}

/**
 * iavf_clean_xdp_irq_zc - produce AF_XDP descriptors to CQ
 * @xdp_ring: XDP Tx ring
 */
static void iavf_clean_xdp_irq_zc(struct iavf_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean;
	struct iavf_tx_buffer *tx_buf;
	struct iavf_tx_desc *tx_desc;
	u16 cnt = xdp_ring->count;
	u16 done_frames = 0;
	u16 xsk_frames = 0;
	u16 last_rs;
	int i;

	last_rs = xdp_ring->next_to_use ? xdp_ring->next_to_use - 1 : cnt - 1;
	tx_desc = IAVF_TX_DESC(xdp_ring, last_rs);
	if ((tx_desc->cmd_type_offset_bsz &
	    cpu_to_le64(IAVF_TX_DESC_DTYPE_DESC_DONE))) {
		if (last_rs >= ntc)
			done_frames = last_rs - ntc + 1;
		else
			done_frames = last_rs + cnt - ntc + 1;
	}

	if (!done_frames)
		return;

	if (likely(!xdp_ring->xdp_tx_active)) {
		xsk_frames = done_frames;
		goto skip;
	}

	ntc = xdp_ring->next_to_clean;
	for (i = 0; i < done_frames; i++) {
		tx_buf = &xdp_ring->tx_bi[ntc];

		if (tx_buf->xdp_type)
			iavf_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		ntc++;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}
skip:
	tx_desc->cmd_type_offset_bsz = 0;
	xdp_ring->next_to_clean += done_frames;
	if (xdp_ring->next_to_clean >= cnt)
		xdp_ring->next_to_clean -= cnt;
	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}

/**
 * iavf_xmit_pkt - produce a single HW Tx descriptor out of AF_XDP descriptor
 * @xdp_ring: XDP ring to produce the HW Tx descriptor on
 * @desc: AF_XDP descriptor to pull the DMA address and length from
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void iavf_xmit_pkt(struct iavf_ring *xdp_ring, struct xdp_desc *desc,
			  unsigned int *total_bytes)
{
	struct iavf_tx_desc *tx_desc;
	dma_addr_t dma;

	dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, desc->addr);
	xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma, desc->len);

	tx_desc = IAVF_TX_DESC(xdp_ring, xdp_ring->next_to_use++);
	tx_desc->buffer_addr = cpu_to_le64(dma);
	tx_desc->cmd_type_offset_bsz = iavf_build_ctob(IAVF_TX_DESC_CMD_EOP,
						       0, desc->len, 0);

	*total_bytes += desc->len;
}

/**
 * iavf_xmit_pkt_batch - produce a batch of HW Tx descriptors out
 * 			 of AF_XDP descriptors
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 * @descs: AF_XDP descriptors to pull the DMA addresses and lengths from
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void iavf_xmit_pkt_batch(struct iavf_ring *xdp_ring,
				struct xdp_desc *descs,
				unsigned int *total_bytes)
{
	u16 ntu = xdp_ring->next_to_use;
	struct iavf_tx_desc *tx_desc;
	u32 i;

	loop_unrolled_for(i = 0; i < PKTS_PER_BATCH; i++) {
		dma_addr_t dma;

		dma = xsk_buff_raw_get_dma(xdp_ring->xsk_pool, descs[i].addr);
		xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma,
						 descs[i].len);

		tx_desc = IAVF_TX_DESC(xdp_ring, ntu++);
		tx_desc->buffer_addr = cpu_to_le64(dma);
		tx_desc->cmd_type_offset_bsz =
			iavf_build_ctob(IAVF_TX_DESC_CMD_EOP, 0,
					descs[i].len, 0);

		*total_bytes += descs[i].len;
	}

	xdp_ring->next_to_use = ntu;
}

/**
 * iavf_fill_tx_hw_ring - produce the number of Tx descriptors onto ring
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 * @descs: AF_XDP descriptors to pull the DMA addresses and lengths from
 * @nb_pkts: count of packets to be send
 * @total_bytes: bytes accumulator that will be used for stats update
 */
static void iavf_fill_tx_hw_ring(struct iavf_ring *xdp_ring,
				 struct xdp_desc *descs, u32 nb_pkts,
				 unsigned int *total_bytes)
{
	u32 batched, leftover, i;

	batched = ALIGN_DOWN(nb_pkts, PKTS_PER_BATCH);
	leftover = nb_pkts & (PKTS_PER_BATCH - 1);

	for (i = 0; i < batched; i += PKTS_PER_BATCH)
		iavf_xmit_pkt_batch(xdp_ring, &descs[i], total_bytes);
	for (; i < batched + leftover; i++)
		iavf_xmit_pkt(xdp_ring, &descs[i], total_bytes);
}

/**
 * iavf_xmit_zc - take entries from XSK Tx ring and place them onto HW Tx ring
 * @xdp_ring: XDP ring to produce the HW Tx descriptors on
 *
 * Returns true if there is no more work that needs to be done, false otherwise
 */
bool iavf_xmit_zc(struct iavf_ring *xdp_ring)
{
	struct xdp_desc *descs = xdp_ring->xsk_pool->tx_descs;
	struct libie_sq_onstack_stats stats = { };
	u32 nb_processed = 0;
	bool ret = true;
	int budget;

	if (static_branch_unlikely(&iavf_xdp_locking_key))
		spin_lock(&xdp_ring->tx_lock);

	iavf_clean_xdp_irq_zc(xdp_ring);

	budget = IAVF_DESC_UNUSED(xdp_ring);
	budget = min_t(u16, budget, IAVF_RING_QUARTER(xdp_ring));

	stats.packets = xsk_tx_peek_release_desc_batch(xdp_ring->xsk_pool,
						       budget);
	if (!stats.packets)
		goto unlock;

	if (xdp_ring->next_to_use + stats.packets >= xdp_ring->count) {
		nb_processed = xdp_ring->count - xdp_ring->next_to_use;
		iavf_fill_tx_hw_ring(xdp_ring, descs, nb_processed,
				     &stats.bytes);
		xdp_ring->next_to_use = 0;
	}

	iavf_fill_tx_hw_ring(xdp_ring, &descs[nb_processed],
			     stats.packets - nb_processed, &stats.bytes);

	iavf_set_rs_bit(xdp_ring);
	iavf_xdp_ring_update_tail(xdp_ring);
	iavf_update_tx_ring_stats(xdp_ring, &stats);

	if (xsk_uses_need_wakeup(xdp_ring->xsk_pool))
		xsk_set_tx_need_wakeup(xdp_ring->xsk_pool);

	ret = stats.packets < budget;
unlock:
	if (static_branch_unlikely(&iavf_xdp_locking_key))
		spin_unlock(&xdp_ring->tx_lock);

	return ret;
}

/**
 * iavf_xsk_wakeup - Implements ndo_xsk_wakeup
 * @netdev: net_device
 * @queue_id: queue to wake up
 * @flags: ignored in our case, since we have Rx and Tx in the same NAPI
 *
 * Returns negative on error, zero otherwise.
 */
int iavf_xsk_wakeup(struct net_device *netdev, u32 queue_id, u32 flags)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	struct iavf_q_vector *q_vector;
	struct iavf_ring *ring;

	if (adapter->state == __IAVF_DOWN ||
	    adapter->state == __IAVF_RESETTING)
		return -ENETDOWN;

	if (!iavf_adapter_xdp_active(adapter))
		return -EINVAL;

	if (queue_id >= adapter->num_active_queues)
		return -EINVAL;

	ring = &adapter->rx_rings[queue_id];

	if (!(ring->xdp_ring->flags & IAVF_TXRX_FLAGS_XSK))
		return -EINVAL;

	q_vector = ring->q_vector;
	if (!napi_if_scheduled_mark_missed(&q_vector->napi))
		iavf_trigger_sw_intr(adapter, q_vector);

	return 0;
}

static u32 iavf_get_xdp_tx_qid(struct iavf_ring *ring)
{
	struct iavf_adapter *adapter = ring->vsi->back;

	return ring->queue_index - adapter->num_active_queues;
}

static struct xsk_buff_pool *iavf_tx_xsk_pool(struct iavf_ring *ring)
{
	struct iavf_adapter *adapter = ring->vsi->back;
	u32 qid;

	if (!iavf_adapter_xdp_active(adapter) ||
	    !(ring->flags & IAVF_TXRX_FLAGS_XDP))
		return NULL;

	qid = iavf_get_xdp_tx_qid(ring);
	if (!test_bit(qid, adapter->af_xdp_zc_qps))
		return NULL;

	return xsk_get_pool_from_qid(adapter->netdev, qid);
}

void iavf_xsk_setup_xdp_ring(struct iavf_ring *xdp_ring)
{
	struct xsk_buff_pool *pool;

	pool = iavf_tx_xsk_pool(xdp_ring);
	if (pool) {
		xdp_ring->xsk_pool = pool;
		xdp_ring->flags |= IAVF_TXRX_FLAGS_XSK;
	} else {
		xdp_ring->dev = &xdp_ring->vsi->back->pdev->dev;
		xdp_ring->flags &= ~IAVF_TXRX_FLAGS_XSK;
	}
}

/**
 * iavf_xsk_clean_xdp_ring - Clean the XDP Tx ring and its buffer pool queues
 * @xdp_ring: XDP_Tx ring
 */
void iavf_xsk_clean_xdp_ring(struct iavf_ring *xdp_ring)
{
	u16 ntc = xdp_ring->next_to_clean, ntu = xdp_ring->next_to_use;
	u32 xsk_frames = 0;

	while (ntc != ntu) {
		struct iavf_tx_buffer *tx_buf = &xdp_ring->tx_bi[ntc];

		if (tx_buf->xdp_type)
			iavf_clean_xdp_tx_buf(xdp_ring, tx_buf);
		else
			xsk_frames++;

		tx_buf->page = NULL;

		ntc++;
		if (ntc >= xdp_ring->count)
			ntc = 0;
	}

	if (xsk_frames)
		xsk_tx_completed(xdp_ring->xsk_pool, xsk_frames);
}

/**
 * iavf_init_rx_descs_zc - pick buffers from XSK buffer pool and use it
 * @pool: XSK Buffer pool to pull the buffers from
 * @xdp: SW ring of xdp_buff that will hold the buffers
 * @rx_desc: Pointer to Rx descriptors that will be filled
 * @count: The number of buffers to allocate
 *
 * This function allocates a number of Rx buffers from the fill ring
 * or the internal recycle mechanism and places them on the Rx ring.
 *
 * Note that ring wrap should be handled by caller of this function.
 *
 * Returns the amount of allocated Rx descriptors
 */
static u16 iavf_init_rx_descs_zc(struct xsk_buff_pool *pool,
				 struct xdp_buff **xdp,
				 union iavf_rx_desc *rx_desc, u16 count)
{
	dma_addr_t dma;
	u16 num_buffs;
	u16 i;

	num_buffs = xsk_buff_alloc_batch(pool, xdp, count);
	for (i = 0; i < num_buffs; i++) {
		dma = xsk_buff_xdp_get_dma(*xdp);
		rx_desc->read.pkt_addr = cpu_to_le64(dma);
		rx_desc->wb.qword1.status_error_len = 0;

		rx_desc++;
		xdp++;
	}

	return num_buffs;
}

static struct xdp_buff **iavf_get_xdp_buff(struct iavf_ring *ring, u32 idx)
{
	return &ring->xdp_buff[idx];
}

/**
 * __iavf_alloc_rx_buffers_zc - allocate a number of Rx buffers
 * @rx_ring: Rx ring
 * @count: The number of buffers to allocate
 *
 * Place the @count of descriptors onto Rx ring. Handle the ring wrap
 * for case where space from next_to_use up to the end of ring is less
 * than @count. Finally do a tail bump.
 *
 * Returns true if all allocations were successful, false if any fail.
 */
static bool __iavf_alloc_rx_buffers_zc(struct iavf_ring *rx_ring, u16 count)
{
	u32 nb_buffs_extra = 0, nb_buffs = 0;
	u16 ntu = rx_ring->next_to_use;
	union iavf_rx_desc *rx_desc;
	u16 total_count = count;
	struct xdp_buff **xdp;

	rx_desc = IAVF_RX_DESC(rx_ring, ntu);
	xdp = iavf_get_xdp_buff(rx_ring, ntu);

	if (ntu + count >= rx_ring->count) {
		nb_buffs_extra = iavf_init_rx_descs_zc(rx_ring->xsk_pool, xdp,
						       rx_desc,
						       rx_ring->count - ntu);
		if (nb_buffs_extra != rx_ring->count - ntu) {
			ntu += nb_buffs_extra;
			goto exit;
		}
		rx_desc = IAVF_RX_DESC(rx_ring, 0);
		xdp = iavf_get_xdp_buff(rx_ring, 0);
		ntu = 0;
		count -= nb_buffs_extra;
		iavf_release_rx_desc(rx_ring, 0);

		if (!count)
			goto exit;
	}

	nb_buffs = iavf_init_rx_descs_zc(rx_ring->xsk_pool, xdp, rx_desc, count);

	ntu += nb_buffs;
	if (ntu == rx_ring->count)
		ntu = 0;

exit:
	if (rx_ring->next_to_use != ntu)
		iavf_release_rx_desc(rx_ring, ntu);

	return total_count == (nb_buffs_extra + nb_buffs);
}

/**
 * iavf_alloc_rx_buffers_zc - allocate a number of Rx buffers
 * @rx_ring: Rx ring
 * @count: The number of buffers to allocate
 *
 * Wrapper for internal allocation routine; figure out how many tail
 * bumps should take place based on the given threshold
 *
 * Returns true if all calls to internal alloc routine succeeded
 */
static bool iavf_alloc_rx_buffers_zc(struct iavf_ring *rx_ring, u16 count)
{
	u16 rx_thresh = IAVF_RING_QUARTER(rx_ring);
	u16 leftover, i, tail_bumps;

	tail_bumps = count / rx_thresh;
	leftover = count - (tail_bumps * rx_thresh);

	for (i = 0; i < tail_bumps; i++)
		if (!__iavf_alloc_rx_buffers_zc(rx_ring, rx_thresh))
			return false;
	return __iavf_alloc_rx_buffers_zc(rx_ring, leftover);
}

/**
 * iavf_check_alloc_rx_buffers_zc - allocate a number of Rx buffers with logs
 * @adapter: board private structure
 * @rx_ring: Rx ring
 *
 * Wrapper for internal allocation routine; Prints out logs, if allocation
 * did not go as expected
 */
void iavf_check_alloc_rx_buffers_zc(struct iavf_adapter *adapter,
				    struct iavf_ring *rx_ring)
{
	u32 count = IAVF_DESC_UNUSED(rx_ring);

	if (!xsk_buff_can_alloc(rx_ring->xsk_pool, count)) {
		netdev_warn(adapter->netdev,
			    "XSK buffer pool does not provide enough addresses to fill %d buffers on Rx ring %d\n",
			    count, rx_ring->queue_index);
		netdev_warn(adapter->netdev,
			    "Change Rx ring/fill queue size to avoid performance issues\n");
	}

	if (!iavf_alloc_rx_buffers_zc(rx_ring, count))
		netdev_warn(adapter->netdev,
			    "Failed to allocate some buffers on XSK buffer pool enabled Rx ring %d\n",
			    rx_ring->queue_index);
}

/**
 * iavf_rx_xsk_pool - Get a valid xsk pool for RX ring
 * @ring: Rx ring being configured
 *
 * Do not return a xsk pool, if socket is TX-only
 **/
static struct xsk_buff_pool *iavf_rx_xsk_pool(struct iavf_ring *ring)
{
	struct iavf_adapter *adapter = ring->vsi->back;
	u16 qid = ring->queue_index;
	struct xsk_buff_pool *pool;

	if (!iavf_adapter_xdp_active(adapter) ||
	    !test_bit(qid, adapter->af_xdp_zc_qps))
		return NULL;

	pool = xsk_get_pool_from_qid(adapter->netdev, qid);
	if (!pool || !xsk_buff_can_alloc(pool, 1))
		return NULL;

	return pool;
}

void iavf_xsk_setup_rx_ring(struct iavf_ring *rx_ring)
{
	struct xsk_buff_pool *pool;

	pool = iavf_rx_xsk_pool(rx_ring);
	if (pool) {
		rx_ring->xsk_pool = pool;
		rx_ring->flags |= IAVF_TXRX_FLAGS_XSK;
	} else {
		rx_ring->dev = &rx_ring->vsi->back->pdev->dev;
		rx_ring->flags &= ~IAVF_TXRX_FLAGS_XSK;
	}
}

/**
 * iavf_xsk_clean_rx_ring - clean buffer pool queues connected to a given Rx ring
 * @rx_ring: ring to be cleaned
 */
void iavf_xsk_clean_rx_ring(struct iavf_ring *rx_ring)
{
	u16 ntc = rx_ring->next_to_clean;
	u16 ntu = rx_ring->next_to_use;

	while (ntc != ntu) {
		struct xdp_buff *xdp = *iavf_get_xdp_buff(rx_ring, ntc);

		xsk_buff_free(xdp);
		ntc++;
		if (ntc >= rx_ring->count)
			ntc = 0;
	}
}

/**
 * iavf_xmit_xdp_tx_zc - AF_XDP ZC handler for XDP_TX
 * @xdp: XDP buffer to xmit
 * @xdp_ring: XDP ring to produce descriptor onto
 *
 * Returns 0 for successfully produced desc,
 * -EBUSY if there was not enough space on XDP ring.
 */
static int iavf_xmit_xdp_tx_zc(struct xdp_buff *xdp,
			       struct iavf_ring *xdp_ring)
{
	u32 size = xdp->data_end - xdp->data;
	u32 ntu = xdp_ring->next_to_use;
	struct iavf_tx_buffer *tx_buf;
	struct iavf_tx_desc *tx_desc;
	dma_addr_t dma;

	if (IAVF_DESC_UNUSED(xdp_ring) < IAVF_RING_QUARTER(xdp_ring))
		iavf_clean_xdp_irq_zc(xdp_ring);

	if (unlikely(!IAVF_DESC_UNUSED(xdp_ring))) {
		libie_stats_inc_one(&xdp_ring->sq_stats, busy);
		return -EBUSY;
	}

	dma = xsk_buff_xdp_get_dma(xdp);
	xsk_buff_raw_dma_sync_for_device(xdp_ring->xsk_pool, dma, size);

	tx_buf = &xdp_ring->tx_bi[ntu];
	tx_buf->bytecount = size;
	tx_buf->gso_segs = 1;
	tx_buf->xdp_type = IAVF_XDP_BUFFER_TX;
	tx_buf->xdp = xdp;

	tx_desc = IAVF_TX_DESC(xdp_ring, ntu);
	tx_desc->buffer_addr = cpu_to_le64(dma);
	tx_desc->cmd_type_offset_bsz = iavf_build_ctob(IAVF_TX_DESC_CMD_EOP,
						       0, size, 0);

	xdp_ring->xdp_tx_active++;

	if (++ntu == xdp_ring->count)
		ntu = 0;
	xdp_ring->next_to_use = ntu;

	return 0;
}

static int iavf_xmit_xdp_tx_zc_locked(struct xdp_buff *xdp,
				      struct iavf_ring *xdp_ring)
{
	int ret;

	if (static_branch_unlikely(&iavf_xdp_locking_key))
		spin_lock(&xdp_ring->tx_lock);
	ret = iavf_xmit_xdp_tx_zc(xdp, xdp_ring);
	if (static_branch_unlikely(&iavf_xdp_locking_key))
		spin_unlock(&xdp_ring->tx_lock);

	return ret;
}

/**
 * iavf_run_xdp_zc - Run XDP program and perform resulting action for ZC
 * @rx_ring: RX descriptor ring to transact packets on
 * @xdp: a prepared XDP buffer
 * @xdp_prog: an XDP program assigned to the interface
 * @xdp_ring: XDP TX queue assigned to the RX ring
 * @rxq_xdp_act: Logical OR of flags of XDP actions that require finalization
 *
 * Returns resulting XDP action.
 */
static unsigned int
iavf_run_xdp_zc(struct iavf_ring *rx_ring, struct xdp_buff *xdp,
		struct bpf_prog *xdp_prog, struct iavf_ring *xdp_ring,
		u32 *rxq_xdp_act)
{
	unsigned int xdp_act;
	int err;

	xdp_act = bpf_prog_run_xdp(xdp_prog, xdp);

	if (likely(xdp_act == XDP_REDIRECT)) {
		err = xdp_do_redirect(rx_ring->netdev, xdp, xdp_prog);
		if (likely(!err)) {
			*rxq_xdp_act |= IAVF_RXQ_XDP_ACT_FINALIZE_REDIR;
			return XDP_REDIRECT;
		}

		if (xsk_uses_need_wakeup(rx_ring->xsk_pool) && err == -ENOBUFS)
			*rxq_xdp_act |= IAVF_RXQ_XDP_ACT_STOP_NOW;

		goto xdp_err;
	}

	switch (xdp_act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		err = iavf_xmit_xdp_tx_zc_locked(xdp, xdp_ring);
		if (unlikely(err))
			goto xdp_err;

		*rxq_xdp_act |= IAVF_RXQ_XDP_ACT_FINALIZE_TX;
		break;
	default:
		bpf_warn_invalid_xdp_action(rx_ring->netdev, xdp_prog, xdp_act);

		fallthrough;
	case XDP_ABORTED:
xdp_err:
		trace_xdp_exception(rx_ring->netdev, xdp_prog, xdp_act);

		fallthrough;
	case XDP_DROP:
		xsk_buff_free(xdp);

		return XDP_DROP;
	}

	return xdp_act;
}

/**
 * iavf_construct_skb_zc - Create an sk_buff from zero-copy buffer
 * @rx_ring: Rx ring
 * @xdp: Pointer to XDP buffer
 *
 * This function allocates a new skb from a zero-copy Rx buffer.
 *
 * Returns the skb on success, NULL on failure.
 */
static struct sk_buff *
iavf_construct_skb_zc(struct iavf_ring *rx_ring, struct xdp_buff *xdp)
{
	unsigned int totalsize = xdp->data_end - xdp->data_meta;
	unsigned int metasize = xdp->data - xdp->data_meta;
	struct sk_buff *skb;

	net_prefetch(xdp->data_meta);

	skb = __napi_alloc_skb(&rx_ring->q_vector->napi, totalsize,
			       GFP_ATOMIC | __GFP_NOWARN);
	if (unlikely(!skb))
		return NULL;

	memcpy(__skb_put(skb, totalsize), xdp->data_meta,
	       ALIGN(totalsize, sizeof(long)));

	if (metasize) {
		skb_metadata_set(skb, metasize);
		__skb_pull(skb, metasize);
	}

	xsk_buff_free(xdp);

	return skb;
}

/**
 * iavf_clean_rx_irq_zc - consumes packets from the hardware ring
 * @rx_ring: AF_XDP Rx ring
 * @budget: NAPI budget
 *
 * Returns number of processed packets on success, remaining budget on failure.
 */
int iavf_clean_rx_irq_zc(struct iavf_ring *rx_ring, int budget)
{
	struct libie_rq_onstack_stats stats = { };
	u32 ntc = rx_ring->next_to_clean;
	u32 ring_size = rx_ring->count;
	struct iavf_ring *xdp_ring;
	struct bpf_prog *xdp_prog;
	u32 cleaned_count = 0;
	bool failure = false;
	u32 rxq_xdp_act = 0;
	u32 to_refill;

	xdp_prog = rcu_dereference(rx_ring->xdp_prog);
	xdp_ring = rx_ring->xdp_ring;

	while (likely(cleaned_count < budget)) {
		union iavf_rx_desc *rx_desc;
		struct xdp_buff *xdp;
		unsigned int xdp_act;
		struct sk_buff *skb;
		unsigned int size;
		u64 qword;

		rx_desc = IAVF_RX_DESC(rx_ring, ntc);

		/* status_error_len will always be zero for unused descriptors
		 * because it's cleared in cleanup, and overlaps with hdr_addr
		 * which is always zero because packet split isn't used, if the
		 * hardware wrote DD then the length will be non-zero
		 */
		qword = le64_to_cpu(rx_desc->wb.qword1.status_error_len);
		if (!iavf_test_staterr(qword, IAVF_RX_DESC_STATUS_DD_SHIFT))
			break;

		/* This memory barrier is needed to keep us from reading
		 * any other fields out of the rx_desc until we have
		 * verified the descriptor has been written back.
		 */
		dma_rmb();

		size = (qword & IAVF_RXD_QW1_LENGTH_PBUF_MASK) >>
		       IAVF_RXD_QW1_LENGTH_PBUF_SHIFT;

		xdp = *iavf_get_xdp_buff(rx_ring, ntc);
		iavf_trace(clean_rx_irq_zc, rx_ring, rx_desc, NULL);

		if (unlikely(!size)) {
			xsk_buff_free(xdp);
			goto next;
		}

		xsk_buff_set_size(xdp, size);
		xsk_buff_dma_sync_for_cpu(xdp, rx_ring->xsk_pool);

		xdp_act = iavf_run_xdp_zc(rx_ring, xdp, xdp_prog, xdp_ring,
					  &rxq_xdp_act);
		if (xdp_act == XDP_PASS)
			goto construct_skb;

		if (unlikely(rxq_xdp_act & IAVF_RXQ_XDP_ACT_STOP_NOW)) {
			failure = true;
			break;
		}

		stats.bytes += size;
		stats.packets++;

next:
		cleaned_count++;
		if (unlikely(++ntc == ring_size))
			ntc = 0;

		continue;

construct_skb:
		skb = iavf_construct_skb_zc(rx_ring, xdp);
		if (!skb) {
			libie_stats_inc_one(&rx_ring->rq_stats,
					    build_skb_fail);
			break;
		}

		cleaned_count++;
		if (unlikely(++ntc == ring_size))
			ntc = 0;

		prefetch(rx_desc);

		/* probably a little skewed due to removing CRC */
		stats.bytes += skb->len;

		/* populate checksum, VLAN, and protocol */
		iavf_process_skb_fields(rx_ring, rx_desc, skb, qword);

		iavf_trace(clean_rx_irq_zc_rx, rx_ring, rx_desc, skb);
		skb->protocol = eth_type_trans(skb, rx_ring->netdev);
		napi_gro_receive(&rx_ring->q_vector->napi, skb);

		stats.packets++;
	}

	rx_ring->next_to_clean = ntc;

	iavf_finalize_xdp_rx(xdp_ring, rxq_xdp_act, 0);

	to_refill = IAVF_DESC_UNUSED(rx_ring);
	if (to_refill > IAVF_RING_QUARTER(rx_ring))
		failure |= !iavf_alloc_rx_buffers_zc(rx_ring, to_refill);

	iavf_update_rx_ring_stats(rx_ring, &stats);

	if (xsk_uses_need_wakeup(rx_ring->xsk_pool)) {
		if (failure || rx_ring->next_to_clean == rx_ring->next_to_use)
			xsk_set_rx_need_wakeup(rx_ring->xsk_pool);
		else
			xsk_clear_rx_need_wakeup(rx_ring->xsk_pool);

		return cleaned_count;
	}

	return unlikely(failure) ? budget : cleaned_count;
}
