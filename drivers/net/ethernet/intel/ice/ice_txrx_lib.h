/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019, Intel Corporation. */

#ifndef _ICE_TXRX_LIB_H_
#define _ICE_TXRX_LIB_H_
#include "ice.h"

/**
 * ice_test_staterr - tests bits in Rx descriptor status and error fields
 * @rx_desc: pointer to receive descriptor (in le64 format)
 * @stat_err_bits: value to mask
 *
 * This function does some fast chicanery in order to return the
 * value of the mask which is really only used for boolean tests.
 * The status_error_len doesn't need to be shifted because it begins
 * at offset zero.
 */
static inline bool
ice_test_staterr(union ice_32b_rx_flex_desc *rx_desc, const u16 stat_err_bits)
{
	return !!(rx_desc->wb.status_error0 & cpu_to_le16(stat_err_bits));
}

static inline __le64
ice_build_ctob(u64 td_cmd, u64 td_offset, unsigned int size, u64 td_tag)
{
	return cpu_to_le64(ICE_TX_DESC_DTYPE_DATA |
			   (td_cmd    << ICE_TXD_QW1_CMD_S) |
			   (td_offset << ICE_TXD_QW1_OFFSET_S) |
			   ((u64)size << ICE_TXD_QW1_TX_BUF_SZ_S) |
			   (td_tag    << ICE_TXD_QW1_L2TAG1_S));
}

/**
 * ice_xdp_ring_update_tail - Updates the XDP Tx ring tail register
 * @xdp_ring: XDP Tx ring
 *
 * This function updates the XDP Tx ring tail register.
 */
static inline void ice_xdp_ring_update_tail(struct ice_ring *xdp_ring)
{
	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch.
	 */
	wmb();
	writel_relaxed(xdp_ring->next_to_use, xdp_ring->tail);
}

static inline void ice_xdp_set_meta(struct xdp_buff *xdp, union ice_32b_rx_flex_desc *desc, s32 btf_id)
{
	struct ice_32b_rx_flex_desc_nic *flex = (struct ice_32b_rx_flex_desc_nic *)desc;
	struct xdp_meta_generic *md = xdp->data - sizeof(struct xdp_meta_generic);

	md->rxcvid = le16_to_cpu(flex->flex_ts.flex.vlan_id);
	md->hash = le32_to_cpu(flex->rss_hash);

	md->flags = 0;
	md->free_slot = 0;
	md->csum_off = 0;
	md->txcvid = 0;
	md->csum = 0;
	md->tstamp = 0;

	md->btf_id = btf_id;

	xdp->data_meta = md;
}

void ice_finalize_xdp_rx(struct ice_ring *rx_ring, unsigned int xdp_res);
int ice_xmit_xdp_buff(struct xdp_buff *xdp, struct ice_ring *xdp_ring);
int ice_xmit_xdp_ring(void *data, u16 size, struct ice_ring *xdp_ring);
void ice_release_rx_desc(struct ice_ring *rx_ring, u16 val);
void
ice_process_skb_fields(struct ice_ring *rx_ring,
		       union ice_32b_rx_flex_desc *rx_desc,
		       struct sk_buff *skb, u16 ptype);
void
ice_receive_skb(struct ice_ring *rx_ring, struct sk_buff *skb, u16 vlan_tag);
#endif /* !_ICE_TXRX_LIB_H_ */
