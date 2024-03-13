// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. */

#include <linux/net/intel/libie/rx.h>

/* Rx buffer management */

/**
 * libie_rx_hw_len - get the actual buffer size to be passed to HW
 * @pp: &page_pool_params of the netdev to calculate the size for
 *
 * Return: HW-writeable length per one buffer to pass it to the HW accounting:
 * MTU the @dev has, HW required alignment, minimum and maximum allowed values,
 * and system's page size.
 */
static u32 libie_rx_hw_len(const struct page_pool_params *pp)
{
	u32 len;

	len = READ_ONCE(pp->netdev->mtu) + LIBIE_RX_LL_LEN;
	len = ALIGN(len, LIBIE_RX_BUF_LEN_ALIGN);
	len = clamp(len, LIBIE_MIN_RX_BUF_LEN, LIBIE_RX_BUF_LEN(pp->offset));

	return len;
}

/**
 * libie_rx_page_pool_create - create a PP with the default libie settings
 * @bq: buffer queue struct to fill
 * @napi: &napi_struct covering this PP (no usage outside its poll loops)
 *
 * Return: 0 on success, -errno on failure.
 */
int libie_rx_page_pool_create(struct libie_buf_queue *bq,
			      struct napi_struct *napi)
{
	struct page_pool_params pp = {
		.flags		= PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV,
		.order		= LIBIE_RX_PAGE_ORDER,
		.pool_size	= bq->count,
		.nid		= NUMA_NO_NODE,
		.dev		= napi->dev->dev.parent,
		.netdev		= napi->dev,
		.napi		= napi,
		.dma_dir	= DMA_FROM_DEVICE,
		.offset		= LIBIE_SKB_HEADROOM,
	};

	/* HW-writeable / syncable length per one page */
	pp.max_len = LIBIE_RX_PAGE_LEN(pp.offset);

	/* HW-writeable length per buffer */
	bq->rx_buf_len = libie_rx_hw_len(&pp);
	/* Buffer size to allocate */
	bq->truesize = roundup_pow_of_two(SKB_HEAD_ALIGN(pp.offset +
							 bq->rx_buf_len));

	bq->pp = page_pool_create(&pp);

	return PTR_ERR_OR_ZERO(bq->pp);
}
EXPORT_SYMBOL_NS_GPL(libie_rx_page_pool_create, LIBIE);

/**
 * libie_rx_page_pool_destroy - destroy a &page_pool created by libie
 * @bq: buffer queue to process
 */
void libie_rx_page_pool_destroy(struct libie_buf_queue *bq)
{
	page_pool_destroy(bq->pp);
	bq->pp = NULL;
}
EXPORT_SYMBOL_NS_GPL(libie_rx_page_pool_destroy, LIBIE);

/* O(1) converting i40e/ice/iavf's 8/10-bit hardware packet type to a parsed
 * bitfield struct.
 */

/* A few supplementary definitions for when XDP hash types do not coincide
 * with what can be generated from ptype definitions by means of preprocessor
 * concatenation.
 */
#define XDP_RSS_L3_L2			XDP_RSS_TYPE_NONE
#define XDP_RSS_L4_NONE			XDP_RSS_TYPE_NONE
#define XDP_RSS_L4_TIMESYNC		XDP_RSS_TYPE_NONE
#define XDP_RSS_TYPE_L3			XDP_RSS_TYPE_NONE
#define XDP_RSS_TYPE_L4			XDP_RSS_L4

#define LIBIE_RX_PTYPE(oip, ofrag, tun, tp, tefr, iprot, pl) {		   \
		.outer_ip		= LIBIE_RX_PTYPE_OUTER_##oip,	   \
		.outer_frag		= LIBIE_RX_PTYPE_##ofrag,	   \
		.tunnel_type		= LIBIE_RX_PTYPE_TUNNEL_IP_##tun,  \
		.tunnel_end_prot	= LIBIE_RX_PTYPE_TUNNEL_END_##tp,  \
		.tunnel_end_frag	= LIBIE_RX_PTYPE_##tefr,	   \
		.inner_prot		= LIBIE_RX_PTYPE_INNER_##iprot,	   \
		.payload_layer		= LIBIE_RX_PTYPE_PAYLOAD_##pl,	   \
		.hash_type		= XDP_RSS_L3_##oip |		   \
					  XDP_RSS_L4_##iprot |		   \
					  XDP_RSS_TYPE_##pl,		   \
	}

#define LIBIE_RX_PTYPE_UNUSED		{ }

#define __LIBIE_RX_PTYPE_L2(iprot, pl)					   \
	LIBIE_RX_PTYPE(L2, NOT_FRAG, NONE, NONE, NOT_FRAG, iprot, pl)
#define LIBIE_RX_PTYPE_L2		__LIBIE_RX_PTYPE_L2(NONE, L2)
#define LIBIE_RX_PTYPE_TS		__LIBIE_RX_PTYPE_L2(TIMESYNC, L2)
#define LIBIE_RX_PTYPE_L3		__LIBIE_RX_PTYPE_L2(NONE, L3)

#define LIBIE_RX_PTYPE_IP_FRAG(oip)					   \
	LIBIE_RX_PTYPE(IPV##oip, FRAG, NONE, NONE, NOT_FRAG, NONE, L3)
#define LIBIE_RX_PTYPE_IP_L3(oip, tun, teprot, tefr)			   \
	LIBIE_RX_PTYPE(IPV##oip, NOT_FRAG, tun, teprot, tefr, NONE, L3)
#define LIBIE_RX_PTYPE_IP_L4(oip, tun, teprot, iprot)			   \
	LIBIE_RX_PTYPE(IPV##oip, NOT_FRAG, tun, teprot, NOT_FRAG, iprot, L4)

#define LIBIE_RX_PTYPE_IP_NOF(oip, tun, ver)				   \
	LIBIE_RX_PTYPE_IP_L3(oip, tun, ver, NOT_FRAG),			   \
	LIBIE_RX_PTYPE_IP_L4(oip, tun, ver, UDP),			   \
	LIBIE_RX_PTYPE_UNUSED,						   \
	LIBIE_RX_PTYPE_IP_L4(oip, tun, ver, TCP),			   \
	LIBIE_RX_PTYPE_IP_L4(oip, tun, ver, SCTP),			   \
	LIBIE_RX_PTYPE_IP_L4(oip, tun, ver, ICMP)

/* IPv oip --> tun --> IPv ver */
#define LIBIE_RX_PTYPE_IP_TUN_VER(oip, tun, ver)			   \
	LIBIE_RX_PTYPE_IP_L3(oip, tun, ver, FRAG),			   \
	LIBIE_RX_PTYPE_IP_NOF(oip, tun, ver)

/* Non Tunneled IPv oip */
#define LIBIE_RX_PTYPE_IP_RAW(oip)					   \
	LIBIE_RX_PTYPE_IP_FRAG(oip),					   \
	LIBIE_RX_PTYPE_IP_NOF(oip, NONE, NONE)

/* IPv oip --> tun --> { IPv4, IPv6 } */
#define LIBIE_RX_PTYPE_IP_TUN(oip, tun)					   \
	LIBIE_RX_PTYPE_IP_TUN_VER(oip, tun, IPV4),			   \
	LIBIE_RX_PTYPE_IP_TUN_VER(oip, tun, IPV6)

/* IPv oip --> GRE/NAT tun --> { x, IPv4, IPv6 } */
#define LIBIE_RX_PTYPE_IP_GRE(oip, tun)					   \
	LIBIE_RX_PTYPE_IP_L3(oip, tun, NONE, NOT_FRAG),			   \
	LIBIE_RX_PTYPE_IP_TUN(oip, tun)

/* Non Tunneled IPv oip
 * IPv oip --> { IPv4, IPv6 }
 * IPv oip --> GRE/NAT --> { x, IPv4, IPv6 }
 * IPv oip --> GRE/NAT --> MAC --> { x, IPv4, IPv6 }
 * IPv oip --> GRE/NAT --> MAC/VLAN --> { x, IPv4, IPv6 }
 */
#define LIBIE_RX_PTYPE_IP(oip)						   \
	LIBIE_RX_PTYPE_IP_RAW(oip),					   \
	LIBIE_RX_PTYPE_IP_TUN(oip, IP),					   \
	LIBIE_RX_PTYPE_IP_GRE(oip, GRENAT),				   \
	LIBIE_RX_PTYPE_IP_GRE(oip, GRENAT_MAC),				   \
	LIBIE_RX_PTYPE_IP_GRE(oip, GRENAT_MAC_VLAN)

/* Lookup table mapping for O(1) parsing */
const struct libie_rx_ptype_parsed libie_rx_ptype_lut[LIBIE_RX_PTYPE_NUM] = {
	/* L2 packet types */
	LIBIE_RX_PTYPE_UNUSED,
	LIBIE_RX_PTYPE_L2,
	LIBIE_RX_PTYPE_TS,
	LIBIE_RX_PTYPE_L2,
	LIBIE_RX_PTYPE_UNUSED,
	LIBIE_RX_PTYPE_UNUSED,
	LIBIE_RX_PTYPE_L2,
	LIBIE_RX_PTYPE_L2,
	LIBIE_RX_PTYPE_UNUSED,
	LIBIE_RX_PTYPE_UNUSED,
	LIBIE_RX_PTYPE_L2,
	LIBIE_RX_PTYPE_UNUSED,

	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,
	LIBIE_RX_PTYPE_L3,

	LIBIE_RX_PTYPE_IP(4),
	LIBIE_RX_PTYPE_IP(6),
};
EXPORT_SYMBOL_NS_GPL(libie_rx_ptype_lut, LIBIE);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel(R) Ethernet common library");
MODULE_LICENSE("GPL");
