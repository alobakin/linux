// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. */

#include <linux/net/intel/libie/rx.h>

#include "internal.h"

/* O(1) converting i40e/ice/iavf's 8/10-bit hardware packet type to a parsed
 * bitfield struct.
 */

#define LIBIE_RX_PTYPE(oip, ofrag, tun, tp, tefr, iprot, pl) {		   \
		.outer_ip		= LIBIE_RX_PTYPE_OUTER_##oip,	   \
		.outer_frag		= LIBIE_RX_PTYPE_##ofrag,	   \
		.tunnel_type		= LIBIE_RX_PTYPE_TUNNEL_IP_##tun,  \
		.tunnel_end_prot	= LIBIE_RX_PTYPE_TUNNEL_END_##tp,  \
		.tunnel_end_frag	= LIBIE_RX_PTYPE_##tefr,	   \
		.inner_prot		= LIBIE_RX_PTYPE_INNER_##iprot,	   \
		.payload_layer		= LIBIE_RX_PTYPE_PAYLOAD_##pl,	   \
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

/* Page Pool */

/**
 * libie_rx_sync_len - get the actual buffer size to be synced and passed to HW
 * @dev: &net_device to calculate the size for
 * @hr: headroom in front of each frame
 *
 * Returns the buffer size to pass it to HW and use for DMA synchronization
 * for the MTU the @dev has.
 */
static u32 libie_rx_sync_len(const struct net_device *dev, u32 hr)
{
	u32 len;

	len = READ_ONCE(dev->mtu) + LIBIE_RX_LL_LEN;
	len = ALIGN(len, LIBIE_RX_BUF_LEN_ALIGN);
	len = min(len, LIBIE_RX_BUF_LEN(hr));

	return len;
}

/**
 * libie_rx_page_pool_create - create a PP with the default libie settings
 * @dev: &net_device which a PP will be created for
 * @size: size of the PP, usually simply Rx queue len
 * @xdp: whether XDP is enabled on the device
 *
 * Returns &page_pool on success, casted -errno on failure.
 */
struct page_pool *libie_rx_page_pool_create(const struct net_device *dev,
					    u32 size, bool xdp)
{
	u32 hr = xdp ? LIBIE_XDP_HEADROOM : LIBIE_SKB_HEADROOM;
	const struct page_pool_params pp = {
		.flags		= PP_FLAG_DMA_MAP | PP_FLAG_DMA_MAP_WEAK |
				  PP_FLAG_DMA_SYNC_DEV,
		.order		= LIBIE_RX_PAGE_ORDER,
		.pool_size	= size,
		.nid		= NUMA_NO_NODE,
		.dev		= dev->dev.parent,
		.dma_dir	= xdp ? DMA_BIDIRECTIONAL : DMA_FROM_DEVICE,
		.max_len	= libie_rx_sync_len(dev, hr),
		.offset		= hr,
	};

	static_assert((PP_FLAG_DMA_MAP | PP_FLAG_DMA_MAP_WEAK) ==
		      LIBIE_RX_DMA_ATTR);

	return page_pool_create(&pp);
}
EXPORT_SYMBOL_NS_GPL(libie_rx_page_pool_create, LIBIE);

/**
 * libie_rx_page_pool_destroy - destroy a &page_pool created by libie
 * @pool: pool to destroy
 * @stats: RQ stats from the ring (or %NULL to skip updating PP stats)
 *
 * As the stats usually has the same lifetime as the device, but PP is usually
 * created/destroyed on ifup/ifdown, in order to not lose the stats accumulated
 * during the last ifup, the PP stats need to be added to the driver stats
 * container. Then the PP gets destroyed.
 */
void libie_rx_page_pool_destroy(struct page_pool *pool,
				struct libie_rq_stats *stats)
{
	libie_rq_stats_sync_pp(stats, pool);
	page_pool_destroy(pool);
}
EXPORT_SYMBOL_NS_GPL(libie_rx_page_pool_destroy, LIBIE);

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("Intel(R) Ethernet common library");
MODULE_LICENSE("GPL");
