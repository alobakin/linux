/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */

#ifndef __LIBIE_RX_H
#define __LIBIE_RX_H

#include <linux/if_vlan.h>

#include <net/page_pool/helpers.h>
#include <net/xdp.h>

/* Rx MTU/buffer/truesize helpers. Mostly pure software-side; HW-defined values
 * are valid for all Intel HW.
 */

/* Space reserved in front of each frame */
#define LIBIE_SKB_HEADROOM	(NET_SKB_PAD + NET_IP_ALIGN)
/* Maximum headroom to calculate max MTU below */
#define LIBIE_MAX_HEADROOM	LIBIE_SKB_HEADROOM
/* Link layer / L2 overhead: Ethernet, 2 VLAN tags (C + S), FCS */
#define LIBIE_RX_LL_LEN		(ETH_HLEN + 2 * VLAN_HLEN + ETH_FCS_LEN)

/* Always use order-0 pages */
#define LIBIE_RX_PAGE_ORDER	0
/* Rx buffer size config is a multiple of 128, align to a cacheline boundary */
#define LIBIE_RX_BUF_LEN_ALIGN	SKB_DATA_ALIGN(128)
/* HW-writeable space in one buffer: truesize - headroom/tailroom,
 * HW-aligned
 */
#define LIBIE_RX_PAGE_LEN(hr)						\
	ALIGN_DOWN(SKB_MAX_ORDER(hr, LIBIE_RX_PAGE_ORDER),		\
		   LIBIE_RX_BUF_LEN_ALIGN)
/* The smallest and largest size for a single descriptor as per HW */
#define LIBIE_MIN_RX_BUF_LEN	1024U
#define LIBIE_MAX_RX_BUF_LEN	9728U
/* "True" HW-writeable space: minimum from SW and HW values */
#define LIBIE_RX_BUF_LEN(hr)	min_t(u32, LIBIE_RX_PAGE_LEN(hr),	\
				      LIBIE_MAX_RX_BUF_LEN)

/* The maximum frame size as per HW (S/G) */
#define __LIBIE_MAX_RX_FRM_LEN	16382U
/* ATST, HW can chain up to 5 Rx descriptors */
#define LIBIE_MAX_RX_FRM_LEN(hr)					\
	min_t(u32, __LIBIE_MAX_RX_FRM_LEN, LIBIE_RX_BUF_LEN(hr) * 5)
/* Maximum frame size minus LL overhead */
#define LIBIE_MAX_MTU							\
	(LIBIE_MAX_RX_FRM_LEN(LIBIE_MAX_HEADROOM) - LIBIE_RX_LL_LEN)

/* Rx buffer management */

/**
 * struct libie_rx_buffer - structure representing an Rx buffer
 * @page: page holding the buffer
 * @offset: offset from the page start (to the headroom)
 * @truesize: total space occupied by the buffer (w/ headroom and tailroom)
 *
 * Depending on the MTU, API switches between one-page-per-frame and shared
 * page model (to conserve memory on bigger-page platforms). In case of the
 * former, @offset is always 0 and @truesize is always ```PAGE_SIZE```.
 */
struct libie_rx_buffer {
	struct page		*page;
	u32			offset;
	u32			truesize;
} __aligned_largest;

/**
 * struct libie_buf_queue - structure representing a buffer queue
 * @pp: &page_pool for buffer management
 * @rx_bi: array of Rx buffers
 * @truesize: size to allocate per buffer, w/overhead
 * @count: number of descriptors/buffers the queue has
 * @rx_buf_len: HW-writeable length per each buffer
 */
struct libie_buf_queue {
	struct page_pool	*pp;
	struct libie_rx_buffer	*rx_bi;

	u32			truesize;
	u32			count;

	/* Cold fields */
	u32			rx_buf_len;
};

int libie_rx_page_pool_create(struct libie_buf_queue *bq,
			      struct napi_struct *napi);
void libie_rx_page_pool_destroy(struct libie_buf_queue *bq);

/**
 * libie_rx_alloc - allocate a new Rx buffer
 * @bq: buffer queue to allocate for
 * @i: index of the buffer within the queue
 *
 * Return: DMA address to be passed to HW for Rx on successful allocation,
 * ```DMA_MAPPING_ERROR``` otherwise.
 */
static inline dma_addr_t libie_rx_alloc(const struct libie_buf_queue *bq,
					u32 i)
{
	struct libie_rx_buffer *buf = &bq->rx_bi[i];

	buf->truesize = bq->truesize;
	buf->page = page_pool_dev_alloc(bq->pp, &buf->offset, &buf->truesize);
	if (unlikely(!buf->page))
		return DMA_MAPPING_ERROR;

	return page_pool_get_dma_addr(buf->page) + buf->offset +
	       bq->pp->p.offset;
}

/**
 * libie_rx_sync_for_cpu - synchronize or recycle buffer post DMA
 * @buf: buffer to process
 * @len: frame length from the descriptor
 *
 * Process the buffer after it's written by HW. The regular path is to
 * synchronize DMA for CPU, but in case of no data it will be immediately
 * recycled back to its PP.
 *
 * Return: true when there's data to process, false otherwise.
 */
static inline bool libie_rx_sync_for_cpu(const struct libie_rx_buffer *buf,
					 u32 len)
{
	struct page *page = buf->page;

	/* Very rare, but possible case. The most common reason:
	 * the last fragment contained FCS only, which was then
	 * stripped by the HW.
	 */
	if (unlikely(!len)) {
		page_pool_recycle_direct(page->pp, page);
		return false;
	}

	page_pool_dma_sync_for_cpu(page->pp, page, buf->offset, len);

	return true;
}

/* O(1) converting i40e/ice/iavf's 8/10-bit hardware packet type to a parsed
 * bitfield struct.
 */

struct libie_rx_ptype_parsed {
	u16			outer_ip:2;
	u16			outer_frag:1;
	u16			tunnel_type:3;
	u16			tunnel_end_prot:2;
	u16			tunnel_end_frag:1;
	u16			inner_prot:3;
	u16			payload_layer:2;

	enum xdp_rss_hash_type	hash_type:16;
};

enum libie_rx_ptype_outer_ip {
	LIBIE_RX_PTYPE_OUTER_L2				= 0U,
	LIBIE_RX_PTYPE_OUTER_IPV4,
	LIBIE_RX_PTYPE_OUTER_IPV6,
};

enum libie_rx_ptype_outer_fragmented {
	LIBIE_RX_PTYPE_NOT_FRAG				= 0U,
	LIBIE_RX_PTYPE_FRAG,
};

enum libie_rx_ptype_tunnel_type {
	LIBIE_RX_PTYPE_TUNNEL_IP_NONE			= 0U,
	LIBIE_RX_PTYPE_TUNNEL_IP_IP,
	LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT,
	LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC,
	LIBIE_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN,
};

enum libie_rx_ptype_tunnel_end_prot {
	LIBIE_RX_PTYPE_TUNNEL_END_NONE			= 0U,
	LIBIE_RX_PTYPE_TUNNEL_END_IPV4,
	LIBIE_RX_PTYPE_TUNNEL_END_IPV6,
};

enum libie_rx_ptype_inner_prot {
	LIBIE_RX_PTYPE_INNER_NONE			= 0U,
	LIBIE_RX_PTYPE_INNER_UDP,
	LIBIE_RX_PTYPE_INNER_TCP,
	LIBIE_RX_PTYPE_INNER_SCTP,
	LIBIE_RX_PTYPE_INNER_ICMP,
	LIBIE_RX_PTYPE_INNER_TIMESYNC,
};

enum libie_rx_ptype_payload_layer {
	LIBIE_RX_PTYPE_PAYLOAD_NONE			= PKT_HASH_TYPE_NONE,
	LIBIE_RX_PTYPE_PAYLOAD_L2			= PKT_HASH_TYPE_L2,
	LIBIE_RX_PTYPE_PAYLOAD_L3			= PKT_HASH_TYPE_L3,
	LIBIE_RX_PTYPE_PAYLOAD_L4			= PKT_HASH_TYPE_L4,
};

#define LIBIE_RX_PTYPE_NUM				154

extern const struct libie_rx_ptype_parsed
libie_rx_ptype_lut[LIBIE_RX_PTYPE_NUM];

/**
 * libie_parse_rx_ptype - convert HW packet type to software bitfield structure
 * @ptype: 10-bit hardware packet type value from the descriptor
 *
 * ```libie_rx_ptype_lut``` must be accessed only using this wrapper.
 *
 * Return: parsed bitfield struct corresponding to the provided ptype.
 */
static inline struct libie_rx_ptype_parsed libie_parse_rx_ptype(u32 ptype)
{
	if (unlikely(ptype >= LIBIE_RX_PTYPE_NUM))
		ptype = 0;

	return libie_rx_ptype_lut[ptype];
}

/* libie_has_*() can be used to quickly check whether the HW metadata is
 * available to avoid further expensive processing such as descriptor reads.
 * They already check for the corresponding netdev feature to be enabled,
 * thus can be used as drop-in replacements.
 */

static inline bool libie_has_rx_checksum(const struct net_device *dev,
					 struct libie_rx_ptype_parsed parsed)
{
	/* Non-zero _INNER* is only possible when _OUTER_IPV* is set,
	 * it is enough to check only for the L4 type.
	 */
	return likely(parsed.inner_prot > LIBIE_RX_PTYPE_INNER_NONE &&
		      (dev->features & NETIF_F_RXCSUM));
}

static inline bool libie_has_rx_hash(const struct net_device *dev,
				     struct libie_rx_ptype_parsed parsed)
{
	return likely(parsed.payload_layer > LIBIE_RX_PTYPE_PAYLOAD_NONE &&
		      (dev->features & NETIF_F_RXHASH));
}

/**
 * libie_skb_set_hash - fill in skb hash value basing on the parsed ptype
 * @skb: skb to fill the hash in
 * @hash: 32-bit hash value from the descriptor
 * @parsed: parsed packet type
 */
static inline void libie_skb_set_hash(struct sk_buff *skb, u32 hash,
				      struct libie_rx_ptype_parsed parsed)
{
	skb_set_hash(skb, hash, parsed.payload_layer);
}

#endif /* __LIBIE_RX_H */
