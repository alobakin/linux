/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2023 Intel Corporation. */

#ifndef __LIBIE_STATS_H
#define __LIBIE_STATS_H

#include <linux/u64_stats_sync.h>

/* Common */

/* Use 32-byte alignment to reduce false sharing */
#define __libie_stats_aligned	__aligned(4 * sizeof(u64_stats_t))

/**
 * libie_stats_add - update one structure counter from a local struct
 * @qs: queue stats structure to update (&libie_rq_stats or &libie_sq_stats)
 * @ss: local/onstack stats structure
 * @f: name of the field to update
 *
 * If a local/onstack stats structure is used to collect statistics during
 * hotpath loops, this macro can be used to shorthand updates, given that
 * the fields have the same name.
 * Must be guarded with u64_stats_update_{begin,end}().
 */
#define libie_stats_add(qs, ss, f)			\
	u64_stats_add(&(qs)->f, (ss)->f)

/**
 * __libie_stats_inc_one - safely increment one stats structure counter
 * @s: queue stats structure to update (&libie_rq_stats or &libie_sq_stats)
 * @f: name of the field to increment
 * @n: name of the temporary variable, result of __UNIQUE_ID()
 *
 * To be used on exception or slow paths -- allocation fails, queue stops etc.
 */
#define __libie_stats_inc_one(s, f, n) ({		\
	typeof(*(s)) *n = (s);				\
							\
	u64_stats_update_begin(&n->syncp);		\
	u64_stats_inc(&n->f);				\
	u64_stats_update_end(&n->syncp);		\
})
#define libie_stats_inc_one(s, f)			\
	__libie_stats_inc_one(s, f, __UNIQUE_ID(qs_))

/* Rx per-queue stats:
 * packets: packets received on this queue
 * bytes: bytes received on this queue
 * fragments: number of processed descriptors carrying only a fragment
 * alloc_page_fail: number of Rx page allocation fails
 * build_skb_fail: number of build_skb() fails
 */

#define DECLARE_LIBIE_RQ_NAPI_STATS(act)		\
	act(packets)					\
	act(bytes)					\
	act(fragments)

#define DECLARE_LIBIE_RQ_FAIL_STATS(act)		\
	act(alloc_page_fail)				\
	act(build_skb_fail)

#define DECLARE_LIBIE_RQ_STATS(act)			\
	DECLARE_LIBIE_RQ_NAPI_STATS(act)		\
	DECLARE_LIBIE_RQ_FAIL_STATS(act)

struct libie_rq_stats {
	struct u64_stats_sync	syncp;

	union {
		struct {
#define act(s)	u64_stats_t	s;
			DECLARE_LIBIE_RQ_NAPI_STATS(act);
			DECLARE_LIBIE_RQ_FAIL_STATS(act);
#undef act
		};
		DECLARE_FLEX_ARRAY(u64_stats_t, raw);
	};
} __libie_stats_aligned;

/* Rx stats being modified frequently during the NAPI polling, to sync them
 * with the queue stats once after the loop is finished.
 */
struct libie_rq_onstack_stats {
	union {
		struct {
#define act(s)	u32		s;
			DECLARE_LIBIE_RQ_NAPI_STATS(act);
#undef act
		};
		DECLARE_FLEX_ARRAY(u32, raw);
	};
};

/**
 * libie_rq_napi_stats_add - add onstack Rx stats to the queue container
 * @qs: Rx queue stats structure to update
 * @ss: onstack structure to get the values from, updated during the NAPI loop
 */
static inline void
libie_rq_napi_stats_add(struct libie_rq_stats *qs,
			const struct libie_rq_onstack_stats *ss)
{
	u64_stats_update_begin(&qs->syncp);
	libie_stats_add(qs, ss, packets);
	libie_stats_add(qs, ss, bytes);
	libie_stats_add(qs, ss, fragments);
	u64_stats_update_end(&qs->syncp);
}

u32 libie_rq_stats_get_sset_count(void);
void libie_rq_stats_get_strings(u8 **data, u32 qid);
void libie_rq_stats_get_data(u64 **data, const struct libie_rq_stats *stats);

/* Tx per-queue stats:
 * packets: packets sent from this queue
 * bytes: bytes sent from this queue
 * busy: number of xmit failures due to the ring being full
 * stops: number times the ring was stopped from the driver
 * restarts: number times it was started after being stopped
 * linearized: number of skbs linearized due to HW limits
 */

#define DECLARE_LIBIE_SQ_NAPI_STATS(act)		\
	act(packets)					\
	act(bytes)

#define DECLARE_LIBIE_SQ_XMIT_STATS(act)		\
	act(busy)					\
	act(stops)					\
	act(restarts)					\
	act(linearized)

#define DECLARE_LIBIE_SQ_STATS(act)			\
	DECLARE_LIBIE_SQ_NAPI_STATS(act)		\
	DECLARE_LIBIE_SQ_XMIT_STATS(act)

struct libie_sq_stats {
	struct u64_stats_sync	syncp;

	union {
		struct {
#define act(s)	u64_stats_t	s;
			DECLARE_LIBIE_SQ_STATS(act);
#undef act
		};
		DECLARE_FLEX_ARRAY(u64_stats_t, raw);
	};
} __libie_stats_aligned;

struct libie_sq_onstack_stats {
#define act(s)	u32		s;
	DECLARE_LIBIE_SQ_NAPI_STATS(act);
#undef act
};

/**
 * libie_sq_napi_stats_add - add onstack Tx stats to the queue container
 * @qs: Tx queue stats structure to update
 * @ss: onstack structure to get the values from, updated during the NAPI loop
 */
static inline void
libie_sq_napi_stats_add(struct libie_sq_stats *qs,
			const struct libie_sq_onstack_stats *ss)
{
	if (unlikely(!ss->packets))
		return;

	u64_stats_update_begin(&qs->syncp);
	libie_stats_add(qs, ss, packets);
	libie_stats_add(qs, ss, bytes);
	u64_stats_update_end(&qs->syncp);
}

u32 libie_sq_stats_get_sset_count(void);
void libie_sq_stats_get_strings(u8 **data, u32 qid);
void libie_sq_stats_get_data(u64 **data, const struct libie_sq_stats *stats);

#endif /* __LIBIE_STATS_H */
