// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2023 Intel Corporation. */

#include <linux/ethtool.h>
#include <linux/net/intel/libie/stats.h>
#include <net/page_pool.h>

#include "internal.h"

/* Rx per-queue stats */

static const char * const libie_rq_stats_str[] = {
#define act(s)	__stringify(s),
	DECLARE_LIBIE_RQ_STATS(act)
#undef act
};

#define LIBIE_RQ_STATS_NUM	ARRAY_SIZE(libie_rq_stats_str)

#ifdef CONFIG_PAGE_POOL_STATS
/**
 * libie_rq_stats_get_pp - get the current stats from a &page_pool
 * @sarr: local array to add stats to
 * @pool: pool to get the stats from
 *
 * Adds the current "live" stats from an online PP to the stats read from
 * the RQ container, so that the actual totals will be returned.
 */
static void libie_rq_stats_get_pp(u64 *sarr, struct page_pool *pool)
{
	struct page_pool_stats *pps;
	/* Used only to calculate pos below */
	struct libie_rq_stats tmp;
	u32 pos;

	/* Validate the libie PP stats array can be casted <-> PP struct */
	static_assert(sizeof(tmp.pp) == sizeof(*pps));

	if (!pool)
		return;

	/* Position of the first Page Pool stats field */
	pos = (u64_stats_t *)&tmp.pp - tmp.raw;
	pps = (typeof(pps))&sarr[pos];

	page_pool_get_stats(pool, pps);
}

/**
 * libie_rq_stats_sync_pp - add the current PP stats to the RQ stats container
 * @stats: stats structure to update
 * @pool: pool to read the stats
 *
 * Called by libie_rx_page_pool_destroy() to save the stats before destroying
 * the pool.
 */
void libie_rq_stats_sync_pp(struct libie_rq_stats *stats,
			    struct page_pool *pool)
{
	u64_stats_t *qarr = (u64_stats_t *)&stats->pp;
	struct page_pool_stats pps = { };
	u64 *sarr = (u64 *)&pps;

	if (!stats)
		return;

	page_pool_get_stats(pool, &pps);

	u64_stats_update_begin(&stats->syncp);

	for (u32 i = 0; i < sizeof(pps) / sizeof(*sarr); i++)
		u64_stats_add(&qarr[i], sarr[i]);

	u64_stats_update_end(&stats->syncp);
}
#else
static void libie_rq_stats_get_pp(u64 *sarr, struct page_pool *pool)
{
}

/* static inline void libie_rq_stats_sync_pp() is declared in "internal.h" */
#endif

/**
 * libie_rq_stats_get_sset_count - get the number of Ethtool RQ stats provided
 *
 * Returns the number of per-queue Rx stats supported by the library.
 */
u32 libie_rq_stats_get_sset_count(void)
{
	return LIBIE_RQ_STATS_NUM;
}
EXPORT_SYMBOL_NS_GPL(libie_rq_stats_get_sset_count, LIBIE);

/**
 * libie_rq_stats_get_strings - get the name strings of Ethtool RQ stats
 * @data: reference to the cursor pointing to the output buffer
 * @qid: RQ number to print in the prefix
 */
void libie_rq_stats_get_strings(u8 **data, u32 qid)
{
	for (u32 i = 0; i < LIBIE_RQ_STATS_NUM; i++)
		ethtool_sprintf(data, "rq%u_%s", qid, libie_rq_stats_str[i]);
}
EXPORT_SYMBOL_NS_GPL(libie_rq_stats_get_strings, LIBIE);

/**
 * libie_rq_stats_get_data - get the RQ stats in Ethtool format
 * @data: reference to the cursor pointing to the output array
 * @stats: RQ stats container from the queue
 * @pool: &page_pool from the queue (%NULL to ignore PP "live" stats)
 */
void libie_rq_stats_get_data(u64 **data, const struct libie_rq_stats *stats,
			     struct page_pool *pool)
{
	u64 sarr[LIBIE_RQ_STATS_NUM];
	u32 start;

	do {
		start = u64_stats_fetch_begin(&stats->syncp);

		for (u32 i = 0; i < LIBIE_RQ_STATS_NUM; i++)
			sarr[i] = u64_stats_read(&stats->raw[i]);
	} while (u64_stats_fetch_retry(&stats->syncp, start));

	libie_rq_stats_get_pp(sarr, pool);

	for (u32 i = 0; i < LIBIE_RQ_STATS_NUM; i++)
		(*data)[i] += sarr[i];

	*data += LIBIE_RQ_STATS_NUM;
}
EXPORT_SYMBOL_NS_GPL(libie_rq_stats_get_data, LIBIE);

/* Tx per-queue stats */

static const char * const libie_sq_stats_str[] = {
#define act(s)	__stringify(s),
	DECLARE_LIBIE_SQ_STATS(act)
#undef act
};

#define LIBIE_SQ_STATS_NUM	ARRAY_SIZE(libie_sq_stats_str)

/**
 * libie_sq_stats_get_sset_count - get the number of Ethtool SQ stats provided
 *
 * Returns the number of per-queue Tx stats supported by the library.
 */
u32 libie_sq_stats_get_sset_count(void)
{
	return LIBIE_SQ_STATS_NUM;
}
EXPORT_SYMBOL_NS_GPL(libie_sq_stats_get_sset_count, LIBIE);

/**
 * libie_sq_stats_get_strings - get the name strings of Ethtool SQ stats
 * @data: reference to the cursor pointing to the output buffer
 * @qid: SQ number to print in the prefix
 */
void libie_sq_stats_get_strings(u8 **data, u32 qid)
{
	for (u32 i = 0; i < LIBIE_SQ_STATS_NUM; i++)
		ethtool_sprintf(data, "sq%u_%s", qid, libie_sq_stats_str[i]);
}
EXPORT_SYMBOL_NS_GPL(libie_sq_stats_get_strings, LIBIE);

/**
 * libie_sq_stats_get_data - get the SQ stats in Ethtool format
 * @data: reference to the cursor pointing to the output array
 * @stats: SQ stats container from the queue
 */
void libie_sq_stats_get_data(u64 **data, const struct libie_sq_stats *stats)
{
	u64 sarr[LIBIE_SQ_STATS_NUM];
	u32 start;

	do {
		start = u64_stats_fetch_begin(&stats->syncp);

		for (u32 i = 0; i < LIBIE_SQ_STATS_NUM; i++)
			sarr[i] = u64_stats_read(&stats->raw[i]);
	} while (u64_stats_fetch_retry(&stats->syncp, start));

	for (u32 i = 0; i < LIBIE_SQ_STATS_NUM; i++)
		(*data)[i] += sarr[i];

	*data += LIBIE_SQ_STATS_NUM;
}
EXPORT_SYMBOL_NS_GPL(libie_sq_stats_get_data, LIBIE);
