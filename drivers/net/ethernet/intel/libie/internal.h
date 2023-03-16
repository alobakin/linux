/* SPDX-License-Identifier: GPL-2.0-only */
/* libie internal declarations not to be used in drivers.
 *
 * Copyright(c) 2023 Intel Corporation.
 */

#ifndef __LIBIE_INTERNAL_H
#define __LIBIE_INTERNAL_H

struct libie_rq_stats;
struct page_pool;

#ifdef CONFIG_PAGE_POOL_STATS
void libie_rq_stats_sync_pp(struct libie_rq_stats *stats,
			    struct page_pool *pool);
#else
static inline void libie_rq_stats_sync_pp(struct libie_rq_stats *stats,
					  struct page_pool *pool)
{
}
#endif

#endif /* __LIBIE_INTERNAL_H */
