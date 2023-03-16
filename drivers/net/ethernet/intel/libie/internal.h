/* SPDX-License-Identifier: GPL-2.0-only */
/* libie internal declarations not to be used in the drivers.
 *
 * Copyright(c) 2023 Intel Corporation.
 */

#ifndef __LIBIE_INTERNAL_H
#define __LIBIE_INTERNAL_H

struct libie_rx_queue;

#ifdef CONFIG_PAGE_POOL_STATS
void libie_rq_stats_sync_pp(const struct libie_rx_queue *rq);
#else
static inline void libie_rq_stats_sync_pp(const struct libie_rx_queue *rq)
{
}
#endif

#endif /* __LIBIE_INTERNAL_H */
