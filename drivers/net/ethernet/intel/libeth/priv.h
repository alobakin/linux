/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LIBETH_PRIV_H
#define __LIBETH_PRIV_H

#include <linux/types.h>

/* Stats */

struct net_device;

bool libeth_stats_init_priv(struct net_device *dev, u32 rqs, u32 sqs,
			    u32 xdpsqs);
void libeth_stats_free_priv(const struct net_device *dev);

int libeth_stats_get_sset_count(struct net_device *dev);
void libeth_stats_get_strings(struct net_device *dev, u8 *data);
void libeth_stats_get_data(struct net_device *dev, u64 *data);

/* XDP */

enum xdp_action;
struct libeth_xdp_buff;
struct libeth_xdp_tx_frame;
struct skb_shared_info;
struct xdp_frame_bulk;

extern const struct xsk_tx_metadata_ops libeth_xsktmo_slow;

void libeth_xsk_tx_return_bulk(const struct libeth_xdp_tx_frame *bq,
			       u32 count);
u32 libeth_xsk_prog_exception(struct libeth_xdp_buff *xdp, enum xdp_action act,
			      int ret);

struct libeth_xdp_ops {
	void	(*bulk)(const struct skb_shared_info *sinfo,
			struct xdp_frame_bulk *bq, bool frags);
	void	(*xsk)(struct libeth_xdp_buff *xdp);
};

void libeth_attach_xdp(const struct libeth_xdp_ops *ops);

static inline void libeth_detach_xdp(void)
{
	libeth_attach_xdp(NULL);
}

#endif /* __LIBETH_PRIV_H */
