// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Intel Corporation.
 *
 * Author: Larysa Zaremba <larysa.zaremba@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

# define __force	__attribute__((force))

#define BITFIELD_GET(_mask, _reg)						\
({										\
	(typeof(_mask))(((_reg) & (_mask)) >> (__builtin_ffsll(_mask) - 1));	\
})

#define GET_BTF_OBJ_ID(_full_id)						\
({										\
	_full_id >> 32;								\
})

#define GET_BTF_TYPE_ID(_full_id)						\
({										\
	_full_id & 0xFFFFFFFF;							\
})

SEC("xdp")
int xdp_meta_prog(struct xdp_md *ctx)
{
	u16 vlan_type, hash_type, csum_level, csum_status;
	struct xdp_meta_generic *data_meta;
	u32 magic_meta, offset, rx_flags;
	u64 btf_id_libbpf, btf_id_hints;

	offset = ctx->data - ctx->data_meta;
	data_meta = bpf_access_mem(ctx->data_meta, ctx->data,
				   offset - sizeof(struct xdp_meta_generic),
				   sizeof(struct xdp_meta_generic));
	if (!data_meta) {
		bpf_printk("could not obtain generic meta pointer\n");
		bpf_printk("space between data_meta and data should be %ld, is %d\n",
			   sizeof(struct xdp_meta_generic), ctx->data - ctx->data_meta);
		return XDP_DROP;
	}

	magic_meta = __bpf_le16_to_cpu(data_meta->magic);
	if (magic_meta != XDP_META_GENERIC_MAGIC) {
		bpf_printk("meta des not contain generic hints, based on received magic: 0x%x\n",
			   magic_meta);
		return XDP_DROP;
	}

	btf_id_libbpf = bpf_core_type_id_kernel(struct xdp_meta_generic);
	btf_id_hints = __bpf_le64_to_cpu(data_meta->full_id);

	bpf_printk("id from libbpf %u (module BTF id: %u), id from hints metadata %u (module BTF id: %u)\n",
		   GET_BTF_TYPE_ID(btf_id_libbpf), GET_BTF_OBJ_ID(btf_id_libbpf),
		   GET_BTF_TYPE_ID(btf_id_hints), GET_BTF_OBJ_ID(btf_id_hints));

	if (btf_id_libbpf == btf_id_hints) {
		bpf_printk("Received meta is generic\n");
	} else {
		bpf_printk("Received meta type is unknown\n");
		return XDP_DROP;
	}

	rx_flags = __bpf_le32_to_cpu(data_meta->rx_flags);
	if (BITFIELD_GET(XDP_META_RX_QID_PRESENT, rx_flags))
		bpf_printk("RX queue ID: %d\n", __bpf_le16_to_cpu(data_meta->rx_qid));
	else
		bpf_printk("RX queue ID not present\n");

	if (BITFIELD_GET(XDP_META_RX_TSTAMP_PRESENT, rx_flags))
		bpf_printk("RX timestamp: %d\n", __bpf_le64_to_cpu(data_meta->rx_tstamp));
	else
		bpf_printk("RX timestamp not present\n");

	vlan_type = BITFIELD_GET(XDP_META_RX_VLAN_TYPE, rx_flags);
	if (vlan_type)
		bpf_printk("RX VLAN type: %s, VLAN ID: %d",
			   vlan_type == XDP_META_RX_CVID ? "customer" : "service",
			   __bpf_le16_to_cpu(data_meta->rx_vid));
	else
		bpf_printk("No VLAN detected\n");

	hash_type = BITFIELD_GET(XDP_META_RX_HASH_TYPE, rx_flags);
	if (hash_type)
		bpf_printk("RX hash type: L%d, hash value: 0x%x\n",
			   hash_type + 1, __bpf_le32_to_cpu(data_meta->rx_hash));
	else
		bpf_printk("RX hash not present\n");

	csum_level = BITFIELD_GET(XDP_META_RX_CSUM_LEVEL, rx_flags);
	csum_status = BITFIELD_GET(XDP_META_RX_CSUM_STATUS, rx_flags);
	if (csum_status == XDP_META_RX_CSUM_COMP)
		bpf_printk("L%d checksum is: 0x%x\n", csum_level,
			   __bpf_le32_to_cpu(data_meta->rx_csum));
	else if (csum_status == XDP_META_RX_CSUM_OK)
		bpf_printk("L%d checksum was checked\n", csum_level);
	else
		bpf_printk("Checksum information was not provided\n");

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
