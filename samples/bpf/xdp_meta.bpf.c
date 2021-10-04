// SPDX-License-Identifier: GPL-2.0
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct ice_aqc_generic___min {
	__le32 param0;
	__le32 param1;
	__le32 addr_high;
	__le32 addr_low;
};

SEC("xdp")
int xdp_meta_prog(struct xdp_md *ctx)
{
	struct xdp_meta_generic *data_meta =
		(void *)(long)ctx->data_meta;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	u32 type_id_meta, btf_id_meta, magic_meta;
	u64 btf_id_libbpf, btf_id_ice;
	u16 rxcvid;
	u32 hash;

	if (data_meta + 1 > data) {
		bpf_printk("data_meta space is not sufficient for generic metadata, should be %ld, is %ld\n",
			   sizeof(struct xdp_meta_generic), (long)data - (long)data_meta);
		return XDP_DROP;
	}

	bpf_probe_read_kernel(&magic_meta, sizeof(magic_meta), (void *)data - 4);
	if (magic_meta != XDP_META_GENERIC_MAGIC) {
		bpf_printk("meta des not contain generic hints, based on received magic: 0x%x\n",
			   magic_meta);
		return XDP_DROP;
	}

	btf_id_libbpf = bpf_core_type_id_kernel(struct xdp_meta_generic);
	bpf_probe_read_kernel(&type_id_meta, sizeof(type_id_meta), (void *)data - 8);
	bpf_probe_read_kernel(&btf_id_meta, sizeof(btf_id_meta), (void *)data - 12);

	bpf_printk("id from libbpf %u (module BTF id: %u), id from hints metadata %u (module BTF id: %u)\n",
		   btf_id_libbpf & 0xFFFFFFFF, btf_id_libbpf >> 32, type_id_meta, btf_id_meta);

	if (btf_id_libbpf == ((u64)btf_id_meta << 32 | type_id_meta))
		bpf_printk("Received meta is generic\n");
	else
		bpf_printk("Received meta type is unknown\n");

	btf_id_ice = bpf_core_type_id_kernel(struct ice_aqc_generic___min);
	bpf_printk("ice_aqc_generic type id %u, ice BTF id %u\n",
		   btf_id_ice & 0xFFFFFFFF, btf_id_ice >> 32);

	hash = BPF_CORE_READ(data_meta, rx_hash);
	rxcvid = BPF_CORE_READ(data_meta, rx_vid);
	bpf_printk("Metadata. Hash: 0x%x, VID: %d\n", hash, rxcvid);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
