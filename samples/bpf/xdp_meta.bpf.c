/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct ice_ring___min {
        struct ice_ring *next;
        void *desc;
        struct device *dev;
        struct net_device *netdev;
        struct ice_vsi *vsi;
        struct ice_q_vector *q_vector;
        u8 *tail;
} __attribute__((preserve_access_index));

SEC("xdp")
int xdp_meta_prog(struct xdp_md *ctx)
{
	struct xdp_meta_generic *data_meta =
		(void *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u64 nh_off;
	u64 btf_id_libbpf;
	u32 btf_id_meta;
	u64 btf_id_ring;
	u16 rxcvid;
	u32 hash;
	long *value;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	
	if (data_meta + 1 > data)
		return XDP_DROP;

	btf_id_libbpf = bpf_core_type_id_kernel(struct xdp_meta_generic);
	bpf_probe_read_kernel(&btf_id_meta, sizeof(btf_id_meta), (void*)data - 4);

	bpf_printk("id from libbpf %u (module BTF id: %u), id from hints metadata %u\n",
		   btf_id_libbpf & 0xFFFFFFFF, btf_id_libbpf >> 32, btf_id_meta);

	btf_id_ring = bpf_core_type_id_kernel(struct ice_ring___min);
	bpf_printk("ring type id %u, ice BTF id %u\n",
		   btf_id_ring & 0xFFFFFFFF, btf_id_ring >> 32);

	if (btf_id_libbpf == btf_id_meta)
		bpf_printk("Received meta is generic\n");
	else
		bpf_printk("Received meta type is unknown\n");

	
	hash = BPF_CORE_READ(data_meta, hash);
	rxcvid = BPF_CORE_READ(data_meta, rxcvid);
	bpf_printk("Metadata. Hash: 0x%x, VID: %d\n", hash, rxcvid);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
