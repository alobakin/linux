/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct xdp_meta_generic___minimal {
	u32 btf_id;
	u16 rxcvid;
	u32 hash;
};

SEC("xdp")
int xdp_meta_prog(struct xdp_md *ctx)
{
	struct xdp_meta_generic___minimal *data_meta =
		(void *)(long)ctx->data_meta;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u64 nh_off;
	u32 btf_id_libbpf;
	u32 btf_id_meta;
	s32 err;
	long *value;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	
	if (data_meta + 1 > data)
		return XDP_DROP;

	btf_id_libbpf = bpf_core_type_id_kernel(struct xdp_meta_generic___minimal);
	err = bpf_probe_read_kernel(&btf_id_meta, sizeof(btf_id_meta), (void*)data - 4);

	/* Probably should not be in the final version */
	if (err){
		bpf_printk("id from libbpf %d, could not obtain id from hints metadata, error is %d\n",
			   btf_id_libbpf, err);
		return XDP_DROP;
	}

	bpf_printk("id from libbpf %d, id from hints metadata %d\n",
		   btf_id_libbpf, btf_id_meta);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
