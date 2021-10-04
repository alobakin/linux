// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <time.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include "xdp_meta.skel.h"

int main(int argc, char **argv)
{
	__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_USE_METADATA;
	__u32 prog_id, prog_fd;
	struct xdp_meta *skel;
	int ifindex, ret = 1;

	if (argc == optind) {
		return ret;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex)
		ifindex = strtoul(argv[optind], NULL, 0);
	if (!ifindex) {
		fprintf(stderr, "Bad interface index or name\n");
		goto end;
	}

	skel = xdp_meta__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_meta__open: %s\n",
			strerror(errno));
		ret = 1;
		goto end;
	}

	ret = xdp_meta__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to xdp_meta__load: %s\n", strerror(errno));
		ret = 1;
		goto end_destroy;
	}

	ret = 1;
	prog_fd = bpf_program__fd(skel->progs.xdp_meta_prog);
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		fprintf(stderr, "Failed to set xdp link");
		goto end_destroy;
	}

	if (bpf_get_link_xdp_id(ifindex, &prog_id, xdp_flags)) {
		fprintf(stderr, "Failed to get XDP program id for ifindex");
		goto end_destroy;
	}

	while (1) {
		sleep(2);
	}

	ret = 0;
end_destroy:
	xdp_meta__destroy(skel);
end:
	return ret;
}
