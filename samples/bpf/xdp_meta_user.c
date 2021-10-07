// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>
#include <time.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include "xdp_meta.skel.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

static volatile bool xdp_meta_sample_running = true;

static void xdp_meta_sample_stop(int signo)
{
	xdp_meta_sample_running = false;
}

/* Had to change the standard read_trace_pipe from trace_helpers.h */
static void xdp_meta_read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0){
		fprintf(stderr, "Could not open the trace_pipe\n");
		return;
	}

	while (xdp_meta_sample_running) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(int argc, char **argv)
{
	__u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_USE_METADATA;
	__u32 prog_id, prog_fd, running_prog_id;
	struct xdp_meta *skel;
	int ifindex, ret = 1;
	struct sigaction handle_ctrl_c;

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
		fprintf(stderr, "Failed to set xdp link\n");
		goto end_destroy;
	}

	if (bpf_get_link_xdp_id(ifindex, &prog_id, xdp_flags)) {
		fprintf(stderr, "Failed to get XDP program id for ifindex\n");
		goto end_destroy;
	}

	memset(&handle_ctrl_c, 0, sizeof(handle_ctrl_c));
	handle_ctrl_c.sa_handler = &xdp_meta_sample_stop;
	sigaction(SIGINT, &handle_ctrl_c, NULL);

	xdp_meta_read_trace_pipe();

	ret = 0;

	if(bpf_get_link_xdp_id(ifindex, &running_prog_id, xdp_flags) || running_prog_id != prog_id){
		fprintf(stderr,
			"Failed to get the running XDP program id or another program is running. Exit without detaching.\n");
		goto end_destroy;
	}

	fprintf(stderr, "Detaching the program...\n");
	bpf_set_link_xdp_fd(ifindex, -1, 0);

end_destroy:
	xdp_meta__destroy(skel);
end:
	return ret;
}
