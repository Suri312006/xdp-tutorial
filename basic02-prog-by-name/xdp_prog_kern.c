/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */

SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

SEC("xdp")
// basically just tells the linux kernel to run this on obtaining a packet
// and just drop that boy
// sudo ./xdp_loader --dev veth-basic02 --progname xdp_abort_func 
// ^ adds the xdp_abort_func rule to the ebtp runtime / hooks
// sudo ./xdp_loader --dev veth-basic02 --unload-all 
// ^ removes all linked functions
// can test functionality with the test env script, look in readme
int xdp_abort_func(struct xdp_md *ctx){
	return XDP_ABORTED;
}

/* Assignment#2: Add new XDP program section that use XDP_ABORTED */

char _license[] SEC("license") = "GPL";

/* Hint the avail XDP action return codes are:

enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
*/
