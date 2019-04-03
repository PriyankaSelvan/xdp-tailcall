/*
 * Example of using bpf tail calls (in XDP programs)
 */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>

#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";
#define PROG(F) SEC("xdp/"__stringify(F)) int bpf_func_##F
#define DEBUG 1

#ifdef  DEBUG
/* Only use this for debug output. Notice output from  bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                     \
        ({                          \
            char ____fmt[] = fmt;               \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);            \
        })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif
struct bpf_map_def SEC("maps") jmp_table1 = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") jmp_table2 = {
        .type = BPF_MAP_TYPE_PROG_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 100,
};


/* Main/root ebpf xdp program */
SEC("xdp/0")
int  xdp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	bpf_debug("XDP: Killroy was here! %d\n", 42);

	/* Validate packet length is minimum Eth header size */
	if (eth + 1 > data_end)
		return XDP_ABORTED;

	u32 key = 78;
        //bpf_debug("XDP: trying %d", key);
	bpf_tail_call(ctx, &jmp_table1, key);

	/* bpf_tail_call on empty jmp_table entry, cause fall-through.
	 * (Normally a bpf_tail_call never returns)
	 */
	bpf_debug("XDP: jmp_table empty, reached fall-through action\n");
	return XDP_PASS;
}

/* Setup of jmp_table is (for now) done manually in _user.c.
 *
 * Notice: bpf_load.c have support for auto-populating for "socket/N",
 * "kprobe/N" and "kretprobe/N" (TODO: add support for "xdp/N").
 */
/* Tail call index=1 */
SEC("xdp/1")
int  xdp_tail_call_1(struct xdp_md *ctx)
{
        //void *data_end = (void *)(long)ctx->data_end;
        //void *data = (void *)(long)ctx->data;
        // struct ethhdr *eth = data;

        bpf_debug("XDP: tail call (xdp_1) id=1\n");


        return XDP_PASS;
}


