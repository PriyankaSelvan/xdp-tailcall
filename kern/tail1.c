
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>

#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                             \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif



/* Tail call index=1 */
SEC("prog")
int  xdp_tail_call_1(struct xdp_md *ctx)
{
        //void *data_end = (void *)(long)ctx->data_end;
        //void *data = (void *)(long)ctx->data;
        // struct ethhdr *eth = data;

        bpf_debug("XDP: tail call (xdp_1) id=1\n");


        return XDP_PASS;
}

