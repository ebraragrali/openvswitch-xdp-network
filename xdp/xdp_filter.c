#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (ip->ihl < 5)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->doff < 5)
        return XDP_PASS;

    unsigned char *payload =
        (unsigned char *)tcp + (tcp->doff * 4);

    /*
     * Search the first 128 bytes of the TCP payload
     * for the keyword "BLOCKME".
     */
    #pragma unroll
    for (int i = 0; i < 128; i++) {

        if (payload + i + 7 > (unsigned char *)data_end)
            break;

        if (payload[i]     == 'B' &&
            payload[i + 1] == 'L' &&
            payload[i + 2] == 'O' &&
            payload[i + 3] == 'C' &&
            payload[i + 4] == 'K' &&
            payload[i + 5] == 'M' &&
            payload[i + 6] == 'E') {

            bpf_printk("DROP: BLOCKME detected\n");    
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
