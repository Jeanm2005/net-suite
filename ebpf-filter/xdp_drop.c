#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("license")
char _license[] = "GPL";

SEC("xdp")
int xdp_drop_tcp_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parse IPv4 Header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. Parse TCP Header
    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Target Port: Drop incoming TCP port 80 (HTTP) traffic
    if (tcph->dest == bpf_htons(80)) {
        bpf_printk("[eBPF Kernel] XDP_DROP: Filtered TCP port 80 packet\n");
        return XDP_DROP;
    }

    return XDP_PASS;
}
