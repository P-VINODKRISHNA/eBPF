#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_DROP_PORT 4040

struct bpf_map_def SEC("maps") drop_port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u16),
    .max_entries = 1,
};

SEC("xdp_drop")
int xdp_prog_drop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    int key = 0;
    __u16 *port = bpf_map_lookup_elem(&drop_port_map, &key);
    if (!port) return XDP_PASS;

    if (tcp->dest == htons(*port)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
