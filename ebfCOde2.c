#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

#define DEFAULT_PORT 4040
#define PROCESS_NAME_LEN 16

struct bpf_map_def SEC("maps") config_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = PROCESS_NAME_LEN,
    .value_size = sizeof(__u16),
    .max_entries = 1,
};

SEC("xdp_prog")
int xdp_prog_func(struct xdp_md *ctx) {
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    char comm[PROCESS_NAME_LEN];
    bpf_probe_read_kernel_str(comm, sizeof(comm), task->comm);

    __u16 *port = bpf_map_lookup_elem(&config_map, comm);
    if (!port) return XDP_DROP;

    if (tcp->dest == htons(*port)) {
        return XDP_PASS;
    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
