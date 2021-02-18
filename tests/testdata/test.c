#include "linux/bpf.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") lru_hash = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") big_hash = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 100000,
};

struct bpf_map_def SEC("maps") array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 5,
};

struct bpf_map_def SEC("maps") big_array = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 100000,
};

struct bpf_map_def SEC("maps") prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") dev_map = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(__u32),
    .value_size = sizeof(int),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") per_cpu_hash = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") per_cpu_lru = {
    .type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") per_cpu_array = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") pc_hash_big = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10000,
};

struct bpf_map_def SEC("maps") pc_array_big = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1000,
};

struct bpf_map_def SEC("maps") perf_event = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
};



SEC("xdp_test")
int rxdp_test(struct xdp_md *ctx)
{
    return XDP_PASS;
}

SEC("xdp_drop")
int rxdp_drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

SEC("xdp_perf")
int rxdp_perf(struct xdp_md *ctx)
{
    __u32 client = 0;
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size = sizeof(__u32);
    flags |= (__u64)sample_size << 32;
    bpf_perf_event_output(ctx, &perf_event, flags, &client, sizeof(client));
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
