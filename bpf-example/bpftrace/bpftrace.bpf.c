#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpftrace.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

volatile const __u64 target_tgid = 0;

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} ustackmap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 4096);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} kstackmap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct key_t);
    __type(value, __u64);
} counts SEC(".maps");

SEC("perf_event")
int bpftrace(void *ctx)
{
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    if (target_tgid != 0 && tgid != target_tgid)
        return 0;

    struct key_t key = {};
    __s64 sid;

    sid = bpf_get_stackid(ctx, &ustackmap, BPF_F_USER_STACK);
    if (sid < 0)
        key.ustackid = (__u32)-1;
    else
        key.ustackid = (__u32)sid;

    sid = bpf_get_stackid(ctx, &kstackmap, 0);
    if (sid < 0)
        key.kstackid = (__u32)-1;
    else
        key.kstackid = (__u32)sid;

    if (key.ustackid == (__u32)-1 && key.kstackid == (__u32)-1)
        return 0;

    __u64 *count = bpf_map_lookup_elem(&counts, &key);
    if (count)
        (*count)++;
    else
    {
        __u64 one = 1;
        bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
    }

    return 0;
}