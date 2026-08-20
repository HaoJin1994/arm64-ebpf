#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/usdt.bpf.h>
#include "usdt.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct usdt_data);
} data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("usdt")
int start(struct pt_regs *ctx)
{
    struct usdt_data data = {};
    __u32 key;
    __u32 arg_cnt;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.tid = (__u32)bpf_get_current_pid_tgid();
    arg_cnt = bpf_usdt_arg_cnt(ctx);
    if (arg_cnt != 2) {
        bpf_printk("usdt start: arg_cnt %d not 2\n", arg_cnt);
        return 0;
    }
    bpf_usdt_arg(ctx, 0, &data.arg1);
    bpf_usdt_arg(ctx, 1, &data.arg2);

    key = (__u32)data.pid;
    bpf_map_update_elem(&data_map, &key, &data, BPF_ANY);

    return 0;
}

SEC("usdt")
int end(struct pt_regs *ctx)
{
    struct usdt_data *map_data, *ringbuf_data;
    __u32 key;

    key = (__u32)(bpf_get_current_pid_tgid() >> 32);

    map_data = bpf_map_lookup_elem(&data_map, &key);
    if (!map_data) {
        bpf_printk("usdt end: pid %d not found\n", key);
        return 0;
    }

    bpf_usdt_arg(ctx, 0, &map_data->ret);

    ringbuf_data = bpf_ringbuf_reserve(&ringbuf, sizeof(*ringbuf_data), 0);
    if (!ringbuf_data) {
        bpf_printk("usdt end: ringbuf reserve failed\n");
        return 0;
    }

    *ringbuf_data = *map_data;
    bpf_ringbuf_submit(ringbuf_data, 0);
    bpf_printk("usdt end: pid %d, tid %d\n", key, map_data->tid);
    bpf_printk("arg1: %llu, arg2: %llu, ret: %llu\n", map_data->arg1, map_data->arg2, map_data->ret);
    bpf_map_delete_elem(&data_map, &key);

    return 0;
}
char LICENSE[] SEC("license") = "GPL";