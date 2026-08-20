#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "crash_trace.h"

/* 崩溃信号 */
#define SIGSEGV 11
#define SIGBUS 7
#define SIGABRT 6
#define SIGILL 4
#define SIGFPE 8
#define SIGSTOP 19

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * tracepoint/signal/signal_deliver 的上下文结构体。
 *
 * 注意：tracepoint 的 raw 类型 (trace_event_raw_signal_deliver) 通常不在
 * vmlinux.h BTF 中，因为内核 BTF 只导出被函数引用的类型。因此这里手动定义。
 *
 * 字段布局必须以 /sys/kernel/tracing/events/signal/signal_deliver/format 为准。
 * 格式说明：
 *   - 前 8 字节是固定前缀 (common_type + common_flags + common_preempt_count + common_pid)
 *   - 后面才是 tracepoint 特有字段
 *
 * 常见 ARM64 布局（offset 以 8 对齐）：
 *   offset 0:  u16 common_type
 *   offset 2:  u8  common_flags
 *   offset 3:  u8  common_preempt_count
 *   offset 4:  s32 common_pid
 *   offset 8:  s32 sig
 *   offset 12: s32 errno
 *   offset 16: s32 code
 *   offset 24: u64 sa_handler   (注意：有 4 字节 padding 在 code 后)
 *   offset 32: u64 sa_flags
 */
struct signal_deliver_ctx
{
    /* 前 8 字节是 tracepoint 固定头部 */
    u16 common_type;
    u8 common_flags;
    u8 common_preempt_count;
    s32 common_pid;

    /* tracepoint 特有字段 */
    int sig;
    int errno;
    int code;
    u32 __pad; /* code 和 sa_handler 之间的 4 字节对齐填充 */
    unsigned long sa_handler;
    unsigned long sa_flags;
};

/*
 * 从当前 task_struct 中读取 mm->start_code（即 text 段加载基址）。
 * 进程崩溃后 /proc/PID/maps 会消失，必须在 BPF 侧提前抓取。
 */
static __always_inline __u64 get_load_base(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm;
    __u64 start_code = 0;

    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    if (mm)
        bpf_probe_read_kernel(&start_code, sizeof(start_code),
                              &mm->start_code);
    return start_code;
}

#if 0
SEC("tracepoint/signal/signal_deliver")
int trace_crash(struct signal_deliver_ctx *ctx)
{
    struct crash_event *e;
    int sig = ctx->sig;

    if (sig != SIGSEGV && sig != SIGBUS && sig != SIGABRT &&
        sig != SIGILL  && sig != SIGFPE)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->tid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->sig       = sig;
    e->code      = ctx->code;
    e->error_code     = ctx->errno;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    e->ustack_sz = bpf_get_stack(ctx, e->ustack,
                                  sizeof(e->ustack), BPF_F_USER_STACK);
    e->kstack_sz = bpf_get_stack(ctx, e->kstack,
                                  sizeof(e->kstack), 0);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
#endif
SEC("tracepoint/signal/signal_generate")
int trace_crash_generate(struct signal_deliver_ctx *ctx)
{
    struct crash_event *e;
    int sig = ctx->sig;

    if (sig != SIGSEGV && sig != SIGBUS && sig != SIGABRT &&
        sig != SIGILL && sig != SIGFPE)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->sig = sig;
    e->code = ctx->code;
    e->error_code = ctx->errno;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* 捕获 text 段加载基址，用于后续虚拟偏移计算 */
    e->load_base = get_load_base();

    e->ustack_sz = bpf_get_stack(ctx, e->ustack,
                                 sizeof(e->ustack), BPF_F_USER_STACK);
    e->kstack_sz = bpf_get_stack(ctx, e->kstack,
                                 sizeof(e->kstack), 0);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";