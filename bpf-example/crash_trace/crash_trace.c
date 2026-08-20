// /home/jin/arm64_lib/bpf-example/crash_trace/crash_trace.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "crash_trace.skel.h"
#include "crash_trace.h"
#include "blazesym_api.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) { exiting = 1; }

/* 完整的信号名称表（参考 bpftrace src/stdlib/strings/signal.h） */
static const char *sig_name(int sig)
{
    static const char *signals[] = {
        [0] = "Unknown signal 0",
        [1] = "SIGHUP",
        [2] = "SIGINT",
        [3] = "SIGQUIT",
        [4] = "SIGILL",
        [5] = "SIGTRAP",
        [6] = "SIGABRT",
        [7] = "SIGBUS",
        [8] = "SIGFPE",
        [9] = "SIGKILL",
        [10] = "SIGUSR1",
        [11] = "SIGSEGV",
        [12] = "SIGUSR2",
        [13] = "SIGPIPE",
        [14] = "SIGALRM",
        [15] = "SIGTERM",
        [16] = "SIGSTKFLT",
        [17] = "SIGCHLD",
        [18] = "SIGCONT",
        [19] = "SIGSTOP",
        [20] = "SIGTSTP",
        [21] = "SIGTTIN",
        [22] = "SIGTTOU",
        [23] = "SIGURG",
        [24] = "SIGXCPU",
        [25] = "SIGXFSZ",
        [26] = "SIGVTALRM",
        [27] = "SIGPROF",
        [28] = "SIGWINCH",
        [29] = "SIGIO",
        [30] = "SIGPWR",
        [31] = "SIGSYS",
    };
    if (sig >= 0 && sig < (int)(sizeof(signals) / sizeof(signals[0])) && signals[sig])
        return signals[sig];
    if (sig >= 32 && sig <= 64)
        return "SIGRT";
    return "UNKNOWN";
}

/* 根据信号和 si_code 返回可读的崩溃原因描述（参考 bpftrace 的 signal_deliver 语义） */
static const char *crash_reason(int sig, int code)
{
    switch (sig)
    {
    case SIGSEGV:
        switch (code)
        {
        case SEGV_MAPERR:
            return "address not mapped to object";
        case SEGV_ACCERR:
            return "invalid permissions for mapped object";
        default:
            return "segmentation fault";
        }
    case SIGBUS:
        switch (code)
        {
        case BUS_ADRALN:
            return "invalid address alignment";
        case BUS_ADRERR:
            return "non-existent physical address";
        case BUS_OBJERR:
            return "object-specific hardware error";
        default:
            return "bus error";
        }
    case SIGILL:
        switch (code)
        {
        case ILL_ILLOPC:
            return "illegal opcode";
        case ILL_ILLOPN:
            return "illegal operand";
        case ILL_ILLADR:
            return "illegal addressing mode";
        case ILL_ILLTRP:
            return "illegal trap";
        case ILL_PRVOPC:
            return "privileged opcode";
        case ILL_PRVREG:
            return "privileged register";
        case ILL_COPROC:
            return "coprocessor error";
        case ILL_BADSTK:
            return "internal stack error";
        default:
            return "illegal instruction";
        }
    case SIGFPE:
        switch (code)
        {
        case FPE_INTDIV:
            return "integer divide by zero";
        case FPE_INTOVF:
            return "integer overflow";
        case FPE_FLTDIV:
            return "floating-point divide by zero";
        case FPE_FLTOVF:
            return "floating-point overflow";
        case FPE_FLTUND:
            return "floating-point underflow";
        case FPE_FLTRES:
            return "floating-point inexact result";
        case FPE_FLTINV:
            return "invalid floating-point operation";
        case FPE_FLTSUB:
            return "subscript out of range";
        default:
            return "floating-point exception";
        }
    case SIGABRT:
        return "abort signal from abort()";
    default:
        return "";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct crash_event *e = data;

    printf("\n!!! CRASH: %s  PID=%d TID=%d COMM=%s\n",
           sig_name(e->sig), e->pid, e->tid, e->comm);
    printf("    Reason: %s (code=%d)\n", crash_reason(e->sig, e->code), e->code);

    int ustack_depth = e->ustack_sz / sizeof(uint64_t);
    if (ustack_depth > 0)
    {
        sym_info_t frames[ustack_depth];
        int n = resolve_symbols(e->pid, e->comm, e->load_base,
                                e->ustack, ustack_depth, frames);
        printf("[User Stack]\n");
        for (int i = 0; i < n; i++)
        {
            sym_info_t *f = &frames[i];
            printf("  #%-2d 0x%016lx  ", i, f->addr);
            if (f->name[0])
                printf("%-40s", f->name);
            else
                printf("%-40s", "???");
            if (f->src_path[0])
                printf("  at %s:%u", f->src_path, f->src_line);
            printf("  [%s+0x%lx]\n",
                   f->module[0] ? f->module : "???", f->module_offset);
        }
    }

    int kstack_depth = e->kstack_sz / sizeof(uint64_t);
    if (kstack_depth > 0)
    {
        sym_info_t kframes[kstack_depth];
        int kn = resolve_kernel_symbols(e->kstack, kstack_depth, kframes);
        printf("[Kernel Stack]\n");
        for (int i = 0; i < kn; i++)
        {
            sym_info_t *f = &kframes[i];
            printf("  #%-2d 0x%016lx  ", i, f->addr);
            if (f->name[0])
                printf("%-40s", f->name);
            else
                printf("%-40s", "???");
            if (f->src_path[0])
                printf("  at %s:%u", f->src_path, f->src_line);
            if (f->module[0])
                printf("  [%s]", f->module);
            printf("\n");
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct crash_trace_bpf *skel;
    struct ring_buffer *ring_buf = NULL;
    struct bpf_link *link = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

        skel = crash_trace_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to load BPF\n");
        return 1;
    }

    err = crash_trace_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program\n");
        err = 1;
        goto cleanup;
    }
    ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.events),
                                handle_event, NULL, NULL);
    if (!ring_buf)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    printf("Crash tracer ready. Waiting for SEGV/BUS/ABRT/ILL/FPE...\n");
    printf("Press Ctrl+C to stop.\n\n");

    while (!exiting)
    {
        ring_buffer__poll(ring_buf, 100);
    }

    err = 0;
cleanup:
    ring_buffer__free(ring_buf);
    bpf_link__destroy(link);
    crash_trace_bpf__destroy(skel);
    return err;
}