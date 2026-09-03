// /home/jin/arm64_lib/bpf-example/crash_trace/crash_trace.h

#ifndef CRASH_TRACE_H
#define CRASH_TRACE_H

#define MAX_STACK_DEPTH 50

#if 0
#define SEGV_MAPERR 1 /* 访问未映射的地址 */
#define SEGV_ACCERR 2 /* 访问权限不足（如写只读内存） */

/* SIGBUS si_code 语义 */
#define BUS_ADRALN 1 /* 非对齐访问 */
#define BUS_ADRERR 2 /* 不存在的物理地址 */
#define BUS_OBJERR 3 /* 对象特定硬件错误 */

/* SIGILL si_code 语义 */
#define ILL_ILLOPC 1 /* 非法操作码 */
#define ILL_ILLOPN 2 /* 非法操作数 */
#define ILL_ILLADR 3 /* 非法寻址模式 */
#define ILL_ILLTRP 4 /* 非法陷阱 */
#define ILL_PRVOPC 5 /* 特权操作码 */
#define ILL_PRVREG 6 /* 特权寄存器 */
#define ILL_COPROC 7 /* 协处理器错误 */
#define ILL_BADSTK 8 /* 内部栈错误 */

/* SIGFPE si_code 语义 */
#define FPE_INTDIV 1 /* 整数除零 */
#define FPE_INTOVF 2 /* 整数溢出 */
#define FPE_FLTDIV 3 /* 浮点除零 */
#define FPE_FLTOVF 4 /* 浮点溢出 */
#define FPE_FLTUND 5 /* 浮点下溢 */
#define FPE_FLTRES 6 /* 浮点不精确结果 */
#define FPE_FLTINV 7 /* 无效浮点操作 */
#define FPE_FLTSUB 8 /* 下标越界 */
#endif
struct crash_event
{
    __u32 pid;
    __u32 tid;
    int sig;
    int code;
    int error_code;
    char comm[16];
    __u64 load_base; /* text 段加载基址（mm->start_code） */
    int ustack_sz;
    __u64 ustack[MAX_STACK_DEPTH];
    int kstack_sz;
    __u64 kstack[MAX_STACK_DEPTH];
};

#endif