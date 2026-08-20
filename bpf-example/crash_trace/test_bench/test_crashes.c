// /home/jin/arm64_lib/bpf-example/crash_trace/test_crashes.c
//
// 编译（ARM64）：
//   aarch64-linux-gnu-gcc -O0 -g -o test_crashes test_crashes.c -lpthread -lm
//
// 或本地编译：
//   gcc -O0 -g -o test_crashes test_crashes.c -lpthread -lm
//
// 运行：
//   ./test_crashes segv_null    # SIGSEGV: 空指针解引用
//   ./test_crashes segv_write   # SIGSEGV: 写只读内存
//   ./test_crashes segv_wild    # SIGSEGV: 野指针
//   ./test_crashes segv_exec    # SIGSEGV: 执行不可执行内存
//   ./test_crashes bus_align    # SIGBUS: 非对齐访问（ARM64 上可能触发）
//   ./test_crashes bus_mmap     # SIGBUS: 访问被截断的 mmap
//   ./test_crashes fpe_div0     # SIGFPE: 整数除零
//   ./test_crashes fpe_ovfl     # SIGFPE: 整数溢出（需 -ftrapv）
//   ./test_crashes ill_ud2      # SIGILL: 非法指令
//   ./test_crashes abrt         # SIGABRT: abort()
//   ./test_crashes abrt_assert  # SIGABRT: assert 失败
//   ./test_crashes stack_ovfl   # 栈溢出 → SIGSEGV
//   ./test_crashes thread       # 多线程中崩溃
//   ./test_crashes indirect     # 通过函数指针间接崩溃
//   ./test_crashes deep         # 深层调用栈（~30 层）再崩溃

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include <math.h>
#include <assert.h>
#include <setjmp.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>

/* ================================================================
 *  深层调用栈构建器 —— 用于测试堆栈回溯的深度
 * ================================================================ */
typedef void (*crash_fn_t)(int depth);

static void __attribute__((noinline))
deep_call_0(int depth) { ((crash_fn_t)(uintptr_t)(depth))(-1); } // 最终崩溃点
static void __attribute__((noinline))
deep_call_1(int depth) { deep_call_0(depth); }
static void __attribute__((noinline))
deep_call_2(int depth) { deep_call_1(depth); }
static void __attribute__((noinline))
deep_call_3(int depth) { deep_call_2(depth); }
static void __attribute__((noinline))
deep_call_4(int depth) { deep_call_3(depth); }
static void __attribute__((noinline))
deep_call_5(int depth) { deep_call_4(depth); }
static void __attribute__((noinline))
deep_call_6(int depth) { deep_call_5(depth); }
static void __attribute__((noinline))
deep_call_7(int depth) { deep_call_6(depth); }
static void __attribute__((noinline))
deep_call_8(int depth) { deep_call_7(depth); }
static void __attribute__((noinline))
deep_call_9(int depth) { deep_call_8(depth); }
static void __attribute__((noinline))
deep_call_10(int depth) { deep_call_9(depth); }
static void __attribute__((noinline))
deep_call_11(int depth) { deep_call_10(depth); }
static void __attribute__((noinline))
deep_call_12(int depth) { deep_call_11(depth); }
static void __attribute__((noinline))
deep_call_13(int depth) { deep_call_12(depth); }
static void __attribute__((noinline))
deep_call_14(int depth) { deep_call_13(depth); }
static void __attribute__((noinline))
deep_call_15(int depth) { deep_call_14(depth); }
static void __attribute__((noinline))
deep_call_16(int depth) { deep_call_15(depth); }
static void __attribute__((noinline))
deep_call_17(int depth) { deep_call_16(depth); }
static void __attribute__((noinline))
deep_call_18(int depth) { deep_call_17(depth); }
static void __attribute__((noinline))
deep_call_19(int depth) { deep_call_18(depth); }
static void __attribute__((noinline))
deep_call_20(int depth) { deep_call_19(depth); }
static void __attribute__((noinline))
deep_call_21(int depth) { deep_call_20(depth); }
static void __attribute__((noinline))
deep_call_22(int depth) { deep_call_21(depth); }
static void __attribute__((noinline))
deep_call_23(int depth) { deep_call_22(depth); }
static void __attribute__((noinline))
deep_call_24(int depth) { deep_call_23(depth); }
static void __attribute__((noinline))
deep_call_25(int depth) { deep_call_24(depth); }
static void __attribute__((noinline))
deep_call_26(int depth) { deep_call_25(depth); }
static void __attribute__((noinline))
deep_call_27(int depth) { deep_call_26(depth); }
static void __attribute__((noinline))
deep_call_28(int depth) { deep_call_27(depth); }
static void __attribute__((noinline))
deep_call_29(int depth) { deep_call_28(depth); }
static void __attribute__((noinline))
deep_call_30(int depth) { deep_call_29(depth); }

/* ================================================================
 *  崩溃场景 1：SIGSEGV — 空指针解引用
 * ================================================================ */
static void __attribute__((noinline))
do_null_deref_core(volatile int *p)
{
    *p = 42; /* 真正的崩溃点 */
}

static void __attribute__((noinline))
do_null_deref_validate(volatile int *p)
{
    if (p != NULL)
    { /* 分支干扰，考验符号解析 */
        int x = *p;
        printf("unreachable: %d\n", x);
    }
    do_null_deref_core(p);
}

static void __attribute__((noinline))
do_null_deref_wrapper(void)
{
    volatile int *p = NULL;
    do_null_deref_validate(p);
}

static void crash_segv_null(void)
{
    printf("[*] Triggering SIGSEGV: null pointer dereference\n");
    fflush(stdout);
    do_null_deref_wrapper();
}

/* ================================================================
 *  崩溃场景 2：SIGSEGV — 写只读内存
 * ================================================================ */
static void __attribute__((noinline))
do_ro_write_inner(char *ro_mem)
{
    ro_mem[0] = 'X'; /* 崩溃点：写只读页 */
}

static void __attribute__((noinline))
do_ro_write_prepare(char *ro_mem, size_t idx)
{
    size_t offset = idx * 0; /* 多余的运算，增加栈帧 */
    do_ro_write_inner(ro_mem + offset);
}

static void crash_segv_write(void)
{
    printf("[*] Triggering SIGSEGV: write to read-only memory\n");
    fflush(stdout);

    /* 分配一页，标记为只读 */
    long page_size = sysconf(_SC_PAGESIZE);
    char *mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }
    strcpy(mem, "hello");
    mprotect(mem, page_size, PROT_READ); /* 改为只读 */
    do_ro_write_prepare(mem, 0);
    munmap(mem, page_size);
}

/* ================================================================
 *  崩溃场景 3：SIGSEGV — 野指针（随机地址）
 * ================================================================ */
static void __attribute__((noinline))
do_wild_ptr_deref(volatile char *addr)
{
    *addr = 0; /* 崩溃点 */
}

static void __attribute__((noinline))
do_wild_ptr_calc(void)
{
    /* 构造一个几乎肯定无效的地址 */
    volatile char *fake_addr = (volatile char *)0xdeadbeefcafe0000UL;
    do_wild_ptr_deref(fake_addr);
}

static void crash_segv_wild(void)
{
    printf("[*] Triggering SIGSEGV: wild pointer\n");
    fflush(stdout);
    do_wild_ptr_calc();
}

/* ================================================================
 *  崩溃场景 4：SIGSEGV — 执行不可执行内存
 * ================================================================ */
static void __attribute__((noinline))
do_exec_nx_jump(void (*fn)(void))
{
    fn(); /* 崩溃点：跳转到不可执行内存 */
}

static void __attribute__((noinline))
do_exec_nx_setup(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    unsigned char *mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        exit(1);
    }
    /* ARM64 非法指令：0x00000000 */
    mem[0] = 0x00;
    mem[1] = 0x00;
    mem[2] = 0x00;
    mem[3] = 0x00;
    mprotect(mem, page_size, PROT_READ); /* 只读，不可执行 */
    do_exec_nx_jump((void (*)(void))mem);
    munmap(mem, page_size);
}

static void crash_segv_exec(void)
{
    printf("[*] Triggering SIGSEGV: execute non-executable memory\n");
    fflush(stdout);
    do_exec_nx_setup();
}

/* ================================================================
 *  崩溃场景 5：SIGBUS — 非对齐访问
 * ================================================================ */
static void __attribute__((noinline))
do_unaligned_load(volatile unsigned long *addr)
{
    unsigned long val = *addr; /* 崩溃点：非对齐访问 */
    (void)val;
}

static void __attribute__((noinline))
do_unaligned_setup(void)
{
    unsigned char buf[16] __attribute__((aligned(8)));
    memset(buf, 0, sizeof(buf));
    /* 故意偏移 1 字节，造成非对齐访问 */
    volatile unsigned long *unaligned = (volatile unsigned long *)(buf + 1);
    do_unaligned_load(unaligned);
}

static void crash_bus_align(void)
{
    printf("[*] Triggering SIGBUS: unaligned access\n");
    printf("    (ARM64 默认允许非对齐访问，除非 /proc/cpu/alignment 设为 2)\n");
    fflush(stdout);
    do_unaligned_setup();
}

/* ================================================================
 *  崩溃场景 6：SIGBUS — 访问被截断的 mmap
 * ================================================================ */
static void __attribute__((noinline))
do_truncated_mmap_read(volatile char *addr)
{
    *addr = 0; /* 崩溃点：截断后访问 */
}

static void __attribute__((noinline))
do_truncated_mmap_setup(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    int fd;
    char template[] = "/tmp/crash_test_XXXXXX";

    fd = mkstemp(template);
    if (fd < 0)
    {
        perror("mkstemp");
        exit(1);
    }
    ftruncate(fd, page_size);
    unlink(template);

    char *mem = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED)
    {
        perror("mmap");
        close(fd);
        exit(1);
    }
    close(fd);

    /* 截断文件，mmap 后半部分变成无效 */
    ftruncate(fd, 0); /* fd 已关闭，这里用 open 再截断 */
    int fd2 = open(template, O_RDWR);
    if (fd2 >= 0)
    {
        ftruncate(fd2, 0);
        close(fd2);
    }

    /* 访问第二页，应触发 SIGBUS */
    do_truncated_mmap_read(mem + page_size);
    munmap(mem, page_size * 2);
}

static void crash_bus_mmap(void)
{
    printf("[*] Triggering SIGBUS: truncated mmap access\n");
    fflush(stdout);
    do_truncated_mmap_setup();
}

/* ================================================================
 *  崩溃场景 7：SIGFPE — 整数除零
 * ================================================================ */
static int __attribute__((noinline))
do_div_zero_inner(int a, int b)
{
    return a / b; /* 崩溃点 */
}

static int __attribute__((noinline))
do_div_zero_middle(int x, int y)
{
    int z = x + y;
    return do_div_zero_inner(z, y - y); /* y - y = 0 */
}

static void crash_fpe_div0(void)
{
    printf("[*] Triggering SIGFPE: integer division by zero\n");
    fflush(stdout);
    int result = do_div_zero_middle(42, 10);
    printf("unreachable: %d\n", result);
}

/* ================================================================
 *  崩溃场景 8：SIGILL — 非法指令 (UD2)
 * ================================================================ */
static void __attribute__((noinline))
do_illegal_instr_outer(void)
{
    /* ARM64 上 UDF #0 是永久未定义指令，触发 SIGILL */
#ifdef __aarch64__
    __asm__ volatile("udf #0");
#elif defined(__x86_64__)
    __asm__ volatile("ud2");
#else
    __builtin_trap();
#endif
}

static void __attribute__((noinline))
do_illegal_instr_inner(void)
{
    do_illegal_instr_outer();
}

static void crash_ill_ud2(void)
{
    printf("[*] Triggering SIGILL: illegal instruction\n");
    fflush(stdout);
    do_illegal_instr_inner();
}

/* ================================================================
 *  崩溃场景 9：SIGABRT — abort()
 * ================================================================ */
static void __attribute__((noinline))
do_abort_level3(void)
{
    abort(); /* 崩溃点 */
}

static void __attribute__((noinline))
do_abort_level2(const char *msg)
{
    fprintf(stderr, "Fatal: %s\n", msg);
    do_abort_level3();
}

static void __attribute__((noinline))
do_abort_level1(int code)
{
    if (code != 0)
    {
        do_abort_level2("irrecoverable error");
    }
}

static void crash_abrt(void)
{
    printf("[*] Triggering SIGABRT: abort()\n");
    fflush(stdout);
    do_abort_level1(1);
}

/* ================================================================
 *  崩溃场景 10：SIGABRT — assert() 失败
 * ================================================================ */
static int __attribute__((noinline))
do_assert_compute(int x, int y)
{
    return x * y - x - y;
}

static void __attribute__((noinline))
do_assert_check(int val)
{
    /* 断言失败时触发 SIGABRT */
    assert(val == 42);
    printf("assert passed: %d\n", val);
}

static void crash_abrt_assert(void)
{
    printf("[*] Triggering SIGABRT: assert() failure\n");
    fflush(stdout);
    int result = do_assert_compute(10, 5); /* 10*5-10-5 = 35 */
    do_assert_check(result);               /* 35 != 42，断言失败 */
}

/* ================================================================
 *  崩溃场景 11：SIGSEGV — 栈溢出
 * ================================================================ */
static int __attribute__((noinline))
do_stack_overflow(int n, char *sp_marker)
{
    char buf[4096]; /* 每次递归消耗 4KB 栈 */
    memset(buf, 'A', sizeof(buf));
    /* 用 volatile 防止尾调用优化 */
    volatile int depth = n;
    if (depth > 0)
    {
        return do_stack_overflow(depth - 1, sp_marker) + buf[0];
    }
    return buf[0];
}

static void crash_stack_ovfl(void)
{
    printf("[*] Triggering SIGSEGV: stack overflow\n");
    fflush(stdout);
    char marker;
    do_stack_overflow(10000, &marker);
}

/* ================================================================
 *  崩溃场景 12：多线程中崩溃
 * ================================================================ */
static void __attribute__((noinline))
do_thread_crash_inner(void)
{
    volatile int *p = NULL;
    *p = 42; /* 崩溃点 */
}

static void *thread_crash_fn(void *arg)
{
    int id = *(int *)arg;
    printf("[thread %d] about to crash...\n", id);
    fflush(stdout);
    do_thread_crash_inner();
    return NULL;
}

static void crash_thread(void)
{
    printf("[*] Triggering SIGSEGV: crash in a spawned thread\n");
    fflush(stdout);

    pthread_t threads[3];
    int ids[3] = {1, 2, 3};

    for (int i = 0; i < 3; i++)
    {
        pthread_create(&threads[i], NULL, thread_crash_fn, &ids[i]);
    }
    for (int i = 0; i < 3; i++)
    {
        pthread_join(threads[i], NULL);
    }
}

/* ================================================================
 *  崩溃场景 13：函数指针间接崩溃
 * ================================================================ */
typedef void (*op_fn_t)(void);

static void __attribute__((noinline))
do_indirect_crash(void)
{
    volatile int *p = NULL;
    *p = 42; /* 崩溃点 */
}

static void __attribute__((noinline))
do_indirect_dispatch(op_fn_t fn)
{
    fn(); /* 通过函数指针调用 */
}

static void __attribute__((noinline))
do_indirect_setup(int selector)
{
    op_fn_t fns[4] = {NULL, NULL, do_indirect_crash, NULL};
    do_indirect_dispatch(fns[selector]);
}

static void crash_indirect(void)
{
    printf("[*] Triggering SIGSEGV: indirect crash via function pointer\n");
    fflush(stdout);
    do_indirect_setup(2);
}

/* ================================================================
 *  崩溃场景 14：深层调用栈（~30 层）后崩溃
 * ================================================================ */
static void crash_deep(void)
{
    printf("[*] Triggering SIGSEGV: deep call stack (~30 frames) + null deref\n");
    fflush(stdout);
    /* 传递 0 作为"深度值"，在 deep_call_0 中强转为函数指针触发崩溃 */
    deep_call_30(0);
}

/* ================================================================
 *  main：根据命令行参数选择崩溃类型
 * ================================================================ */
typedef struct
{
    const char *name;
    void (*fn)(void);
    const char *desc;
} crash_entry_t;

static crash_entry_t crashes[] = {
    {"segv_null", crash_segv_null, "SIGSEGV: null pointer dereference"},
    {"segv_write", crash_segv_write, "SIGSEGV: write to read-only memory"},
    {"segv_wild", crash_segv_wild, "SIGSEGV: wild pointer dereference"},
    {"segv_exec", crash_segv_exec, "SIGSEGV: execute NX memory"},
    {"bus_align", crash_bus_align, "SIGBUS:  unaligned access"},
    {"bus_mmap", crash_bus_mmap, "SIGBUS:  truncated mmap access"},
    {"fpe_div0", crash_fpe_div0, "SIGFPE:  integer division by zero"},
    {"ill_ud2", crash_ill_ud2, "SIGILL:  illegal instruction (udf)"},
    {"abrt", crash_abrt, "SIGABRT: abort()"},
    {"abrt_assert", crash_abrt_assert, "SIGABRT: assert() failure"},
    {"stack_ovfl", crash_stack_ovfl, "SIGSEGV: stack overflow"},
    {"thread", crash_thread, "SIGSEGV: crash in spawned thread"},
    {"indirect", crash_indirect, "SIGSEGV: crash via function pointer"},
    {"deep", crash_deep, "SIGSEGV: deep 30-frame call stack"},
    {NULL, NULL, NULL},
};

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: %s <crash_type>\n\n", argv[0]);
        printf("Available crash types:\n");
        for (crash_entry_t *e = crashes; e->name; e++)
        {
            printf("  %-14s  %s\n", e->name, e->desc);
        }
        printf("\nExample:\n");
        printf("  # 终端 1: 运行 crash_trace\n");
        printf("  # 终端 2: 触发崩溃\n");
        printf("  ./test_crashes segv_null\n");
        printf("  ./test_crashes deep\n");
        return 1;
    }

    const char *choice = argv[1];

    for (crash_entry_t *e = crashes; e->name; e++)
    {
        if (strcmp(choice, e->name) == 0)
        {
            printf("=== Crash Test: %s ===\n", e->name);
            printf("=== Description: %s ===\n", e->desc);
            printf("=== PID: %d ===\n\n", getpid());
            fflush(stdout);

            /* 给 crash_trace 一点时间 attach */
            printf("Waiting 2 seconds for tracer to attach...\n");
            fflush(stdout);
            sleep(2);

            e->fn();
            return 0; /* unreachable */
        }
    }

    printf("Unknown crash type: '%s'\n", choice);
    printf("Run '%s' without arguments to see available types.\n", argv[0]);
    return 1;
}