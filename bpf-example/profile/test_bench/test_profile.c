// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sdt.h>
/*
 * 测试用：深调用链 + CPU 计算，方便 profile 采样到完整的栈
 */

static int leaf_add(int a, int b)
{
    volatile int x = 0;
    for (int i = 0; i < 1000; i++)
        x += a + b;
    return x;
}

static int level3(int a, int b)
{
    int x = leaf_add(a, b);
    x += leaf_add(b, a);
    return x;
}

static int level2(int a, int b)
{
    DTRACE_PROBE2(test_profile, level2_start, a, b);
    int x = level3(a, b);
    x += level3(a + 1, b + 1);
    DTRACE_PROBE1(test_profile, level2_end, x);
    return x;
}

static int level1(int a, int b)
{
    int x = level2(a, b);
    x += level2(a + 2, b + 2);
    return x;
}

static void do_work_a(void)
{
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++)
        sum += level1(i, i * 2);
    (void)sum;
}

static void do_work_b(void)
{
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++)
        sum += level1(i + 1, i * 3);
    (void)sum;
}

static void do_work_c(void)
{
    volatile int sum = 0;
    for (int i = 0; i < 100000; i++)
        sum += level1(i + 2, i * 5);
    (void)sum;
}

int main(void)
{
    printf("Stack test running, PID = %d\n", getpid());
    printf("Usage: sudo ./profile %d\n", getpid());
    printf("Press Ctrl-C to stop\n");

    while (1) {
        do_work_a();
        do_work_b();
        do_work_c();
    }

    return 0;
}