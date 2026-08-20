// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sdt.h>


static int add(int a, int b)
{
    DTRACE_PROBE2(test_usdt, add_start, a, b);
    int sum = a+b;
    DTRACE_PROBE1(test_usdt, add_end, sum);
    return sum;
}


int main(void)
{
    printf("test running, PID = %d\n", getpid());
    printf("Usage: ./test_usdt %d\n", getpid());
    printf("Press Ctrl-C to stop\n");

    while (1) {
        int sum = add(8, 16);
        sleep(1);
    }

    return 0;
}