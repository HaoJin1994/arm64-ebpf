#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 声明 kfunc（__ksym 表示"由内核符号提供"）
extern int bpf_memcpy(void *dst, u32 dst__sz, const void *src, u32 src__sz, u32 len) __ksym;

SEC("kprobe/do_unlinkat")
int test_bpf_memcpy(void *ctx)
{
    char src[32] = "Hello from BPF kfunc memcpy!";
    char dst[32] = {0};

    // 调用自定义的 bpf_memcpy kfunc
    // __sz 后缀让验证器自动检查 dst 和 src 的缓冲区大小
    int ret = bpf_memcpy(dst, sizeof(dst), src, sizeof(src), 16);
    if (ret == 0) {
        bpf_printk("bpf_memcpy success: '%s'", dst);
    } else {
        bpf_printk("bpf_memcpy failed: %d", ret);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";