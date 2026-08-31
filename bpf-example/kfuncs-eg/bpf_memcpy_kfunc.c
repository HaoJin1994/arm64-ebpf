#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/string.h>

/* ─── 声明 kfunc 原型 ─── */
__bpf_kfunc int bpf_memcpy(u8 *dst, u32 dst__sz, const u8 *src, u32 src__sz, u32 len);

__bpf_kfunc_start_defs();

/* ─── 包装内核 memcpy ───
 *
 * 参数说明：
 *   dst      - 目标缓冲区指针
 *   dst__sz  - 目标缓冲区大小（BPF 验证器需要，用于边界检查）
 *   src      - 源缓冲区指针
 *   src__sz  - 源缓冲区大小（BPF 验证器需要，用于边界检查）
 *   len      - 要拷贝的字节数
 *
 * 命名约定：__sz 后缀告诉验证器这是对应指针的缓冲区大小
 */
__bpf_kfunc int bpf_memcpy(u8 *dst, u32 dst__sz, const u8 *src, u32 src__sz, u32 len)
{
    // 边界检查（防止越界）
    if (len > dst__sz || len > src__sz)
        return -EINVAL;

    // 调用内核的 memcpy
    memcpy(dst, src, len);

    return 0;
}

__bpf_kfunc_end_defs();

/* ─── BTF ID 注册 ─── */
BTF_KFUNCS_START(bpf_memcpy_ids_set)
BTF_ID_FLAGS(func, bpf_memcpy)
BTF_KFUNCS_END(bpf_memcpy_ids_set)

static const struct btf_kfunc_id_set bpf_memcpy_set = {
    .owner = THIS_MODULE,
    .set   = &bpf_memcpy_ids_set,
};

static int __init bpf_memcpy_init(void)
{
    int ret;

    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_memcpy_set);
    if (ret) {
        pr_err("bpf_memcpy: failed to register kfunc set for KPROBE\n");
        return ret;
    }

    // 注册到其他程序类型
    register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_memcpy_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_memcpy_set);

    pr_info("bpf_memcpy kfunc module loaded\n");
    return 0;
}

static void __exit bpf_memcpy_exit(void)
{
    // 注意：某些内核版本可能不支持unregister，所以注释掉
    pr_info("bpf_memcpy kfunc module unloaded\n");
}

module_init(bpf_memcpy_init);
module_exit(bpf_memcpy_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BPF kfunc wrapper for kernel memcpy");