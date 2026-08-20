// /home/jin/arm64_lib/bpf-example/blazesym_src/blazesym_api.h
#ifndef BLAZESYM_API_H
#define BLAZESYM_API_H

#include <stdint.h>
#include <stddef.h>

/* 单帧堆栈符号化结果 */
typedef struct
{
    uint64_t addr;          /* 原始地址                     */
    char name[256];         /* 函数名 / 符号名              */
    char module[256];       /* 所属模块路径（so/exe）        */
    uint64_t module_offset; /* 符号内偏移                    */
    char src_path[256];     /* 源码文件路径                  */
    uint32_t src_line;      /* 源码行号（0 表示无）          */
} sym_info_t;

/*
 * 一步完成堆栈符号化（blazesym 内部自动处理 /proc/$PID/maps）
 *
 *   pid        - 目标进程 PID
 *   comm       - 目标进程名（/proc/PID/maps 不存在时，用于搜索可执行文件）
 *   load_base  - text 段加载基址（BPF 侧捕获的 mm->start_code）
 *   addrs      - 待符号化的地址数组（绝对地址）
 *   addr_cnt   - 地址数量
 *   results    - 结果数组（调用方分配，长度 >= addr_cnt）
 *
 *   返回实际填充的结果数量，失败返回 -1
 */
int resolve_symbols(int pid, const char *comm, uint64_t load_base,
                    const uint64_t *addrs, size_t addr_cnt,
                    sym_info_t *results);
int resolve_kernel_symbols(const uint64_t *addrs, size_t addr_cnt,
                           sym_info_t *results);

#endif