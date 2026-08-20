# arm64_lib — ARM64 eBPF 开发环境

基于 ARM64 (aarch64) 架构的 eBPF 程序开发工具集，提供完整的交叉编译环境、依赖库以及 12 个涵盖不同 eBPF 程序类型的实战示例。

## 目录结构

```
arm64_lib/
├── lib/                          # 预编译的 ARM64 依赖库
│   ├── libbpf.so / libbpf.a      #   libbpf
│   ├── libelf.so / libelf.a      #   libelf (elfutils)
│   ├── libz.so / libz.a          #   zlib
│   └── libblazesym_c.so / .a     #   blazesym 符号化库
├── libbpf/                       # libbpf 源码与安装
├── blazesym/                     # blazesym 符号化库 (C API)
├── vmlinux                       # ARM64 内核 vmlinux 镜像 (用于生成 BTF)
├── bpf-example/                  # eBPF 示例程序集
│   ├── biopattern/               # 块设备 I/O 模式分析
│   ├── bpftrace/                 # CPU 性能采样 (火焰图)
│   ├── blazesym_src/             # 符号解析 API 封装库
│   ├── crash_trace/              # 进程崩溃追踪
│   ├── hide/                     # 隐藏进程 PID
│   ├── lsm-connect/              # LSM 安全连接控制
│   ├── memleak/                  # 内存泄漏检测
│   ├── profile/                  # 基于 Perf Event 的 CPU 性能分析
│   ├── socket-http/              # Socket 层 HTTP 流量过滤
│   ├── tc/                       # TC 流量控制
│   ├── tcpstates/                # TCP 连接状态追踪 & TCP RTT
│   ├── usdt/                     # 用户态静态探针 (USDT)
│   └── xdp/                      # XDP 数据路径
```

## 构建要求

### 宿主机环境

- **操作系统**: Linux
- **交叉编译工具链**: `aarch64-linux-gnu-gcc` (ARM64 交叉编译)
- **Clang/LLVM**: 用于编译 BPF 字节码 (`clang -target bpf`)
- **bpftool**: 用于生成 BPF skeleton 头文件和导出 vmlinux.h
- **GNU Make**: 构建系统

### 依赖库路径

所有依赖库统一放置在 `/home/jin/arm64_lib/lib/` 目录下：

| 库 | 用途 |
|---|---|
| `libbpf` | eBPF 程序加载与管理的核心库 |
| `libelf` (elfutils) | ELF 文件解析 |
| `libz` (zlib) | 压缩支持 |
| `libblazesym_c` | 地址符号化 (将地址转为函数名/源码行号) |

## 快速开始

### 1. 编译单个示例

进入任意子目录，执行 `make`：

```bash
cd bpf-example/memleak
make
```

构建产物：
- `<name>.bpf.o` — eBPF 字节码文件
- `<name>.skel.h` — bpftool 生成的 skeleton 头文件
- `<name>` — ARM64 可执行文件

### 2. 部署到 ARM64 目标机

将编译产物拷贝到 ARM64 目标机器上运行：

```bash
# 拷贝依赖库
scp lib/*.so target:/usr/lib/

# 拷贝可执行文件与 BPF 字节码
scp bpf-example/memleak/memleak target:/tmp/
scp bpf-example/memleak/memleak.bpf.o target:/tmp/

# 在目标机上运行 (需要 root 权限)
/tmp/memleak -p $(pidof target_app)
```

## eBPF 示例项目总览

| 文件夹 | 程序类型 | Map 类型 | 核心 eBPF 能力 |
|---|---|---|---|
| `biopattern` | tracepoint | HASH | CO-RE 内核结构体读取, 原子操作 |
| `bpftrace` | perf_event | STACK_TRACE, HASH | 栈追踪, 火焰图生成 |
| `crash_trace` | tracepoint | RINGBUF | 栈追踪, 内核内存读取, 信号捕获 |
| `hide` | tracepoint (syscall) | HASH, PROG_ARRAY, RINGBUF | tail call, 用户态内存读写 |
| `lsm-connect` | LSM | (无) | LSM 安全策略钩子 |
| `memleak` | uprobe/uretprobe | HASH, STACK_TRACE | 用户态函数挂载, CO-RE, 内存泄漏追踪 |
| `profile` | perf_event | RINGBUF | 栈追踪, 内核内存读取, 符号化 |
| `socket-http` | socket | RINGBUF | skb 数据读取, HTTP 协议解析 |
| `tc` | TC | (无) | 直接包解析 (DPA) |
| `tcpstates` | tracepoint, fentry | HASH, PERF_EVENT_ARRAY | fentry trampoline, CO-RE, RTT 直方图 |
| `usdt` | USDT | HASH, RINGBUF | 用户态静态探针参数读取 |
| `xdp` | XDP | (无) | 网卡驱动层最早数据路径处理 |

**共涉及 8 种 BPF 程序类型**: tracepoint, perf_event, uprobe/uretprobe, socket, TC, XDP, LSM, fentry, USDT

**共涉及 5 种 Map 类型**: HASH, RINGBUF, STACK_TRACE, PERF_EVENT_ARRAY, PROG_ARRAY

## blazesym_src — 符号解析 API

`blazesym_src/` 目录封装了 [blazesym](https://github.com/libbpf/blazesym) 符号化库，提供了一站式符号解析 API：

- **`resolve_symbols()`** — 解析用户态地址到函数名、模块路径、源码行号
- **`resolve_kernel_symbols()`** — 解析内核态地址到内核函数名

主要用于 `profile`、`bpftrace`、`crash_trace` 等需要将调用栈地址转换为可读符号的项目。

## 各子项目 Makefile 说明

每个子项目 Makefile 遵循统一的构建模式：

1. **BPF 字节码编译**: 使用 `clang -target bpf` 将 `.bpf.c` 编译为 `.bpf.o`，然后用 `llvm-strip -g` 去除调试信息
2. **Skeleton 生成**: 使用 `bpftool gen skeleton` 将 `.bpf.o` 生成 `.skel.h` 头文件
3. **用户态程序编译**: 使用 `aarch64-linux-gnu-gcc` 交叉编译 `.c` 用户态加载程序

部分项目（如 `profile`、`bpftrace`）同时提供 `Makefile_x86` 用于 x86_64 本地编译调试。

## 调试与问题排查

### 查看 BPF 日志

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## 参考资料

- [libbpf](https://github.com/libbpf/libbpf) — BPF CO-RE 用户态加载库
- [blazesym](https://github.com/libbpf/blazesym) — 地址符号化库
- [eBPF 官方文档](https://ebpf.io/)
- [BPF CO-RE 参考指南](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [bpf-developer-tutorial].(https://github.com/eunomia-bpf/bpf-developer-tutorial)


