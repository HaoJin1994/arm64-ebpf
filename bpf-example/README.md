
## bpf-example 各子项目 eBPF 知识点总结

---

### 1. `biopattern` — 块设备 I/O 模式分析

| 知识点 | 说明 |
|---|---|
| **Tracepoint** | `SEC("tracepoint/block/block_rq_complete")` — 挂载到块设备请求完成事件 |
| **BPF_CORE_READ** | CO-RE 方式读取内核结构体字段，跨内核版本兼容 |
| **BPF_MAP_TYPE_HASH** | 按设备号(dev)为 key 统计顺序/随机 I/O 计数 |
| **`bpf_map_lookup_or_try_init`** | 封装宏，查找或初始化 map 元素 |
| **`__sync_fetch_and_add`** | 原子操作，无锁累加计数器 |
| **`bpf_core_type_exists`** | 运行时判断内核类型是否存在，实现 CO-RE 兼容 |
| **`preserve_access_index`** | 保留结构体字段偏移信息供 CO-RE 重定位 |

---

### 2. `bpftrace` — CPU 性能采样（火焰图）

| 知识点 | 说明 |
|---|---|
| **Perf Event** | `SEC("perf_event")` — 基于 PMU 硬件计数器按频率采样 |
| **BPF_MAP_TYPE_STACK_TRACE** | 专门的栈追踪 map，存储用户态/内核态调用栈 |
| **`bpf_get_stackid`** | 获取栈 ID（去重），`BPF_F_USER_STACK` 获取用户栈 |
| **BPF_MAP_TYPE_HASH** | 统计 `{ustack_id, kstack_id}` → 计数，用于火焰图折叠 |
| **全局变量 volatile const** | `target_tgid` 作为可配置的过滤参数（从用户态设置） |

---

### 3. `crash_trace` — 进程崩溃追踪

| 知识点 | 说明 |
|---|---|
| **Tracepoint** | `SEC("tracepoint/signal/signal_generate")` — 挂载信号产生事件 |
| **BPF_MAP_TYPE_RINGBUF** | Ring Buffer 高效传递崩溃事件到用户态 |
| **`bpf_ringbuf_reserve` / `bpf_ringbuf_submit`** | Ring Buffer 的预留/提交模式 |
| **`bpf_get_stack`** | 获取完整调用栈（用户栈 + 内核栈），`BPF_F_USER_STACK` 标志 |
| **`bpf_probe_read_kernel`** | 安全读取内核内存（`task_struct` → `mm` → `start_code`） |
| **`bpf_get_current_task`** | 获取当前 `task_struct` 指针 |
| **`bpf_get_current_pid_tgid`** | 获取 PID/TID |
| **`bpf_get_current_comm`** | 获取进程名 |

---

### 4. `hide` (pidhide) — 隐藏进程 PID

| 知识点 | 说明 |
|---|---|
| **Tracepoint (syscall)** | `SEC("tp/syscalls/sys_enter_getdents64")` + `sys_exit_getdents64` — 拦截 `getdents64` 系统调用 |
| **BPF_MAP_TYPE_PROG_ARRAY** | 程序数组，配合 `bpf_tail_call` 实现尾调用 |
| **`bpf_tail_call`** | 尾调用跳转，在 `handle_getdents_exit` 中循环遍历目录项 |
| **`bpf_probe_read_user`** | 读取用户态内存（读 `linux_dirent64` 结构体） |
| **`bpf_probe_write_user`** | **写入用户态内存**，修改 `d_reclen` 跳过目标 PID 目录 |
| **BPF_MAP_TYPE_RINGBUF** | 传递隐藏操作结果事件到用户态 |
| **`BPF_CORE_READ`** | 读取 `task_struct → real_parent → tgid` 获取父进程 PID |

---

### 5. `lsm-connect` — LSM 安全连接控制

| 知识点 | 说明 |
|---|---|
| **LSM BPF** | `SEC("lsm/socket_connect")` — 挂载到 Linux LSM (Linux Security Module) 钩子 |
| **BPF_PROG 宏** | 声明式的 BPF 程序参数绑定，自动解包 `struct socket`, `struct sockaddr` 等 |
| **返回值控制** | 返回 `-EPERM` 拒绝连接，返回 `0` 放行 |
| **`bpf_printk`** | 调试日志输出到 `/sys/kernel/debug/tracing/trace_pipe` |

---

### 6. `memleak` — 内存泄漏检测

| 知识点 | 说明 |
|---|---|
| **uprobe / uretprobe** | `SEC("uprobe")` + `SEC("uretprobe")` — 用户态函数挂载（malloc/free/calloc/realloc/mmap/munmap 等） |
| **BPF_KPROBE / BPF_KRETPROBE** | 宏简化 uprobe/uretprobe 的参数获取和返回值获取 |
| **`PT_REGS_RC`** | 从 `pt_regs` 中提取函数返回值 |
| **BPF_MAP_TYPE_STACK_TRACE** | 存储分配栈，关联每次内存分配 |
| **`bpf_get_stackid`** | 获取分配时的调用栈 ID |
| **BPF_MAP_TYPE_HASH** | 多重 map：`sizes`(暂存 size)、`allocs`(地址→分配信息)、`combined_allocs`(栈→统计) |
| **`__sync_fetch_and_add` / `__sync_fetch_and_sub`** | 原子加/减，无锁更新统计信息 |
| **`bpf_ktime_get_ns`** | 获取纳秒时间戳，用于采样率控制和记录分配时间 |
| **`bpf_probe_read_user`** | 读取用户态内存（如 `posix_memalign` 的间接指针） |
| **CO-RE 兼容** | `bpf_core_type_exists` 检测内核版本差异，兼容不同 `kmem_alloc` tracepoint |
| **`bpf_map_delete_elem`** | 清理已完成追踪的分配记录 |

---

### 7. `profile` — 基于 Perf Event 的 CPU 性能分析

| 知识点 | 说明 |
|---|---|
| **Perf Event** | `SEC("perf_event")` — 同 bpftrace，基于 PMU 采样 |
| **BPF_MAP_TYPE_RINGBUF** | 传递采样事件（含栈信息）到用户态 |
| **`bpf_get_stack`** | 获取完整调用栈（用户栈 + 内核栈） |
| **`bpf_probe_read_kernel`** | 读取 `task_struct → mm → start_code` 获取进程加载基址 |
| **`bpf_get_smp_processor_id`** | 获取当前 CPU ID |
| **`bpf_get_current_comm`** | 获取进程命令名 |

---

### 8. `socket-http` — Socket 层 HTTP 流量过滤

| 知识点 | 说明 |
|---|---|
| **Socket Filter** | `SEC("socket")` — 挂载到 socket 上，使用 `struct __sk_buff` 上下文 |
| **`bpf_skb_load_bytes`** | 从 skb 中安全读取指定偏移量的数据（解析以太网/IP/TCP/HTTP 头） |
| **`__bpf_ntohs` / `bpf_htons`** | 网络字节序转换（BPF 内置函数） |
| **`bpf_strncmp`** | 字符串前缀比较，识别 HTTP 方法（GET/POST/PUT/DELETE/HTTP） |
| **BPF_MAP_TYPE_RINGBUF** | 传递 HTTP 请求事件到用户态 |
| **`bpf_ringbuf_reserve` / `bpf_ringbuf_submit`** | Ring Buffer 预留/提交 |

---

### 9. `tc` — TC 流量控制

| 知识点 | 说明 |
|---|---|
| **TC (Traffic Control)** | `SEC("tc")` — 挂载到 Linux TC 子系统（ingress/egress 钩子） |
| **`struct __sk_buff`** | TC 层的包上下文，包含 `data`, `data_end`, `protocol` 等 |
| **直接包解析 (Direct Packet Access)** | 通过 `data`/`data_end` 指针直接解析以太网头和 IP 头 |
| **边界检查** | `l2 + 1 > data_end` 等检查，确保内存访问安全（eBPF verifier 要求） |
| **`bpf_ntohs`** | 网络字节序转换 |

---

### 10. `tcpstates` — TCP 连接状态追踪 & TCP RTT

#### `tcpstates.bpf.c`

| 知识点 | 说明 |
|---|---|
| **Tracepoint** | `SEC("tracepoint/sock/inet_sock_set_state")` — 挂载 TCP 状态变更事件 |
| **BPF_MAP_TYPE_HASH** | 多张 map：`sports`/`dports`(端口过滤)、`timestamps`(sock→时间戳) |
| **BPF_MAP_TYPE_PERF_EVENT_ARRAY** | 通过 `bpf_perf_event_output` 将事件发送到用户态 |
| **`bpf_perf_event_output`** | 高性能事件输出（传统方式，对比 ring buffer） |
| **`bpf_ktime_get_ns`** | 计算状态持续时长 (delta_us) |
| **`bpf_probe_read_kernel`** | 读取 `sock` 结构体中的源/目标 IP 地址 |
| **`bpf_get_current_pid_tgid`** | 获取触发状态变更的进程 PID |

#### `tcprtt.bpf.c`

| 知识点 | 说明 |
|---|---|
| **fentry** | `SEC("fentry/tcp_rcv_established")` — 挂载到内核函数入口（trampoline 方式，比 kprobe 更高效） |
| **BPF_PROG 宏** | 声明式参数绑定，直接解包 `struct sock *sk` |
| **BPF_CORE_READ** | CO-RE 方式读取 `inet_sock`, `tcp_sock` 中的 SRTT (平滑 RTT) |
| **`log2l`** | log2 计算，用于直方图分桶 |
| **`__sync_fetch_and_add`** | 原子累加直方图槽位计数 |
| **`bpf_map_lookup_or_try_init`** | 查找或初始化直方图 |

---

### 11. `usdt` — 用户态静态探针

| 知识点 | 说明 |
|---|---|
| **USDT** | `SEC("usdt")` — 挂载到用户态 ELF 中的 USDT 探针点 |
| **`bpf_usdt_arg_cnt`** | 获取 USDT 探针参数个数 |
| **`bpf_usdt_arg`** | 读取 USDT 探针参数值 |
| **BPF_MAP_TYPE_HASH** | `data_map` — 用 PID 关联 USDT start/end 探针对数据 |
| **BPF_MAP_TYPE_RINGBUF** | 传递 USDT 数据到用户态 |
| **`bpf_map_delete_elem`** | 在 end 探针中清理 start 探针存储的数据 |

---

### 12. `xdp` — XDP 数据路径

| 知识点 | 说明 |
|---|---|
| **XDP** | `SEC("xdp")` — 挂载到网卡驱动的最早数据路径 |
| **`struct xdp_md`** | XDP 上下文，包含 `data`, `data_end` 指针 |
| **直接包解析** | 通过 `data`/`data_end` 计算包大小 |
| **`XDP_PASS`** | 返回值：放行数据包（其他选项：`XDP_DROP`, `XDP_TX`, `XDP_REDIRECT`） |

---

## 总览表

| 文件夹 | 程序类型 | Map 类型 | 核心 eBPF 能力 |
|---|---|---|---|
| `biopattern` | tracepoint | HASH | CO-RE, 原子操作 |
| `bpftrace` | perf_event | STACK_TRACE, HASH | 栈追踪, 火焰图 |
| `crash_trace` | tracepoint | RINGBUF | 栈追踪, 内核内存读取 |
| `hide` | tracepoint(syscall) | HASH, PROG_ARRAY, RINGBUF | tail call, 用户内存读写 |
| `lsm-connect` | LSM | (无) | LSM 安全策略 |
| `memleak` | uprobe/uretprobe | HASH, STACK_TRACE | 用户态函数挂载, CO-RE |
| `profile` | perf_event | RINGBUF | 栈追踪, 内核内存读取 |
| `socket-http` | socket | RINGBUF | skb 数据读取, 字符串匹配 |
| `tc` | TC | (无) | 直接包解析 |
| `tcpstates` | tracepoint, fentry | HASH, PERF_EVENT_ARRAY | fentry, CO-RE, 直方图 |
| `usdt` | USDT | HASH, RINGBUF | USDT 探针参数读取 |
| `xdp` | XDP | (无) | 最早数据路径包处理 |

---

**共涉及 8 种 BPF 程序类型**：tracepoint, perf_event, uprobe/uretprobe, socket, TC, XDP, LSM, fentry, USDT

**共涉及 5 种 Map 类型**：HASH, RINGBUF, STACK_TRACE, PERF_EVENT_ARRAY, PROG_ARRAY

**核心技术栈**：CO-RE (BPF_CORE_READ / bpf_core_type_exists)、BPF skeleton (bpftool gen skeleton)、libbpf 用户态加载、blazesym 符号解析