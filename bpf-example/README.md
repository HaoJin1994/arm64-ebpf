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

### 13. `sockops` — Socket 操作拦截与消息重定向

sockops 项目演示了如何使用 **sockmap/sockhash** 机制实现 TCP 连接追踪和 socket 级别的消息重定向。包含两个 BPF 程序：

#### `bpf_contrack.bpf.c` — 连接追踪

| 知识点 | 说明 |
|---|---|
| **SEC("sockops")** | `BPF_PROG_TYPE_SOCK_OPS` — 挂载到 cgroup，监控该 cgroup 内所有 socket 操作事件 |
| **`bpf_program__attach_cgroup`** | 用户态将 sockops 程序附加到 **cgroup v2**，cgroup 定义监控范围 |
| **`struct bpf_sock_ops`** | sockops 上下文，包含 `family`, `op`, `remote_ip4`, `local_ip4`, `remote_port`, `local_port` 等字段 |
| **`BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`** | 被动连接建立事件（服务端 accept） |
| **`BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`** | 主动连接建立事件（客户端 connect） |
| **`BPF_MAP_TYPE_SOCKHASH`** | sockhash 类型的 map，key 为自定义五元组 `struct sock_key`，value 为 socket 引用 |
| **`bpf_sock_hash_update`** | 将新建立的 TCP 连接信息写入 sockhash map，`BPF_NOEXIST` 标志防止覆盖 |
| **`bpf_htonl` / `bpf_ntohl`** | BPF 内置网络字节序转换函数 |
| **`bpf_printk`** | 调试日志输出到 `/sys/kernel/debug/tracing/trace_pipe` |

#### `bpf_redirect.bpf.c` — 消息重定向

| 知识点 | 说明 |
|---|---|
| **SEC("sk_msg")** | `BPF_PROG_TYPE_SK_MSG` — 当消息发送到 sockhash map 中的 socket 时触发 |
| **`bpf_prog_attach`** + `BPF_SK_MSG_VERDICT` | 用户态将 sk_msg 程序附加到 sockhash map fd 上（libbpf 无高层 API，需用底层 syscall 封装） |
| **`bpf_prog_detach2`** | 对应 `bpf_prog_attach` 的 detach 操作 |
| **`struct sk_msg_md`** | sk_msg 上下文，包含 `remote_ip4`, `local_ip4`, `remote_port`, `local_port`, `family` 等 |
| **`bpf_msg_redirect_hash`** | 将消息重定向到 sockhash map 中匹配 key 的目标 socket，`BPF_F_INGRESS` 标志表示走 ingress 路径 |
| **`SK_PASS`** | 返回值：放行消息，不做重定向 |

#### 用户态程序 `sockops_exp.c`

| 知识点 | 说明 |
|---|---|
| **`bpf_map__reuse_fd`** | 同一进程内两个 BPF 对象共享同一个 sockhash map（sockops 写入，sk_msg 读取） |
| **多 skeleton 加载** | 同时加载两个独立的 BPF 对象（`bpf_contrack_bpf` + `bpf_redirect_bpf`），分别管理 |

#### 架构流程

---

### 14. `funclatency` — 函数延迟直方图统计

funclatency 项目用于测量指定内核函数或用户态函数的执行延迟，并以 log2 直方图的形式输出统计结果。支持 kprobe（内核函数）和 uprobe（用户态函数）两种挂载方式。

#### `funclatency.bpf.c`

| 知识点 | 说明 |
|---|---|
| **kprobe / kretprobe** | `SEC("kprobe/dummy_kprobe")` + `SEC("kretprobe/dummy_kretprobe")` — 通过 `bpf_program__attach_kprobe` 在运行时动态附加到目标内核函数 |
| **uprobe / uretprobe** | 用户态通过 `bpf_program__attach_uprobe_opts` 动态附加到用户态函数，支持 PID 过滤 |
| **`BPF_KPROBE` / `BPF_KRETPROBE`** | 宏简化 kprobe/kretprobe 的参数获取和返回值获取 |
| **`bpf_ktime_get_ns`** | 获取纳秒时间戳，在 entry 记录起始时间，在 exit 计算函数耗时 |
| **BPF_MAP_TYPE_HASH** | `starts` map：以 PID 为 key 存储函数入口时间戳，关联 entry 和 exit 两次触发 |
| **`bpf_map_update_elem`** | 在 entry 中将当前 PID 和起始时间写入 map |
| **`bpf_map_lookup_elem`** | 在 exit 中查找 entry 记录的起始时间 |
| **`__sync_fetch_and_add`** | 原子操作，无锁累加直方图槽位计数（支持并发更新） |
| **全局数组 `hist`** | `__u32 hist[MAX_SLOTS]` — BPF 全局数组作为直方图存储，从 bss 段直接读取 |
| **`log2l` 对数分桶** | 使用 `bits.bpf.h` 中的高效 log2 算法，将纳秒级延迟映射到 2 的幂次桶 |
| **`const volatile` 配置** | `targ_tgid` 和 `units` 作为可配置参数，从用户态通过 rodata 段设置 |

#### 用户态程序 `funclatency.c`

| 知识点 | 说明 |
|---|---|
| **`bpf_program__attach_kprobe`** | 动态附加 kprobe/kretprobe 到指定内核函数（第二参数 `retprobe` 区分入口/返回） |
| **`bpf_program__attach_uprobe_opts`** | 动态附加 uprobe/uretprobe 到用户态二进制，通过 `bpf_uprobe_opts` 指定函数名 |
| **`LIBBPF_OPTS`** | 宏初始化 `bpf_object_open_opts`，使用默认选项打开 BPF 对象 |
| **rodata 段写入** | `obj->rodata->units` 和 `obj->rodata->targ_tgid` 在加载前写入用户配置 |
| **bss 段读取** | `obj->bss->hist` 直接从 BPF 全局数组读取直方图数据（Linux 5.7+ 支持） |
| **log2 直方图打印** | `print_log2_hist` 按 2 的幂次区间输出分布，用星号 `*` 可视化频率 |
| **SIGINT 信号处理** | 通过 `sigaction` 注册信号处理器，实现优雅退出 |
| **argp 参数解析** | 使用 GNU argp 库解析命令行参数（`-m` 毫秒、`-u` 微秒、`-p` PID、`-d` 时长、`-i` 间隔） |

---

### 15. `tcx` — TCX (Traffic Control eXpress) 入口/出口流量处理

TCX 是 Linux 6.6+ 引入的新型 BPF 挂载点，替代旧的 TC BPF。支持多个程序按序链式执行，通过 `BPF_F_BEFORE`/`BPF_F_AFTER` 控制排序。

#### `tcx_demo.bpf.c`

| 知识点 | 说明 |
|---|---|
| **SEC("tcx/ingress")** | `BPF_PROG_TYPE_TCX` — 挂载到网卡 ingress 路径，比 TC clsact 更轻量 |
| **`struct __sk_buff`** | TCX 层的包上下文，包含 `data`, `data_end`, `len`, `protocol`, `ifindex` 等字段 |
| **直接包解析 (DPA)** | 通过 `data`/`data_end` 指针直接解析以太网头、IP 头、UDP 头 |
| **边界检查** | 逐层检查 `(void *)(hdr + 1) > data_end`，确保内存访问安全 |
| **`TCX_NEXT`** | 返回值 -1：将数据包传递给链中下一个 TCX 程序 |
| **`TCX_PASS`** | 返回值 0：终止链，放行数据包到内核网络栈 |
| **全局变量 (bss 段)** | `stats_hits`, `classifier_hits`, `last_len` 等 — 用户态可读写，用于统计和调试 |
| **`bpf_ntohs` / `bpf_htons`** | BPF 内置网络字节序转换 |

#### 用户态程序 `tcx_demo.c`

| 知识点 | 说明 |
|---|---|
| **`bpf_program__attach_tcx`** | libbpf 高层 API 附加 TCX 程序到指定网卡 ifindex |
| **`BPF_F_BEFORE`** | 通过 `bpf_tcx_opts` 指定程序插入到链中某个程序之前，实现多程序编排 |
| **`bpf_prog_query_opts`** | 查询网卡上已附加的 BPF 程序链（需 `BPF_TCX_INGRESS` 枚举值） |
| **`prog_cnt`** | 输入+输出参数：输入时设置最大查询数量，输出时返回实际附加的程序数 |
| **`LIBBPF_OPTS`** | 宏初始化 `bpf_prog_query_opts` 和 `bpf_tcx_opts` 结构体 |

---

### 16. `kfuncs-eg` — BPF kfunc 内核函数注册与调用

kfuncs-eg 演示如何编写内核模块注册自定义 BPF kfunc（内核函数），让 BPF 程序安全调用内核函数。

#### 内核模块 `bpf_memcpy_kfunc.c`

| 知识点 | 说明 |
|---|---|
| **`__bpf_kfunc`** | 标记函数为 BPF kfunc，使其可被 BPF 程序调用 |
| **`__bpf_kfunc_start_defs` / `__bpf_kfunc_end_defs`** | 包裹 kfunc 定义区域，用于 BTF 识别 |
| **`__sz` 后缀约定** | 参数名 `dst__sz` 中的 `__sz` 后缀告诉 BPF 验证器该参数是对应指针的缓冲区大小，用于自动边界检查 |
| **`BTF_KFUNCS_START` / `BTF_KFUNCS_END`** | 定义 kfunc ID 集合，将 kfunc 注册到 BTF |
| **`BTF_ID_FLAGS(func, ...)`** | 将函数添加到 kfunc ID 集合 |
| **`register_btf_kfunc_id_set`** | 注册 kfunc 到指定程序类型（如 `BPF_PROG_TYPE_KPROBE`, `BPF_PROG_TYPE_TRACING`） |
| **内核模块** | kfunc 必须以内核模块形式加载，通过 `insmod` 安装 |

#### BPF 程序 `memcpy_test.bpf.c`

| 知识点 | 说明 |
|---|---|
| **`__ksym`** | 声明外部内核符号，告诉 BPF 加载器该函数由内核模块提供 |
| **`extern int bpf_memcpy(...) __ksym`** | 声明 kfunc 原型，使 BPF 程序可以调用它 |

---

### 17. `tcp-status` — TCP 连接状态迭代器

使用 BPF iterator 遍历内核中所有 TCP socket，按目标地址/端口/状态过滤并输出连接信息。

#### `tcp_status.bpf.c`

| 知识点 | 说明 |
|---|---|
| **SEC("iter/tcp")** | `BPF_PROG_TYPE_TRACING` + `BPF_ITER_TCP` — 迭代内核所有 TCP socket |
| **`struct bpf_iter__tcp`** | BPF iterator 上下文，包含 `sk_common`（`sock_common` 指针）和 `meta->seq`（seq_file 输出） |
| **`BPF_CORE_READ`** | CO-RE 方式安全读取内核结构体字段（`skc_family`, `skc_state`, `skc_daddr` 等） |
| **`BPF_SEQ_PRINTF`** | 向 `seq_file` 输出格式化字符串，用户态通过 `cat /sys/kernel/bpf/` 读取 |
| **`BPF_SNPRINTF`** | 格式化字符串到缓冲区，`%pI4` 格式化 IPv4 地址 |
| **`const volatile` 过滤参数** | `target_addr`, `target_port`, `target_state` 作为可配置过滤条件 |
| **全局统计结构体** | `struct tcp_status_stats` 记录扫描数、匹配数、销毁数等 |

#### 用户态程序 `tcp_status.c`

| 知识点 | 说明 |
|---|---|
| **BPF iterator 链接** | 通过 `bpf_link__open` 方式附加 iterator 程序，自动创建 `/sys/kernel/bpf/` 下的伪文件 |
| **`bpf_link__pin`** | 将 iterator 链接持久化到 BPF 文件系统，供 `cat` 读取 |
| **`bpf_object__pin`** | 将 BPF 对象和 map 持久化到文件系统 |
| **rodata 段写入** | 加载前通过 `skel->rodata->target_addr` 写入过滤参数 |
| **getopt_long 参数解析** | 使用 `getopt_long` 解析 `--destination`, `--port`, `--apply` 等参数 |