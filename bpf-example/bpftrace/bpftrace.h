#ifndef __BPFTRACE_H_
#define __BPFTRACE_H_

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 127
#endif

struct key_t
{
    __u32 ustackid;
    __u32 kstackid;
};

#endif /* __BPFTRACE_H_ */
