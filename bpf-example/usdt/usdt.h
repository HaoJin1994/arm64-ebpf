#ifndef USDT_H
#define USDT_H

struct usdt_data {
    __u64 pid;
    __u64 tid;
    __u64 arg1;
    __u64 arg2;
    __u64 ret;
};

#endif