#!/usr/bin/python3
from __future__ import print_function
from bcc import BPF, USDT
import sys, builtins, time
from curses import wrapper, curs_set 

if len(sys.argv) < 2:
    print("Usage: " + sys.argv[0] + " <pid to instrument")
    exit()

pid = int(sys.argv[1])

text = """
#include <linux/ptrace.h>

BPF_HASH(reads);
BPF_HASH(writes);

BPF_HISTOGRAM(read_out);
BPF_HISTOGRAM(write_out);

#define READ_CMD 1
#define WRITE_CMD 2

int command_start(struct pt_regs *ctx) {
    u64 ts;
    ts = bpf_ktime_get_ns();

    u64 opCtx;
    bpf_usdt_readarg(4, ctx, &opCtx);

    int type;
    bpf_usdt_readarg(3, ctx, &type);
    // type is a value of Command::ReadWriteType
    switch(type) {
        case READ_CMD:
            reads.update(&opCtx, &ts);
            break;
        case WRITE_CMD:
            writes.update(&opCtx, &ts);
            break;
        default:
            break;
    }
    return 0;
}

int command_end(struct pt_regs *ctx) {
    u64 ts, *start = NULL;
    ts = bpf_ktime_get_ns();

    u64 opCtx;
    bpf_usdt_readarg(4, ctx, &opCtx);

    int type;
    bpf_usdt_readarg(3, ctx, &type);
    // type is a value of Command::ReadWriteType
    switch(type) {
        case READ_CMD:
            start = reads.lookup(&opCtx);
            break;
        case WRITE_CMD:
            start = writes.lookup(&opCtx);
            break;
        default:
            break;
    }
    if(start) {
        u64 delta = ts - *start;
        delta = delta / 1000000; //convert from ns to ms
        switch(type) {
            case READ_CMD:
                read_out.increment(delta);
                break;
            case WRITE_CMD:
                write_out.increment(delta);
                break;
            default:
                break;
        }
    }
    return 0;
}
"""

command_start = USDT(pid=pid)
command_start.enable_probe(probe="commandStart", fn_name="command_start")
command_end = USDT(pid=pid)
command_end.enable_probe(probe="commandEnd", fn_name="command_end")

b = BPF(text=text, usdt_contexts=[command_start, command_end])

def main():
    try:
        print("Read time histogram:")
        b["read_out"].print_linear_hist("Elapsed time in ms")
        print("Write time histogram:")
        b["write_out"].print_linear_hist("Elapsed time in ms")
    except KeyboardInterrupt:
        exit()

if __name__ == "__main__":
    print("recording data...hit Ctrl-C to stop and print histogram")
    try:
        time.sleep(100000000)
    except KeyboardInterrupt:
        main()
