#!/usr/bin/python3
from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("Need to pass along pid")
    exit()

text = """
#include <linux/ptrace.h>
struct timing_t {
    char buf[256];
    u64 delta;
};

BPF_HASH(invoc_times, const void*);
BPF_PERF_OUTPUT(timings);

int start_command(struct pt_regs *ctx) {
    u64 ts = bpf_ktime_get_ns();
    const void* opCtx = NULL;
    bpf_usdt_readarg(4, ctx, &opCtx);
    if(opCtx)
        invoc_times.update(&opCtx, &ts);
    return 0;
}

int end_command(struct pt_regs *ctx) {
    u64 ts, *tsp, delta;
    const void* opCtx = NULL;
    bpf_usdt_readarg(4, ctx, &opCtx);
    tsp = invoc_times.lookup(&opCtx);
    if(tsp) {
        delta = bpf_ktime_get_ns() - *tsp;
        char* name;
        bpf_usdt_readarg(2, ctx, &name);
        struct timing_t result;
        result.delta = delta;
        bpf_probe_read(&result.buf, sizeof(result.buf), name);
        timings.perf_submit(ctx, &result, sizeof(result));
        invoc_times.delete(&opCtx);
    }
    return 0;
}
"""
print(text)
pid = sys.argv[1]

print(int(pid))
pid = int(pid)
time_start = USDT(pid=pid)
time_start.enable_probe(probe="commandStart", fn_name="start_command")
time_end = USDT(pid=pid)
time_end.enable_probe(probe="commandEnd", fn_name="end_command")

b = BPF(text=text, usdt_contexts=[time_start, time_end])

def print_command(cpu, data, size):
    event = b["timings"].event(data)
    name = str(event.buf, 'utf-8')
    print('{}\t{}'.format(name, event.delta))

b["timings"].open_perf_buffer(print_command)
print("Commands and length of completion in ns:")
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
