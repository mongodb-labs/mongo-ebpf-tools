#!/usr/bin/python3
import sys
import errno
import ctypes as ct
from bcc import BPF, USDT

if len(sys.argv) == 1:
    print("ERROR: need a pid to instrument")
    exit(1)

pid = int(sys.argv[1])

text = """
#include <linux/ptrace.h>
#include <linux/futex.h>
#include <linux/sched.h> /* For TASK_COMM_LEN */

BPF_HASH(tid_to_start, u32);
BPF_HASH(tid_to_stackid, u32, int);
BPF_STACK_TRACE(stacks, 1024);//will spit back stack ids and store the stack trace

BPF_PERF_OUTPUT(futex_out);
struct futex_out_struct {
    char comm[2*TASK_COMM_LEN];
    u64 nanoseconds;
    int stack_id;
    u32 tgid;
    u32 pid;
};

int stdx_mutex_entry(struct pt_regs *ctx) {
    int stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);
    u32 tid = bpf_get_current_pid_tgid();
    tid_to_stackid.insert(&tid, &stack_id);
    return 0;
}

int stdx_mutex_exit(struct pt_regs *ctx) {
    // if this is hit and the start time has not been removed, then the stack will not be read
    u32 tid = bpf_get_current_pid_tgid();
    u64 *start = tid_to_start.lookup(&tid);
    if(start) {
        int* stackid = tid_to_stackid.lookup(&tid);
        if(stackid) {
            tid_to_stackid.delete(&tid);
        }
        tid_to_start.delete(&tid);
    }
    return 0;
}

int syscall__futex(struct pt_regs* ctx, int* uaddr, int futex_op) {
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_tid >> 32;
    u32 tid = pid_tid;
    if(pid != %PID%) return 0; //filter on pid
    if((futex_op & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)) != FUTEX_WAIT) return 0;
    u64 start = bpf_ktime_get_ns();
    tid_to_start.insert(&tid, &start);
    return 0;
}

int syscall__futex_ret(struct pt_regs* ctx, int* uaddr, int futex_op) {
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_tid >> 32;
    u32 tid = pid_tid;
    if(pid != %PID%) return 0; //filter on pid
    u64 *start = tid_to_start.lookup(&tid);
    if(!start) return 0;
    u64 now = bpf_ktime_get_ns();
    tid_to_start.delete(&tid);

    int* stack_idp = tid_to_stackid.lookup(&tid);
    if(!stack_idp) return 0;
    tid_to_stackid.delete(&tid);

    struct futex_out_struct out = {};
    bpf_get_current_comm(&out.comm, sizeof(out.comm));
    out.nanoseconds = now - *start;
    out.stack_id = *stack_idp;
    out.tgid = tid;
    out.pid = pid;
    futex_out.perf_submit(ctx, &out, sizeof(out));
    return 0;
}

""".replace("%PID%", str(pid))
mutex_enter = USDT(pid=pid)
mutex_enter.enable_probe(probe="lock_enter", fn_name="stdx_mutex_entry")

mutex_exit = USDT(pid=pid)
mutex_exit.enable_probe(probe="lock_exit", fn_name="stdx_mutex_exit")

b = BPF(text=text, usdt_contexts=[mutex_enter, mutex_exit])
futex_fnname = b.get_syscall_fnname("futex")
b.attach_kprobe(event=futex_fnname, fn_name="syscall__futex")
b.attach_kretprobe(event=futex_fnname, fn_name="syscall__futex_ret")

NUM_BACKTRACES = 10
backtraces = [(-1, [''])] * NUM_BACKTRACES

OUTPUT_CHANNEL = 'futex_out'

out_of_mem = False


def walk_backtrace(stack_traces, event):
    missed_stack = False
    global out_of_mem
    if event.stack_id < 0 and event.stack_id != -errno.EFAULT:
        missed_stack = True
        out_of_mem = out_of_mem or event.stack_id == -errno.ENOMEM

    line = [event.comm.decode('utf-8', 'replace')]  # start the line with what COMM it is
    try:
        user_stack = list(stack_traces.walk(event.stack_id))
    except KeyError:
        missed_stack = True
    if missed_stack:
        line.append("[Missed User Stack]")
    else:
        line.extend(
            [b.sym(addr, event.tgid).decode('utf-8', 'replace') for addr in reversed(user_stack)])
    return line


def record_backtrace(cpu, data, size):
    event = b[OUTPUT_CHANNEL].event(data)
    time_delta = event.nanoseconds
    stack_traces = b['stacks']
    for i in range(NUM_BACKTRACES):
        if backtraces[i][0] == -1 or backtraces[i][0] < time_delta:
            bt = walk_backtrace(stack_traces, event)
            backtraces.insert(i, (time_delta, bt))
            backtraces.pop()
            return


b[OUTPUT_CHANNEL].open_perf_buffer(record_backtrace)

print("listening...")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        for time, backtrace in backtraces:
            print("TIME: ", time)
            print("BT: ", '\n'.join(backtrace))
        exit()
