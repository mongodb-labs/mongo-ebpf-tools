#!/usr/bin/python3
import sys
import os
from bcc import BPF, USDT
import ctypes as ct

pid = int(sys.argv[1])
text = """
#include <linux/ptrace.h>

BPF_PERF_OUTPUT(debug_info);
BPF_HASH(request, void*);

int start_request(struct pt_regs *ctx) {
    u64 ktime = bpf_ktime_get_ns();
    void* opCtx = NULL;
    bpf_usdt_readarg(1, ctx, &opCtx);
    if(opCtx) {
        request.insert(&opCtx, &ktime);
    }
    return 0;
}

struct debug_out {
    void* opCtx;
    bool isCommand;
    int32_t networkOp;
    char networkOpStr[15];
    char namespace[20];
    int error_code;
    int64_t elapsedMsExcludingPauses;
    bool usedDisk;
    bool hasSortStage;
    bool upsert;
    bool hasPlanCacheKey;
    char planSummary[100];
    u64 totalElapsedNs;
};

int end_request(struct pt_regs *ctx) {
    u64 ktime = bpf_ktime_get_ns();
    u64* old_ktime = NULL;
    void* opCtx = NULL;
    bpf_usdt_readarg(1, ctx, &opCtx);
    if(opCtx) {
        old_ktime = request.lookup(&opCtx);
    }
    struct debug_out out = {}; 
    bpf_usdt_readarg(1, ctx, &out.opCtx);
    bpf_usdt_readarg(2, ctx, &out.isCommand);
    bpf_usdt_readarg(3, ctx, &out.networkOp);
    const char* networkOpStrAddr = NULL;
    bpf_usdt_readarg(4, ctx, &networkOpStrAddr);
    bpf_probe_read_str(out.networkOpStr, sizeof(out.networkOpStr), networkOpStrAddr);
    const char* ns_addr = NULL;
    bpf_usdt_readarg(5, ctx, &ns_addr);
    if(ns_addr) {
        bpf_probe_read_str(out.namespace, sizeof(out.namespace), ns_addr);
    } else {
        out.namespace[0] = 0;
    }
    bpf_usdt_readarg(6, ctx, &out.error_code);
    bpf_usdt_readarg(7, ctx, &out.elapsedMsExcludingPauses);
    bpf_usdt_readarg(8, ctx, &out.usedDisk);
    bpf_usdt_readarg(9, ctx, &out.hasSortStage);
    bpf_usdt_readarg(10, ctx, &out.upsert);
    bpf_usdt_readarg(11, ctx, &out.hasPlanCacheKey);
    const char* planSummaryAddr = NULL;
    bpf_usdt_readarg(12, ctx, &planSummaryAddr);
    if(planSummaryAddr) {
        bpf_probe_read_str(out.planSummary, sizeof(out.planSummary), planSummaryAddr);
    } else {
        out.planSummary[0] = 0;
    }
    if(old_ktime) {
        out.totalElapsedNs = ktime - *old_ktime;
    } else {
        out.totalElapsedNs = 0;
    }
    debug_info.perf_submit(ctx, &out, sizeof(out));
    return 0;
}

BPF_PERF_OUTPUT(command_op_map);

struct command_op {
    char command_name[64];
    void* opCtx;
};

int start_command(struct pt_regs *ctx) {
    struct command_op out = {};
    const char* addr = NULL;
    bpf_usdt_readarg(2, ctx, &addr);
    bpf_probe_read_str(out.command_name, sizeof(out.command_name), addr);
    bpf_usdt_readarg(4, ctx, &out.opCtx);
    command_op_map.perf_submit(ctx, &out, sizeof(out));
    return 0;
}
"""
class DebugOut(ct.Structure):
    """ BCC usually autogenerates types like this based upon what type is submitted to PERF_OUTPUT. However, they only support a small subset of C types (e.g. they don't support bool), so this has to be manually defined """
    _fields_ = [
        ('opCtx', ct.c_voidp),
        ('isCommand', ct.c_bool),
        ('networkOp', ct.c_int),
        ('networkOpStr', ct.c_char * 15),
        ('namespace', ct.c_char * 20),
        ('error_code', ct.c_int32),
        ('elapsedMsExcludingPauses', ct.c_int64),
        ('usedDisk', ct.c_bool),
        ('hasSortStage', ct.c_bool),
        ('upsert', ct.c_bool),
        ('hasPlanCacheKey', ct.c_bool),
        ('planSummary', ct.c_char * 100),
        ('totalElapsedNs', ct.c_uint64)
            ]

    op_cmd_name = dict()

    def __str__(self):
        # look within dict for optional name instad of networkOpStr
        res = "{}:\n" \
              "--------------------------\n".format(
                      DebugOut.op_cmd_name.get(
                          self.opCtx, str(self.networkOpStr, 'utf-8')
                          )
                      )
        for name, _ in DebugOut._fields_:
            if name not in ('networkOpStr', 'opCtx'):
                res += '\t{}: {}'.format(name, getattr(self, name))
        return res

handle_request_start = USDT(pid=pid)
handle_request_start.enable_probe('handleRequestStart', 'start_request')

handle_request_end = USDT(pid=pid)
handle_request_end.enable_probe('handleRequestEnd', 'end_request')

start_command = USDT(pid=pid)
start_command.enable_probe('commandStart', 'start_command')

b = BPF(text=text, usdt_contexts=[handle_request_start, handle_request_end, start_command])

def print_info(cpu, data, size):
    assert size >= ct.sizeof(DebugOut)
    ct_cast =ct.cast(data, ct.POINTER(DebugOut))
    event = ct_cast.contents
    print(event)

def add_command_name(cpu, data, size):
    event = b['command_op_map'].event(data)
    DebugOut.op_cmd_name[event.opCtx] = str(event.command_name, 'utf-8')

b['debug_info'].open_perf_buffer(print_info)
b['command_op_map'].open_perf_buffer(add_command_name)

print("listening")

def is_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False

while is_alive(pid):
    try:
        b.perf_buffer_poll(timeout=1000)
    except KeyboardInterrupt:
        print("exiting")
        exit()
