#!/usr/bin/python3
import sys
from time import sleep
from bcc import BPF, USDT
ERROR_CODES = dict()
def error_code(msg, val, **kwargs):
    ERROR_CODES[val] = msg

def error_class(class_name, error_list):
    pass

# parse error_codes.err to interpret meaningful error codes
if len(sys.argv) != 3:
    print("Usage: " + sys.argv[0] + " <PID to instrument> <path to error_codes.err>")
    exit(1)

error_codes = open(sys.argv[2], "r").read()
exec(error_codes, globals(), locals())
ERROR_CODES[0] = "Unknown failure that doesn't throw"

text = """
#include <linux/ptrace.h>

BPF_PERF_OUTPUT(failed);
BPF_HISTOGRAM(error_hist, int, {NUM_ERR_CODES});

struct failed_out {{
    char name[50];
    int error_code;
}};

int command_failed(struct pt_regs *ctx) {{
    struct failed_out out = {{}};
    int err_code = 0;
    bpf_usdt_readarg(6, ctx, &err_code);
    error_hist.increment(err_code);
    const char* addr = NULL;
    bpf_usdt_readarg(2, ctx, &addr);
    bpf_probe_read_str(out.name, sizeof(out.name), addr);
    out.error_code = err_code;
    failed.perf_submit(ctx, &out, sizeof(out));
    return 0;
}}
""".format(NUM_ERR_CODES=len(ERROR_CODES))

command_failed = USDT(pid=int(sys.argv[1]))
command_failed.enable_probe(probe="commandFail", fn_name="command_failed")

b = BPF(text = text, usdt_contexts=[command_failed])

command_to_errors = dict()
def print_event(cpu, data, size):
    event = b["failed"].event(data)
    event_name = str(event.name, 'utf-8')
    if event_name not in command_to_errors:
        command_to_errors[event_name] = dict()
    if event.error_code not in command_to_errors[event_name]:
        command_to_errors[event_name][event.error_code] = 0
    command_to_errors[event_name][event.error_code] += 1

b["failed"].open_perf_buffer(print_event)

print('listening until CTRL-C....')
print("{:<30} | Occurrences".format("Commands"))
print('-' * 30, '|', '-' * 13) 
failed_commands_with_error_codes = list()
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        failed_commands_with_error_codes += b["error_hist"].items()
        for error_code, num_occurences in failed_commands_with_error_codes:
            error_code = error_code.value
            num_occurences = num_occurences.value
            if num_occurences > 0 and error_code in ERROR_CODES:
                print("\r{:>30} | {:5} ".format(ERROR_CODES[error_code], num_occurences))

        print("\nSummary of error codes per command")
        for cmd, errs in command_to_errors.items():
            print(cmd)
            for err_num, count in errs.items():
                print('\t{}\t{}'.format(ERROR_CODES[err_num], count))
        exit()
