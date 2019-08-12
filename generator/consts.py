""" Constants & utilities to be used across USDT test runner and generator """

# Keys #

PROBE_NAME_KEY = "name"
PROBE_ARGS_KEY = "args"
ARG_TYPE_KEY = "type"
ARG_NAME_KEY = "name"
PROBE_HIT_KEY = "hits"
ARG_STR_LEN_KEY = "length"
ARG_STRUCT_FIELDS_KEY = "fields"

# EBPF-C Code #

HEADERS = """
#include <linux/ptrace.h>
#include <linux/sched.h>
"""

BPF_OUT_NAME = "out"
BPF_PERF_OUTPUT = "BPF_PERF_OUTPUT({});\n\n"
BPF_PERF_OUTPUT_ADDR_NAME = "addr_{}_{}"
BPF_PERF_OUTPUT_ARG_NAME = "arg_{}_{}"
BPF_PERF_OUTPUT_STRUCT_NAME = "{}_output"
BPF_PERF_OUTPUT_MEMBER_ASSN = "\tout.{target} = {source_struct}.{source_struct_member};\n"
BPF_PERF_SUBMIT_STMT = "\t{}.perf_submit(ctx, &out, sizeof(out));\n"

BPF_PERF_OUTPUT_COMMON_MEMBER_DECLS ="""
        char comm[TASK_COMM_LEN];
        u32 pid;
        u32 tid;
        u64 ns;
"""

BPF_PERF_OUTPUT_COMMON ="""
        // get time
        out.ns = bpf_ktime_get_ns();

        // get pid & tid
        u64 tid_pid = bpf_get_current_pid_tgid();
        out.pid = (tid_pid >> 32);
        out.tid = tid_pid;

        // get comm
        bpf_get_current_comm(&out.comm, sizeof(out.comm));
"""

BPF_READ_ARG = "\tbpf_usdt_readarg({num}, ctx, &out.{output_member_name});\n"

BPF_READ_STR = """
\tconst char* {addr_name} = NULL;
\tbpf_usdt_readarg({arg_num}, ctx, &{addr_name});
\tbpf_probe_read_str(&out.{out_member}, sizeof(out.{out_member}), {addr_name});
"""

BPF_READ_STRUCT_MEMBER_STR = """
\tconst char* {str_addr_name} = {source};
\tbpf_probe_read_str(out.{target}, sizeof(out.{target}), {str_addr_name});
"""

BPF_READ_STRUCT = """
\tstruct {probe_name}_level_0_{index} {struct_name} = {{}};
\tconst void* addr_{index} = NULL;
\tbpf_usdt_readarg({arg_num}, ctx, &addr_{index});
\tbpf_probe_read(&{struct_name}, sizeof({struct_name}), addr_{index});
"""

PROBE_FN_NAME = "{}_fn"
PROBE_ENTRY_FN = """
int {}(struct pt_regs *ctx) {{
{}
\treturn 0;\n}}\n
"""

BASE_STRUCT_NAME = "{probe_name}_level_0_{index}_base"
STRUCT_NAME = "{probe_name}_level_{depth}_{index}"
STRUCT = """
struct {} {{
{}}};\n
"""
STRUCT_MEMBER = "\t{};\n"
STRUCT_INIT = "\tstruct {} {} = {{}};\n"

ARG_NAME_CAT = "_{}"

# EBPF-C Types & Declarations #

INT_TYPE = "int"
STRING_TYPE = "str"
STRUCT_TYPE = "struct"
POINTER_TYPE = 'ptr'

TYPE_DECL = {
    INT_TYPE: "int {arg_name}",
    STRING_TYPE: "char {arg_name}[{length}]",
    STRUCT_TYPE: "struct " + STRUCT_NAME + " {arg_name}",
    POINTER_TYPE: "void* {arg_name}"
}
