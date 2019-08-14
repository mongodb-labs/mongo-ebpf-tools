""" Constants & utilities to be used across USDT test runner and generator """

# Keys #

PROBE_NAME_KEY = "name"
PROBE_ARGS_KEY = "args"
ARG_TYPE_KEY = "type"
ARG_NAME_KEY = "name"
PROBE_HIT_KEY = "hits"
ARG_STR_LEN_KEY = "length"
ARG_STRUCT_FIELDS_KEY = "fields"
MAX_STR_SZ_KEY = "max_str_sz"
MAX_MAP_SZ_KEY = "max_map_sz"
SAMPLES_PROPORTION_KEY = "samples_prop"

# EBPF-C Code #

HEADERS = """
#include <linux/ptrace.h>
#include <linux/sched.h>
"""

# Default long string map storage: this caps maximum string size at
# ~ 134 MB (only one long string supported per probe).
# NOTE that larger string sizes generate more instructions in the unrolled
# long-string copying loop, which may result in maximum instruction size being exceeded, even though
# there is enough space in the string map to store a string of that size.
MAX_STR_SZ = 2097152 #works but seems unreliable
MAX_MAP_SZ = 64

LONG_STRING_BUF_NAME = "longstr_buf_{}"
LONG_STRING_PRELUDE = """
#define MAX_STR_SZ      {max_str_sz}
#define MAX_MAP_SZ      {max_map_sz}

#define BAD_CHUNK_IDX   -1
#define BAD_READ_PROBE  -2
#define KERNEL_FAULT    -3
#define LOGICAL_ERROR   -5

#define MIN(i1, i2) (i1 <= i2 ? i1 : i2)

struct str_chunk {{
\tunsigned char str[MAX_STR_SZ];
}};

BPF_ARRAY({longstr_buf_name}, struct str_chunk, MAX_MAP_SZ);
"""

LONG_STR_FN_NAME = "read_long_str"
LONG_STR_FN_DECL = "static inline __attribute__((__always_inline__)) int " \
    + LONG_STR_FN_NAME + "(char *str, int sz) {\n #UNROLLED_LOOP# }\n"
LONG_STR_FN_CALL = """
\tchar *{arg_name}_str = NULL;
\tbpf_usdt_readarg({arg_num}, ctx, &out.{arg_name}_sz);
\tbpf_usdt_readarg({arg_num_inc}, ctx, &{arg_name}_str);
\t out.{arg_name}_sz = read_long_str({arg_name}_str, out.{arg_name}_sz);
"""

BPF_OUT_NAME = "out"
BPF_PERF_OUTPUT = "BPF_PERF_OUTPUT({});\n\n"
BPF_PERF_OUTPUT_ADDR_NAME = "addr_{}_{}"
BPF_PERF_OUTPUT_ARG_NAME = "arg_{}_{}"
BPF_PERF_OUTPUT_STRUCT_NAME = "{}_output"
BPF_PERF_OUTPUT_MEMBER_ASSN = "\tout.{target} = {source_struct}.{source_struct_member};\n"
BPF_PERF_SUBMIT_STMT = "\t{}.perf_submit(ctx, &out, sizeof(out));\n"

BPF_PERF_OUTPUT_BOILERPLATE_MEMBER_DECLS ="""
\tchar comm[TASK_COMM_LEN];
\tu32 pid;
\tu32 tid;
\tu64 ns;
"""

BPF_PERF_OUTPUT_BOILERPLATE ="""
\t// get time
\tout.ns = bpf_ktime_get_ns();
\t
\t// get pid & tid
\tu64 tid_pid = bpf_get_current_pid_tgid();
\tout.pid = (tid_pid >> 32);
\tout.tid = tid_pid;
\t
\t// get comm
\tbpf_get_current_comm(&out.comm, sizeof(out.comm));
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

RANDOM_SAMPLES_PRELUDE = """
\tif (bpf_get_prandom_u32() >= {}) return 0;
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
LONG_LONG_TYPE = "long long"
STRING_TYPE = "str"
STRUCT_TYPE = "struct"
POINTER_TYPE = 'ptr'
LONG_STRING_TYPE = 'longstr'
TYPES = [INT_TYPE, LONG_LONG_TYPE, STRING_TYPE, STRUCT_TYPE, POINTER_TYPE, LONG_STRING_TYPE]

TYPE_DECL = {
    INT_TYPE: "int {arg_name}",
    LONG_LONG_TYPE: "long long {arg_name}",
    STRING_TYPE: "char {arg_name}[{length}]",
    STRUCT_TYPE: "struct " + STRUCT_NAME + " {arg_name}",
    POINTER_TYPE: "void* {arg_name}",
    # only the size of a long string is stored in the output struct
    # the string itself can be retrieved from string_chunks in the BPF_ARRAY
    # longstr_buf
    LONG_STRING_TYPE: "int {arg_name}_sz"
}

# Utility functions #

LONGSTR_LOOP_INIT = """
\tint count = 0;
\tunsigned int step = MIN(MAX_STR_SZ, sz);
\tint len = sz;
\tstruct str_chunk* chunk;
"""

# WARNING: may (theoretically) be able to cause a segfault
# since this is technically reading more memory than it should
LONGSTR_LOOP_READ = """
\tchunk = {longstr_buf_name}.lookup(&count);
\tif (chunk == NULL) return BAD_CHUNK_IDX;
{{
\tunsigned to_read = MIN(MAX_STR_SZ, step);
\tif(to_read < MAX_STR_SZ) {{
\t\tif (bpf_probe_read(&chunk->str, to_read, str)) return KERNEL_FAULT;
\t}} else {{
\t\tif (bpf_probe_read(&chunk->str, MAX_STR_SZ, str)) return KERNEL_FAULT;
\t}}
}}
\tif (len <= step) return sz;
\tlen -= step;
\tstr += step;
"""
LONGSTR_LOOP_STEP = """
\tcount = {index};
\tif((sz - len) <= 0)
\treturn LOGICAL_ERROR;
\tif((sz - len) < MAX_STR_SZ && (sz - len) > 0)
\t\tstep = sz - len;
\telse
\t\tstep = MAX_STR_SZ;
"""
LONGSTR_LOOP_END = "\n\treturn sz;\n"

def generate_longstr_prelude(probe, max_map_sz, max_str_sz):
    longstr_buf_name = LONG_STRING_BUF_NAME.format(probe)
    prelude = LONG_STRING_PRELUDE.format(max_str_sz = max_str_sz,
                                         max_map_sz = max_map_sz,
                                         longstr_buf_name = longstr_buf_name)
    read_str = LONGSTR_LOOP_READ.format(longstr_buf_name = longstr_buf_name)

    unrolled_loop = LONGSTR_LOOP_INIT + read_str
    for index in range(1, max_map_sz - 1):
         unrolled_loop += LONGSTR_LOOP_STEP.format(index = index) + read_str

    return prelude + LONG_STR_FN_DECL.replace("#UNROLLED_LOOP#", unrolled_loop + LONGSTR_LOOP_END)

def declare_member(arg_type, arg_name, probe_name, depth, index, length):
    assert arg_type in TYPE_DECL
    return STRUCT_MEMBER.format(TYPE_DECL[arg_type].format(probe_name = probe_name,
                                                           arg_name = arg_name,
                                                           depth = depth,
                                                           index = index,
                                                           length = length))

def reduce(fn, items):
    return ''.join(map(fn, items))
