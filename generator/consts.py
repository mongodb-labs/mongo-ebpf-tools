""" Constants & utilities to be used across USDT test runner and generator """

from .err import errors

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
# ~ 67 MB (only one long string supported per probe).
# NOTE that larger string sizes generate more instructions in the unrolled
# long-string copying loop, which may result in maximum instruction size being exceeded, even though
# there is enough space in the string map to store a string of that size.
MAX_STR_SZ = 1048576
MAX_MAP_SZ = 64

LONG_STRING_BUF_NAME = "longstr_buf_{}"
LONG_STRING_PRELUDE = """
#define MAX_STR_SZ      {max_str_sz}
#define MAX_MAP_SZ      {max_map_sz}

#define BAD_CHUNK_IDX   """ + str(errors["BAD_CHUNK_IDX"]) + """
#define BAD_READ_PROBE  """ + str(errors["BAD_READ_PROBE"]) + """
#define KERNEL_FAULT    """ + str(errors["KERNEL_FAULT"]) + """
#define LOGICAL_ERROR   """ + str(errors["LOGICAL_ERROR"]) + """

struct str_chunk {{
\tunsigned char str[MAX_STR_SZ];
}};

// longstrs are stored here in "chunks", with up to MAX_MAP_SZ chunks per str
// this array is treated as a ring buffer
BPF_ARRAY({longstr_buf_name}, struct str_chunk, MAX_MAP_SZ);
// this is the current index of the chunk ring buffer
BPF_ARRAY({longstr_buf_name}_index, unsigned int, 1);

"""

LONG_STR_FN_NAME = "read_long_str"
LONG_STR_FN_DECL = "static inline __attribute__((__always_inline__)) int " \
    + LONG_STR_FN_NAME + "(char *str, int *idx, int sz) {\n #UNROLLED_LOOP# }\n"
LONG_STR_FN_CALL = """
\t// get long string
\tchar *{arg_name}_str = NULL;
\tbpf_usdt_readarg({arg_num}, ctx, &out.{arg_name}_sz);
\tbpf_usdt_readarg({arg_num_inc}, ctx, &{arg_name}_str);
\tout.{arg_name}_sz = read_long_str({arg_name}_str, &out.{arg_name}_idx, out.{arg_name}_sz);
"""

BPF_OUT_NAME = "out"
BPF_PERF_OUTPUT = "\nBPF_PERF_OUTPUT({});\n"
BPF_PERF_OUTPUT_ADDR_NAME = "addr_{}_{}"
BPF_PERF_OUTPUT_ARG_NAME = "arg_{}_{}"
BPF_PERF_OUTPUT_STRUCT_NAME = "{}_output"
BPF_PERF_OUTPUT_MEMBER_ASSN = "\tout.{target} = {source_struct}.{source_struct_member};\n"
BPF_PERF_SUBMIT_STMT = "\n\t// submit all\n\t{}.perf_submit(ctx, &out, sizeof(out));\n"

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

BPF_READ_ARG = "\n\tbpf_usdt_readarg({num}, ctx, &out.{output_member_name});\n"

BPF_READ_STR = """\n
\tconst char* {addr_name} = NULL;
\tbpf_usdt_readarg({arg_num}, ctx, &{addr_name});
\tbpf_probe_read_str(&out.{out_member}, sizeof(out.{out_member}), {addr_name});
"""

BPF_READ_STRUCT_MEMBER_STR = """
\tconst char* {str_addr_name} = {source};
\tbpf_probe_read_str(out.{target}, sizeof(out.{target}), {str_addr_name});
"""

BPF_READ_STRUCT = """\n
\tstruct {probe_name}_level_0_{index} {struct_name} = {{}};
\tconst void* addr_{index} = NULL;
\tbpf_usdt_readarg({arg_num}, ctx, &addr_{index});
\tbpf_probe_read(&{struct_name}, sizeof({struct_name}), addr_{index});
"""

PROBE_FN_NAME = "{}_fn"
PROBE_ENTRY_FN = """
int {}(struct pt_regs *ctx) {{
{}
\treturn 0;
}}
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
UNSIGNED_LONG_TYPE = "unsigned long"
LONG_LONG_TYPE = "long long"
CHAR_TYPE = 'char' # useful for bools since C doesn't have those
STRING_TYPE = "str"
STRUCT_TYPE = "struct"
POINTER_TYPE = 'ptr'
LONG_STRING_TYPE = 'longstr'
TYPES = [INT_TYPE, UNSIGNED_LONG_TYPE, LONG_LONG_TYPE, CHAR_TYPE, STRING_TYPE, STRUCT_TYPE, \
        POINTER_TYPE, LONG_STRING_TYPE]

TYPE_DECL = {
    INT_TYPE: "int {arg_name}",
    UNSIGNED_LONG_TYPE: 'unsigned long {arg_name}',
    LONG_LONG_TYPE: "long long {arg_name}",
    CHAR_TYPE: 'char {arg_name}',
    STRING_TYPE: "char {arg_name}[{length}]",
    STRUCT_TYPE: "struct " + STRUCT_NAME + " {arg_name}",
    POINTER_TYPE: "void* {arg_name}",
    # the size & starting chunk index of a long string is stored in the output struct
    # the string itself can be retrieved from string_chunks in the BPF_ARRAY
    # longstr_buf
    LONG_STRING_TYPE: ["int {arg_name}_sz", "unsigned int {arg_name}_idx"]
}

# Utility functions #

LONGSTR_LOOP_INIT = """
\t// get last index available in ring buffer
\tunsigned int index = 0;
\tunsigned int *index_ptr = NULL;
\tindex_ptr = {longstr_buf_name}_index.lookup(&index);
\tif (index_ptr == NULL) return BAD_CHUNK_IDX;

\t// reserve the necessary number of chunks
\tindex = *index_ptr;
\t*idx = index; // this is going to be sent back with the output event
\tif (index >= MAX_MAP_SZ || sz < 0) return LOGICAL_ERROR;
\t*index_ptr = (index + sz/MAX_STR_SZ);
\tif (sz % MAX_STR_SZ != 0) (*index_ptr)++;
\t*index_ptr %= MAX_MAP_SZ;

\tunsigned int len = sz;
\tstruct str_chunk* chunk;
"""

# WARNING: may (theoretically) be able to cause a segfault
# since this is technically reading more memory than it should
LONGSTR_LOOP_READ = """
\tchunk = {longstr_buf_name}.lookup(&index);
\tif (chunk == NULL) return BAD_CHUNK_IDX;
\tindex = (index + 1) % MAX_MAP_SZ;

\tif (len < 0) {{
\t\treturn LOGICAL_ERROR;
\t}} if (len < MAX_STR_SZ) {{
\t\treturn bpf_probe_read(&chunk->str, len, str) ? KERNEL_FAULT : sz;
\t}} else if (bpf_probe_read(&chunk->str, MAX_STR_SZ, str)) return KERNEL_FAULT;
"""
LONGSTR_LOOP_ITER = """
\tlen -= MAX_STR_SZ;
\tstr += MAX_STR_SZ;
"""
LONGSTR_LOOP_END = "\n\treturn sz;\n"

def generate_longstr_prelude(probe, max_map_sz, max_str_sz):
    longstr_buf_name = LONG_STRING_BUF_NAME.format(probe)
    prelude = LONG_STRING_PRELUDE.format(max_str_sz = max_str_sz,
                                         max_map_sz = max_map_sz,
                                         longstr_buf_name = longstr_buf_name)
    read_str = LONGSTR_LOOP_READ.format(longstr_buf_name = longstr_buf_name)

    unrolled_loop = LONGSTR_LOOP_INIT.format(longstr_buf_name = longstr_buf_name) + read_str
    for index in range(1, max_map_sz):
         unrolled_loop += LONGSTR_LOOP_ITER + read_str

    return prelude + LONG_STR_FN_DECL.replace("#UNROLLED_LOOP#", unrolled_loop + LONGSTR_LOOP_END)

def declare_single_member(fmt, arg_name, probe_name, depth, index, length):
    return STRUCT_MEMBER.format(fmt.format(probe_name = probe_name,
                                           arg_name = arg_name,
                                           depth = depth,
                                           index = index,
                                           length = length))

def declare_member(arg_type, arg_name, probe_name, depth, index, length):
    assert arg_type in TYPE_DECL
    if isinstance(TYPE_DECL[arg_type], str):
        return declare_single_member(TYPE_DECL[arg_type], arg_name, probe_name, depth, index, length)
    else:
        members = ""
        for member in TYPE_DECL[arg_type]:
            members += declare_single_member(member, arg_name, probe_name, depth, index, length)
        return members

def reduce(fn, items):
    return ''.join(map(fn, items))
