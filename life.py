#!/usr/bin/python3

import argparse

from bcc import BPF, USDT
from sys import exit
from threading import Lock
from time import sleep
from util import WorkerMaster, WorkerThread

pct = 1
SAMPLES_THRESH = int(pct*(2**32))
# can transfer ~ 134 MB
MAX_STR_SZ = 2097152
MAX_MAP_SZ = 64

UNROLLED_LOOP = """
    int count = 0;
    int step = MIN(MAX_STR_SZ, sz);
    int len = sz;

    struct str_chunk* tt = ss_#PROBE#.lookup(&count);
    if (tt == NULL) return;

    bpf_probe_read_str(&tt->s, MAX_STR_SZ, str);

    if (len <= step) return;
    len -= step;
    str += step;
"""

for l in range(1, MAX_MAP_SZ - 1):
    UNROLLED_LOOP += """
    count = {};
    step = MIN(MAX_STR_SZ, sz - len);

    tt = ss_#PROBE#.lookup(&count);
    if (tt == NULL) return;
    bpf_probe_read(&tt->s, MAX_STR_SZ, str);

    if (len <= step) return;
    len -= step; 
    str += step;
""".format(l)

code = """
#include <linux/ptrace.h>

#define SAMPLES_THRESH  #SAMPLES_THRESH#
#define MAX_STR_SZ      #MAX_STR_SZ#
#define MAX_MAP_SZ      #MAX_MAP_SZ#

#define MIN(i1, i2) (i1 <= i2 ? i1 : i2)

BPF_PERF_OUTPUT(str_out_#PROBE#);

struct str_out_t {
    int sz;
};

struct str_chunk {
    char s[MAX_STR_SZ];
};

BPF_ARRAY(ss_#PROBE#, struct str_chunk, MAX_MAP_SZ);

static inline __attribute__((__always_inline__)) void read_long_str(char *str, int sz) {
    #UNROLLED_LOOP#
}

int str_entry_#PROBE#(struct pt_regs *ctx) {
    // only evaluate & submit to perf output for some pct of samples
    if (bpf_get_prandom_u32() >= SAMPLES_THRESH) return 0;

    struct str_out_t out = {};
    char *str = NULL;

    bpf_usdt_readarg(1, ctx, &out.sz);
    bpf_usdt_readarg(2, ctx, &str);
    read_long_str(str, out.sz);

    str_out_#PROBE#.perf_submit(ctx, &out, sizeof(out));

    return 0;
}
"""

print_lk = Lock()

def gen_callback(probe, bpfs):
    def callback(cpu, data, size):
        bpf = bpfs[probe]
        evt = bpf["str_out_{}".format(probe)].event(data)
        sz = evt.sz
        print_lk.acquire()
        print(probe, sz)
        i = 0
        c = 0
        try:
            print("- ", len(bpf["ss_{}".format(probe)]), sz)
            print(bpf["ss_{}".format(probe)][0].s)
        except:
            print("err")
            pass
        while i < sz and c < MAX_MAP_SZ:
            print(bpf["ss_{}".format(probe)][c].s)
            i += MAX_STR_SZ
            c = c + 1
        print("-------------")
        print_lk.release()
    return callback

def gen_work(probe, bpfs):
    def callback():
        bpfs[probe].perf_buffer_poll(100)
    return callback

code = code.replace("#SAMPLES_THRESH#", str(SAMPLES_THRESH))
code = code.replace("#MAX_STR_SZ#", str(MAX_STR_SZ))
code = code.replace("#MAX_MAP_SZ#", str(MAX_MAP_SZ))
code = code.replace("#UNROLLED_LOOP#", UNROLLED_LOOP)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gather timing data from WiredTiger.")
    parser.add_argument('pid',
                        metavar='pid',
                        type=int,
                        nargs=1,
                        help='pid of process emitting probes')
    args = parser.parse_args()
    bpfs = dict()

    # necessary to have multiple bpfs, one for each object,
    # due to restriction on number of insns per bpf object.
    # copying out long strings requires a large number of insns,
    # and duplicating that for each entrypt function is prohibitively
    # large in terms of number of isns.
    probes = ["query1", "query", "query1", "query1R", "queryR", "query2", "query3"]
    for probe in probes:
        print(probe)
        usdt = USDT(pid=args.pid[0])
        usdt.enable_probe(probe, fn_name="str_entry_{}".format(probe))
        bpfs[probe] = BPF(text=code.replace("#PROBE#", probe), usdt_contexts=[usdt])

    print(code)

    wrks = []
    for probe in probes:
        print(probe)
        bpf = bpfs[probe]
        bpf["str_out_{}".format(probe)].open_perf_buffer(gen_callback(probe, bpfs))
        wrks.append(WorkerThread(gen_work(probe, bpfs)))

    master = WorkerMaster(wrks)
    master.start_all()
    print("Ready")

    # loop until keyboard interrupt
    try:
        while True:
            pass
    except KeyboardInterrupt:
        master.kill_all()
        for wrk in wrks:
            wrk.should_work = False
            wrk.join() 

    print("Bye.")
