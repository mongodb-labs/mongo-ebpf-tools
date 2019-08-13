#!/usr/bin/python3

from bcc import BPF, USDT
import sys
import bson.raw_bson as raw_bson
from bsonjs import dumps
import ctypes as ct

if len(sys.argv) < 2:
    print("USAGE: " + sys.argv[0] + " <pid>")
    exit(1)

text = """
#include <linux/ptrace.h>

BPF_PERF_OUTPUT(findCmdPlans);
BPF_PERF_OUTPUT(findCmdAgg);

#define MAX_PLAN_LEN 400

struct findPlan {
    char plan[MAX_PLAN_LEN];
    int size;
};

int findCmdPlan(struct pt_regs *ctx) {
    struct findPlan out = {};
    size_t sz = 0;
    bpf_usdt_readarg(2, ctx, &sz);
    if(!sz) return 0;
    out.size = sz;
    sz = sz < MAX_PLAN_LEN ? sz : MAX_PLAN_LEN;
    const char* data = NULL;
    bpf_usdt_readarg(1, ctx, &data);
    if(!data) return 0;
    bpf_probe_read(out.plan, sz, data);
    findCmdPlans.perf_submit(ctx, &out, sizeof(out));
    return 0;
}

struct maxBsonObj {
    char ob[16777216];
};

//BPF_ARRAY(aggCommands, struct maxBsonObj, 1);

struct findCmdAggOut {
    int bsonSize;
};

int findCmdToAgg(struct pt_regs *ctx) {
    int sz = -1;
    bpf_usdt_readarg(1, ctx, &sz);
    if(sz == -1) return 0;
    struct findCmdAggOut out = {};
    out.bsonSize = sz;
    findCmdAgg.perf_submit(ctx, &out, sizeof(out));
    return 0;
}

struct beginQueryOpOut {
    char nss[50];
    char bson[100];
    unsigned int queryObjSz;
    long long nreturn;
    long long nskip;
};

BPF_PERF_OUTPUT(beginQuery);

int beginQueryOp(struct pt_regs *ctx) {
    struct beginQueryOpOut out = {};
    void* nssPtr = NULL;
    bpf_usdt_readarg(2, ctx, &nssPtr);
    if(!nssPtr) return 0;
    bpf_probe_read_str(out.nss, sizeof(out.nss), nssPtr);
    void* bsonPtr = NULL;
    bpf_usdt_readarg(3, ctx, &bsonPtr);
    bpf_usdt_readarg(4, ctx, &out.queryObjSz);
    if(out.queryObjSz > 100 || out.queryObjSz < 0) return 0;
    if(bsonPtr && out.queryObjSz){
        bpf_probe_read(out.bson, out.queryObjSz, bsonPtr);
    }
    bpf_usdt_readarg(5, ctx, &out.nreturn);
    bpf_usdt_readarg(6, ctx, &out.nskip);
    beginQuery.perf_submit(ctx, &out, sizeof(out));
    return 0;
}

struct SummaryStats {
    size_t nReturned;
    // The total number of index keys examined by the plan.
    size_t totalKeysExamined;

    // The total number of documents examined by the plan.
    size_t totalDocsExamined;

    // The number of milliseconds spent inside the root stage's work() method.
    long long executionTimeMillis;

    // The number of collection scans that occur during execution. Note that more than one
    // collection scan may happen during execution (e.g. for $lookup execution).
    long long collectionScans;

    // The number of collection scans that occur during execution which are nontailable. Note that
    // more than one collection scan may happen during execution (e.g. for $lookup execution).
    long long collectionScansNonTailable;

    // Did this plan use an in-memory sort stage?
    bool hasSortStage;

    // Did this plan use disk space?
    bool usedDisk;

    // Was this plan a result of using the MultiPlanStage to select a winner among several
    // candidates?
    bool fromMultiPlanner;

    // Was a replan triggered during the execution of this query?
    bool replanned;
};

struct endQueryOutput {
    void* opCtx;
    struct SummaryStats summaryStats;
    long long numResults;
};

BPF_PERF_OUTPUT(endQuery);

int endQueryOp(struct pt_regs *ctx) {
    struct endQueryOutput out = {};
    void* summaryPtr = NULL;
    out.opCtx = NULL;
    bpf_usdt_readarg(1, ctx, &out.opCtx);
    if(!out.opCtx) return 0;
    bpf_usdt_readarg(2, ctx, &summaryPtr); 
    if(!summaryPtr) return 0;
    bpf_probe_read(&out.summaryStats, sizeof(out.summaryStats), summaryPtr);
    bpf_usdt_readarg(3, ctx, &out.numResults);
    endQuery.perf_submit(ctx, &out, sizeof(out));
    return 0;
}
"""

probe = USDT(int(sys.argv[1]))
probe.enable_probe(probe="findCmdPlan", fn_name="findCmdPlan")

toAgg = USDT(int(sys.argv[1]))
toAgg.enable_probe(probe="findToAgg", fn_name="findCmdToAgg")

# beginQuery = USDT(int(sys.argv[1]))
probe.enable_probe(probe="beginQueryOp", fn_name="beginQueryOp")
probe.enable_probe(probe="endQueryOp", fn_name="endQueryOp")

class BeginQuery(ct.Structure):
    _fields_ = [
            ("nss", ct.c_char * 50),
            ("bson", ct.c_byte * 100),
            ("queryObjSz", ct.c_uint),
            ("nreturn", ct.c_longlong),
            ("nskip", ct.c_longlong)
            ]

class SummaryStats(ct.Structure):
    _fields_ = [
            ("nReturned", ct.c_size_t),
            ("totalKeysExamined", ct.c_size_t),
            ("totalDocsExamined", ct.c_size_t),
            ("executionTimeMillis", ct.c_longlong),
            ("collectionScans", ct.c_longlong),
            ("collectionScansNonTailable", ct.c_longlong),
            ("hasSortStage", ct.c_bool),
            ("usedDisk", ct.c_bool),
            ("fromMultiPlanner", ct.c_bool),
            ("replanned", ct.c_bool)
            ]

class EndQuery(ct.Structure):
    _fields_ = [
            ("opCtx", ct.c_voidp),
            ("summaryStats", SummaryStats),
            ("numResults", ct.c_longlong)
            ]

b = BPF(text=text, usdt_contexts=[probe, toAgg])

def on_hit(cpu, data, size):
    event = b["findCmdPlans"].event(data)
    print("Summary of query plan: ", str(event.plan, 'utf-8'))

def toAggHit(cpu, data, size):
    event = b["findCmdAgg"].event(data)
    print("Find is now an agg pipeline. Bson size: ", event.bsonSize)

def beginQueryHit(cpu, data, size):
    event = ct.cast(data, ct.POINTER(BeginQuery)).contents
    bson = bytes(event.bson)
    bson = bson[:event.queryObjSz]
    rbson = raw_bson.RawBSONDocument(bson)
    print("Namespace: ", str(event.nss, 'utf-8'))
    print(" had query ", dumps(rbson.raw))
    print(" which returned ", event.nreturn, " and skipped ", event.nskip)

def endQueryHit(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EndQuery)).contents
    print("Query over. Total docs examined: ", event.summaryStats.totalDocsExamined, " which yielded ", event.numResults, " results.")

b["findCmdPlans"].open_perf_buffer(on_hit)
b["findCmdAgg"].open_perf_buffer(toAggHit)
b["beginQuery"].open_perf_buffer(beginQueryHit)
b["endQuery"].open_perf_buffer(endQueryHit)
print("listening")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit(0)
