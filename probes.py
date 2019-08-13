#!/bin/python3

from generator.generator import Generator, Probe
from generator.consts import *
from bcc import BPF, USDT
from util import WorkerThread, Counter, Timer
import ctypes

#####################################################################################

# Probes & Probe History Tracking #

class ProbeHit:
    def __init__(self, name, comm, pid, tid, ns, cpu, size):
        self.name = name
        self.comm = comm.decode('utf-8')
        self.pid = pid
        self.tid = tid
        self.ns = ns
        self.prev = None
        self.cpu = cpu
        self.size = size
        self.fields = ["comm", "pid", "tid", "ns", "cpu", "size"]
        self.args = dict()

    def update_counters(self, counters):
        for field in self.fields:
            if field == "ns":
                continue
            if field not in counters:
                counters[field] = Counter()
            counters[field].encounter(getattr(self, field))

    def __str__(self):
        return " | ".join(str(getattr(self, field)) for field in self.fields)

class ProbeHistory:
    def __init__(self):
        self.hits = []
        self.hits_lookup = dict()
        self.counters = dict()
        self.timer = Timer()
        self.lost = 0

    def append(self, hit):
        key = hit.tid
        if key in self.hits_lookup:
            hit.prev = self.hits_lookup[key]
            self.timer.tick(hit)
        else:
            hit.prev = None
        self.hits.append(hit)
        self.hits_lookup[key] = hit
        hit.update_counters(self.counters)

    def last_hit(self, key):
        return self.hits_lookup.get(key)

    def add_lost(self, lost):
        self.lost += lost

    def all_hits(self, key):
        all_hits = []
        last = self.last(key)
        while last is not None:
            all_hits.append(last)
            last = last.prev
        return all_hits

    def __str__(self):
        out = str(self.timer)
        for key in self.counters:
            counter = self.counters[key]
            out += "{}: {}".format(key, str(counter))
        out += "lost: {}".format(self.lost)
        return out

class TimeTable:
    def __init__(self, view):
        self.times = dict()
        self.on_add = self._callback_gen(view)
        self.lost = 0
        self.last_probe = None
        # generate stats counters
        self.counters = dict();
        self.counters["probe"] = Counter()
        self.counters["size"] = Counter()

    def _callback_gen(self, view):
        def _on_add(probe, hit):
            if view != None:
                view.on_probe_hit("{} | {}\n".format(probe, hit),
                                  str(self),
                                  probe,
                                  str(self.get(probe)))
        return _on_add

    def add(self, probe, hit):
        if self.has(probe):
            self.times[probe].append(hit)
        else:
            ph = ProbeHistory()
            ph.append(hit)
            self.times[probe] = ph

        # update counters
        self.counters["probe"].encounter(probe)
        self.counters["size"].encounter(hit.size)
        hit.update_counters(self.counters)

        # callback
        self.on_add(probe, hit)
        self.last_probe = probe

    def add_lost(self, probe, lost):
        self.times[probe].add_lost(lost)
        self.lost += lost

    def has(self, probe):
        return probe in self.times

    def get(self, probe):
        return self.times[probe]

    def __str__(self):
        out = ""
        for key in self.counters:
            counter = self.counters[key]
            out += "{}: {}".format(key, str(counter))
        out += "lost: {}".format(self.lost)
        return out

# USDT Thread #

class USDTArg:
    def __init__(self, name, c_type, num):
        self.name = name
        self.num = num
        self.c_type = c_type

    def __str__(self):
        return "{} {};\n".format(self.c_type, self.name)

class USDTThread(WorkerThread):
    def __init__(self, pid, probes, time_table):
        WorkerThread.__init__(self, target=lambda: self._bpf.perf_buffer_poll(100))
        self._pid = pid
        self._probes = [Probe(probe) for probe in probes]
        self._generator = Generator()
        self._lost = dict()
        self.time_table = time_table
        self._init_bpf()
        # TODO: remove
        print("DONE")
        WorkerThread.__init__(self, target=self._work_gen())

    def _work_gen(self):
        def work():
            self._bpf.perf_buffer_poll(100)
        return work

    def _callback_gen(self, probe):
        def process_callback(cpu, data, size):
            event = self._bpf[probe.name].event(data)
            hit = ProbeHit(name = probe.name,
                           comm = event.comm,
                           pid = event.pid,
                           tid = event.tid,
                           ns = event.ns,
                           cpu = cpu,
                           size = size)
            for arg in probe.args:
                # long str is a special case! must read from map
                if arg.type == LONG_STRING_TYPE:
                    sz_name = arg.name + "_sz"
                    sz = getattr(event, sz_name)
                    hit.args[sz_name] = sz
                    hit.args[arg.name] = self.read_long_str(sz, probe)
                else:
                    hit.args[arg.name] = getattr(event, arg.name)
            self.time_table.add(probe.name, hit)
        return process_callback

    def read_long_str(self, sz, probe):
        buf = LONG_STRING_BUF_NAME.format(probe.name)
        out = bytes()
        i = 0
        c = 0
        try:
            if sz == 0: # for some reason my test probes are not reporting real string sizes correctly
                out = self._bpf[buf][c].str
                assert False
            else:
                while i < sz and c < MAX_MAP_SZ:
                    print("LEN: ", len(self._bpf[buf][c].str))
                    print("STR: ", self._bpf[buf])
                    out += self._bpf[buf][c].str
                    i += MAX_STR_SZ
                    c = c + 1
        except Exception as e:
            print(e)
            out += bytes("#ERR#" + str(e), 'utf-8')
        return out

    def _lost_callback_gen(self, probe):
        def process_callback(lost):
            self.time_table.add_lost(probe.name, lost)
        return process_callback

    def gen_code(self):
        for probe in self._probes:
            self._generator.add_probe(probe)
        self.bpf_code = self._generator.finish()
        print(self.bpf_code)

    def _init_bpf(self):
        self.gen_code()

        # enable probes
        usdt_probes = [USDT(pid=self._pid) for p in self._probes]
        for index, probe in enumerate(self._probes):
            usdt_probes[index].enable_probe(probe=probe.name, fn_name=probe.function_name)

        # register callbacks on probe hits
        self._bpf = BPF(text=self.bpf_code, usdt_contexts=usdt_probes)
        for probe in self._probes:
            self._bpf[probe.name].open_perf_buffer(self._callback_gen(probe), lost_cb=self._lost_callback_gen(probe))
