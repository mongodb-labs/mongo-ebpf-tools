#!/bin/python3

import ctypes as ct

from bcc import BPF, USDT
from math import ceil
from threading import RLock
from time import sleep

from generator.generator import Generator, Probe
from generator.consts import *
from generator.err import *
from table import *
from util import WorkerThread, Counter, Timer

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

    def __str__(self):#prettyprint(self):
        out = self.name + "{ "
        #for field in self.fields:
        #    out += "{}: {}, ".format(field, str(getattr(self, field)))
        for arg in self.args:
            out += "{}: {}, ".format(arg, str(self.args[arg]))
        return out + "}\n"

    def row_str(self):
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
        # multiple threads often modify a single timetable
        self.lock = RLock()

        self.times = dict()
        self.global_history = SortedTable("tid", "ns") # tid dictionary
        self.on_add = self._callback_gen(view)
        self.lost = 0

        # generate additional stats counters
        self.counters = dict();
        self.counters["probe"] = Counter()
        self.counters["size"] = Counter()

    def _callback_gen(self, view):
        def _on_add(probe, hit):
            with self.lock:
                if view != None:
                    view.on_probe_hit("{} | {}\n".format(probe, hit.row_str()),
                                      str(self),
                                      probe,
                                      str(self.get(probe)))
        return _on_add

    def add(self, probe, hit):
        with self.lock:
            if self.has(probe):
                # TODO: this may not report correct time due to potentially out of order events
                self.times[probe].append(hit)
            else:
                ph = ProbeHistory()
                ph.append(hit)
                self.times[probe] = ph

            # update counters
            self.counters["probe"].encounter(probe)
            self.counters["size"].encounter(hit.size)
            hit.update_counters(self.counters)

            self.global_history.add(hit)

            # callback
            self.on_add(probe, hit)

    def add_lost(self, probe, lost):
        with self.lock:
            self.times[probe].add_lost(lost)
            self.lost += lost

    def has(self, probe):
        with self.lock:
            return probe in self.times

    def get(self, probe):
        with self.lock:
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
        WorkerThread.__init__(self, target=lambda: self._bpf.perf_buffer_poll(100), on_die=lambda: self._bpf.cleanup())
        self._pid = pid
        self._probes = [Probe(probe) for probe in probes]
        self._generator = Generator()
        self._lost = dict()
        self.time_table = time_table
        self._init_bpf()
        WorkerThread.__init__(self, target=self._work_gen())

    def _work_gen(self):
        def work():
            self._bpf.perf_buffer_poll(100)
        return work

    def _callback_gen(self, probe):
        def process_callback(cpu, data, size):
            event = self._bpf[probe.name].event(data)

            # gather generic probe data
            hit = ProbeHit(name = probe.name,
                           comm = event.comm,
                           pid = event.pid,
                           tid = event.tid,
                           ns = event.ns,
                           cpu = cpu,
                           size = size)
            start_chunk_idx = getattr(event, probe.buf_idx_name) if probe.has_long_str else 0
            
            # parse probe arguments
            hit.args = self.args_2_dict(event, hit.args, probe, start_chunk_idx)
            self.time_table.add(probe.name, hit)

        return process_callback

    def args_2_dict(self, event, args, probe, start_chunk_idx, level = 0):
        result = dict()

        for arg in probe.args:
            if arg.type == LONG_STRING_TYPE:
                # passing structs containing long strings is not supported by the generator
                assert level == 0

                sz_name = arg.name + "_sz"
                err_name = arg.name + "_err"
                sz = getattr(event, sz_name)
                result[probe.buf_idx_name] = start_chunk_idx

                if sz < 0: # a negative size indicates an error
                    print(error_strings[sz])
                    result[err_name] = sz

                else:
                    try:
                        result[sz_name] = sz
                        result[arg.name] = self.read_long_str(sz, probe, start_chunk_idx)
                    except KeyError:
                        result[err_name] = errors["KEY_ERROR"]

            elif arg.type == STRUCT_TYPE:
                result[arg.name] = self.args_2_dict(event, arg.fields, level + 1)

            else:
                result[arg.name] = getattr(event, arg.name if level == 0 else arg.name + '_' + str(level))

        return result

    def read_long_str(self, sz, probe, start_chunk_idx):
        # get index of starting chunk
        i = start_chunk_idx
        sz_remaining = sz
        out = []
        while i < probe.max_map_sz and sz_remaining > 0:
            chunk_sz = min(sz_remaining, probe.max_str_sz)
            out += self._bpf[probe.buf_name][i].str[:chunk_sz]
            sz_remaining -= chunk_sz
            i = i + 1
        return bytes(out)

    def _lost_callback_gen(self, probe):
        def process_callback(lost):
            self.time_table.add_lost(probe.name, lost)
        return process_callback

    def gen_code(self):
        for probe in self._probes:
            self._generator.add_probe(probe)
        self.bpf_code = self._generator.finish()
        # uncomment this to print out generated EBPF-C code
        # NOTE: will break curses UI, so don't use with threads.py
        # print(self.bpf_code)

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
