#!/bin/python3

import argparse
import bson.raw_bson as raw_bson

from bsonjs import dumps
from generator.err import errors, error_strings
from generator.consts import *
from generator.generator import Probe
from probes import ProbeHit, ProbeHistory, TimeTable, USDTThread, USDTArg
from signal import signal, SIGINT
from threading import Event, Lock
from util import WorkerMaster, WorkerThread, Counter

####################################################################################

class Bundle:
    def __init__(self, start = None):
        # TODO: start/end timers?
        self._probes = [start]
        self._done = False
        if start:
            self.tid = start.tid
            self.name = start.name.replace("_start", "")
            self.count = start.args["count"]
        else:
            self.tid = None
            self.name = None
            self.count = None
    
    def start(self):
        return self._probes[0] 

    def is_start(probe):
        return probe.name.endswith("_start")

    def is_end(self, probe):
        return probe.name.endswith("_end") \
            and probe.args["count"] == self.count

    def has_open_nested_probe(self):
        return isinstance(self._probes[-1], Bundle) and not self._probes[-1]._done

    def push(self, probe):
        if self.has_open_nested_probe():
            self._probes[-1].push(probe)
        elif self.is_end(probe):
            self._done = True
            self._probes.append(probe)
        elif Bundle.is_start(probe):
            self._probes.append(Bundle(probe))
        else:
            self._probes.append(probe)

    def __str__(self):
        out = "{\n"
        out += "#probes: {}\n".format(len(self._probes))
        #out += "tid: {}\n".format(self.tid)
        out += "count: {}\n".format(self.count)
        out += " [\n"
        for probe in self._probes:
            probestr = str(probe)
            for line in probestr.splitlines():
                out += "   " + line + "\n"
        return out + " ]\n}\n"

class AggTimeTable(TimeTable):
    def __init__(self, view, probes, file_name):
        TimeTable.__init__(self, view)
        self.on_add = self._callback_gen(view)
        self.probes = probes
        self.bundles = {}#TODO dedup wrt ProbeHistory
        self.file = file_name

        # error stats
        self.counters["BsonErrors"] = Counter()

    def _probe_has_bson(self, probe):
        assert probe in probes
        for args in probes[probe]:
            if args[ARG_TYPE_KEY] == LONG_STRING_TYPE:
                return True
        return False

    def _callback_gen(self, view):
        def process_callback(probe, hit):
            if __name__ == "__main__":
                with self.lock:
#                    print("[", hit.ns, "] [", hit.tid, "]", probe)
                    # TODO: abstract away bson logic/ make this less awk
                    # check for errors:
                    errname = "bson_err"
                    if errname in hit.args:
                        err = hit.args[errname]
                        print("ERROR", error_strings[err])
                        self.counters["BsonErrors"].encounter(error_strings[err])

                    # we can have at most one bson per probe
                    elif self._probe_has_bson(probe):
                        bson = hit.args["bson"]
                        sz = hit.args["bson_sz"]

                        # attempt to parse long string as bson
                        try:
                            rbson = raw_bson.RawBSONDocument(bson)
                            sbson = dumps(rbson.raw)
                            hit.args["bson"] = sbson
                            self.counters["BsonErrors"].encounter("success")
 
                        except Exception as e:
                            #out = ""
                            #for b in bson:
                            #    out += str(hex(b))
                            #print(out)
                            #print(e)
                            self.counters["BsonErrors"].encounter("BAD_BSON")

        return process_callback

    def dumps(self):
        out = str(self)
        for tid in self.global_history.buckets:
            hit_list = self.global_history.buckets[tid].head
            bundle = Bundle()
            prev = None
            while hit_list != None:
                print("[", hit_list.value.ns, "] [", hit_list.value.tid, "]", hit_list.value.name)
                if prev != None:
                    # for testing purposes, ensure this is true
                    assert prev.ns < hit_list.value.ns
                prev = hit_list.value
                bundle.push(hit_list.value)
                hit_list = hit_list.next
            out += str(bundle)

        if self.file:
            try:
                with open(self.file, "w") as fd:
                    fd.write(out)
            except IOError as e:
                print(e)
                print(out)
        else:
            print(out)

####################################################################################

def sigint_handler_gen(mr, tt):
    def handler(signal, frame):
        mr.kill_all()
        print("---------------- SORTED -------------------")
        tt.dumps()
        exit(0)
    return handler

def mk_USDTThread_from(probe_name, probe_args, args, time_table):
    return USDTThread(args.pid[0],
                      [{
                        PROBE_NAME_KEY: probe_name,
                        SAMPLES_PROPORTION_KEY: args.sample,
                        MAX_STR_SZ_KEY: args.chunk,
                        MAX_MAP_SZ_KEY: args.map,
                        PROBE_ARGS_KEY: probe_args
                      }],
                      time_table)

# Main #

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gather data from aggregation requests.")
    parser.add_argument('pid',
                        metavar='pid',
                        type=int,
                        nargs=1,
                        help='pid of process emitting probes')
    parser.add_argument('-s', '--sample',
                        metavar='sample',
                        type=float,
                        nargs='?',
                        default=1,
                        help='number of queries to sample')
    parser.add_argument('-c', '--chunk',
                        metavar='chunk',
                        type=int,
                        nargs='?',
                        default=MAX_STR_SZ,
                        help='maximum chunk size')
    parser.add_argument('-m', '--map',
                        metavar='map',
                        type=int,
                        nargs='?',
                        default=MAX_MAP_SZ,
                        help='maximum map size')
    parser.add_argument('-f', '--file',
                        metavar='file',
                        type=str,
                        nargs='?',
                        default=None,
                        help='output file for bundle')

    args = parser.parse_args()
    print(args)

    probes = {
        # delimiters to indicate start/end of aggrequest construction
        "aggRequestParse_start": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "count"}],
        "aggRequestParse_end": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "count"}],
        # data provided during construction, some may be hit multiple times
        "aggRequestParsePipeline": [{ARG_TYPE_KEY: LONG_STRING_TYPE, ARG_NAME_KEY: "bson"}],
        "aggRequestBatchSize": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "batchSize"}],
        "aggRequestCollation": [{ARG_TYPE_KEY: LONG_STRING_TYPE, ARG_NAME_KEY: "bson"}],
        "aggRequestAllowDiskUse": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "allowDiskUse"}],
        "aggRequestFromMongos": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "fromMongos"}],
        "aggRequestNeedsMerge": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "needsMerge"}],
        "aggRequestBypassDocumentValidation": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "bypassDocumentValidation"}],
        "aggRequestMaxTimeMS": [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "maxTimeMS"}],
        "aggRequestReadConcern": [{ARG_TYPE_KEY: LONG_STRING_TYPE, ARG_NAME_KEY: "bson"}],
        "aggRequestUnwrappedReadPref": [{ARG_TYPE_KEY: LONG_STRING_TYPE, ARG_NAME_KEY: "bson"}]
    }

    mr = None
    time_table = AggTimeTable(None, probes, args.file)

    workers = []
    for probe_name in probes:
        worker = mk_USDTThread_from(probe_name, probes[probe_name], args, time_table)
        workers.append(worker)

    mr = WorkerMaster(workers)
    mr.start_all()
    print("Listening for probes.")

    signal(SIGINT, sigint_handler_gen(mr, time_table))
    Event().wait() # wait for keyboard interrupt forever
