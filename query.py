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
from util import WorkerMaster, WorkerThread

####################################################################################

class QueryTimeTable(TimeTable):
    def __init__(self, view):
        TimeTable.__init__(self, view)
        self.on_add = self._callback_gen(view)
        self.successful = 0
        self.kernel_faults = 0
        self.key_errs = 0
        self.bad_bson = 0
        self.others = 0
        if __name__ == "__main__":
            self.lk = Lock()

    def _callback_gen(self, view):
        def process_callback(probe, hit):
            if __name__ == "__main__":
                self.lk.acquire()
                print("----", probe, "----")

                # check for errors:
                errname = "bson_err"
                if errname in hit.args:
                    err = hit.args[errname]
                    print("ERROR", error_strings[err])
                    if err == errors["KERNEL_FAULT"]:
                        self.kernel_faults = self.kernel_faults + 1
                    elif err == errors["KEY_ERROR"]:
                        self.key_errs = self.key_errs + 1
                    else:
                        self.others = self.others + 1

                else:
                    ptr = hit.args["ptr"]
                    bson = hit.args["bson"]
                    sz = hit.args["bson_sz"]
                    print("BSON REC'VED: [{}] [{}/{} bytes]".format(ptr, len(bson), sz))
                    try:
                        rbson = raw_bson.RawBSONDocument(bson)
                        print(dumps(rbson.raw))
                        self.successful = self.successful + 1
                    except Exception as e:
                        out = ""
                        for b in bson:
                            out += str(hex(b))
                        print(out)
                        print(e)
                        self.bad_bson = self.bad_bson + 1

                self.lk.release()
        return process_callback

    def dump_stats(self):
        total = self.others + self.key_errs + self.successful + self.kernel_faults + self.bad_bson
        if total == 0:
            return
        print("TOTAL:", total)
        print("successes:", self.successful, "[{}%]".format(round(self.successful*100/total, 3)))
        print("kernel faults:", self.kernel_faults, "[{}%]".format(round(self.kernel_faults*100/total, 3)))
        print("key errs:", self.key_errs, "[{}%]".format(round(self.key_errs*100/total, 3)))
        print("others:", self.others, "[{}%]".format(round(self.others*100/total, 3)))
        print("bad bsons:", self.bad_bson, "[{}%]".format(round(self.bad_bson*100/total, 3)))

####################################################################################

def sigint_handler_gen(mr, tt):
    def handler(signal, frame):
        mr.kill_all()
        print("-----------------------------------")
        print(str(tt))
        tt.dump_stats()
        exit(0)
    return handler

def ptr_and_bson_probe(name, samples, chunk_sz, map_sz):
    return {PROBE_NAME_KEY: name,
                 SAMPLES_PROPORTION_KEY: samples,
                 MAX_STR_SZ_KEY: chunk_sz,
                 MAX_MAP_SZ_KEY: map_sz,
                 PROBE_ARGS_KEY: [
                    {ARG_TYPE_KEY: POINTER_TYPE, ARG_NAME_KEY: "ptr"},
                    {ARG_TYPE_KEY: LONG_STRING_TYPE, ARG_NAME_KEY: "bson"}
                 ]}

# Main #

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gather data from QueryRequests.")
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

    args = parser.parse_args()
    print(args)

    mr = None
    time_table = QueryTimeTable(None)

    workers = []
    for probe_name in ["queryRequestFilter", "queryRequestProj", "queryRequestSort", "queryRequestHint",
                       "queryRequestReadConcern", "queryRequestCollation", "queryRequestUnwrappedReadPref"]:
        worker = USDTThread(args.pid[0], [ptr_and_bson_probe(probe_name, args.sample, args.chunk, args.map)], time_table)
        workers.append(worker)

    mr = WorkerMaster(workers)
    mr.start_all()

    signal(SIGINT, sigint_handler_gen(mr, time_table))
    Event().wait() # wait for keyboard interrupt forever
