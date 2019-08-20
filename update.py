#!/bin/python3

import argparse
import bson.raw_bson as raw_bson

from bsonjs import dumps
from generator.consts import *
from generator.generator import Probe
from probes import ProbeHit, ProbeHistory, TimeTable, USDTThread, USDTArg
from signal import signal, SIGINT
from threading import Event, Lock
from util import WorkerMaster, WorkerThread

####################################################################################

class BSONTimeTable(TimeTable):
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
                errname = "objdata_{}_err".format(probe)
                if errname in hit.args:
                    err = hit.args[errname]
                    print("ERROR", err)
                    if err == -3:
                        self.kernel_faults = self.kernel_faults + 1
                    elif err == -4:
                        self.key_errs = self.key_errs + 1
                    else:
                        self.others = self.others + 1

                else:
                    bson = hit.args["objdata_{}".format(probe)]
                    sz = hit.args["objdata_{}_sz".format(probe)]
                    print("printing", sz)
                    try:
                        rbson = raw_bson.RawBSONDocument(bson)
                        print(dumps(rbson.raw))
                        self.successful = self.successful + 1
                    except:
                        out = ""
                        for b in bson:
                            out += str(hex(b))
                        print(out)
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
        tt.dump_stats()
        exit(0)
    return handler

# Main #

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gather timing data from WiredTiger.")
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
    time_table = BSONTimeTable(None)

    workers = []
    for probe_name in ["updateQuery", "updateProj", "updateSort"]:
        probe = {PROBE_NAME_KEY: probe_name,
                 SAMPLES_PROPORTION_KEY: args.sample,
                 MAX_STR_SZ_KEY: args.chunk,
                 MAX_MAP_SZ_KEY: args.map,
                 PROBE_ARGS_KEY: [{ARG_TYPE_KEY: LONG_STRING_TYPE,
                                   ARG_NAME_KEY: "objdata_{}".format(probe_name)}]}
        worker = USDTThread(args.pid[0], [probe], time_table)
        workers.append(worker)

    mr = WorkerMaster(workers)
    mr.start_all()

    signal(SIGINT, sigint_handler_gen(mr, time_table))
    Event().wait() # wait for keyboard interrupt forever
