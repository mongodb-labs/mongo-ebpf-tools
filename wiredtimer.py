#!/bin/python3

import argparse

from generator.consts import PROBE_NAME_KEY, PROBE_ARGS_KEY, ARG_NAME_KEY, ARG_TYPE_KEY, INT_TYPE
from probes import ProbeHit, ProbeHistory, TimeTable, USDTThread, USDTArg
from sys import exit
from signal import signal, SIGINT
from threading import Event
from util import WorkerThread, Timer, StartStopTimer

#####################################################################################

class WiredTimeTable(TimeTable):
    def __init__(self, view):
        TimeTable.__init__(self, view)
        self.on_add = self._callback_gen(view)
        self.timers = dict()
        self.probe_intervals = WiredTimeTable.get_wiredtiger_probe_roots()
        self.probes = WiredTimeTable.get_wiredtiger_probes()
        for probe_int in self.probe_intervals:
            self.timers[probe_int] = dict()

    def add(self, probe, hit):
        key = probe.replace("_start", "").replace("_end", "")
        if hit.tid not in self.timers[key]:
            self.timers[key][hit.tid] = StartStopTimer(key + "_start", key + "_end")
        self.timers[key][hit.tid].tick(hit)
        super().add(probe, hit)

    def _callback_gen(self, view):
        def process_callback(probe, hit):
            out = "Last probe hit: {}\n".format(probe)
            for field in hit.args:
                out += "{}: {}\n".format(field, hit.args[field])
            out += "\n"
            key = probe.replace("_start", "").replace("_end", "")
            for k in self.timers:
                for tid in self.timers[k]:
                    h = self.get(key+"_start").last_hit(tid)
                    if h == None:
                        continue
                    out += "{}[{}:{}]\n".format(k, h.comm, tid)
                    out += str(self.timers[k][tid]) + '\n'
                if len(self.timers[k].values()) > 1:
                    timer = Timer.combine(self.timers[k].values())
                    out += "{} stats for all threads:\n".format(k) + str(timer) + '\n'
            if __name__ == '__main__':
                print(out)
                print(str(self))
            else:
                view.erase()
                view.add_line(out)
        return process_callback

    def get_wiredtiger_probe_roots():
        return ["WiredTiger_findRecord",
                "WiredTiger_insertRecords",
                "WiredTiger_deleteRecord",
                "WiredTiger_updateRecord"]

    def get_wiredtiger_probes():
        probes = [{PROBE_NAME_KEY: "WiredTiger_findRecord_start"},
                  {PROBE_NAME_KEY: "WiredTiger_findRecord_end"},
                  {PROBE_NAME_KEY: "WiredTiger_deleteRecord_start"},
                  {PROBE_NAME_KEY: "WiredTiger_deleteRecord_end"},
                  {PROBE_NAME_KEY: "WiredTiger_updateRecord_start",
                   PROBE_ARGS_KEY: [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "length"}]},
                  {PROBE_NAME_KEY: "WiredTiger_updateRecord_end",
                   PROBE_ARGS_KEY: [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "length"}]},
                  {PROBE_NAME_KEY: "WiredTiger_insertRecords_start",
                   PROBE_ARGS_KEY: [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "count"}]},
                  {PROBE_NAME_KEY: "WiredTiger_insertRecords_end",
                   PROBE_ARGS_KEY: [{ARG_TYPE_KEY: INT_TYPE, ARG_NAME_KEY: "count"}]}]
        return probes

#####################################################################################

def sigint_handler_gen(worker):
    def handler(signal, frame):
        worker.should_work = False
        worker.join()
        print("\nDone.")
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
    args = parser.parse_args()

    time_table = WiredTimeTable(None)
    worker = USDTThread(args.pid[0], time_table.probes, time_table)
    worker.start()
    print("Listening to WiredTiger probes.")

    signal(SIGINT, sigint_handler_gen(worker))
    Event().wait() # wait for keyboard interrupt forever
