#!/bin/python3

import argparse

from generator.consts import *
from generator.generator import Probe
from probes import ProbeHit, ProbeHistory, TimeTable, USDTThread, USDTArg
from threading import Lock
from time import sleep
from util import WorkerMaster, WorkerThread, Timer, Timer2

####################################################################################

class QueryTimeTable(TimeTable):
    def __init__(self, view):
        TimeTable.__init__(self, view)
        self.on_add = self._callback_gen(view)
        if __name__ == "__main__":
            self.lk = Lock()

    def _callback_gen(self, view):
        def process_callback(probe, hit):
            if __name__ == "__main__":
                self.lk.acquire()
                print("----", probe, "----")
                print(hit.get_field("objdata_{}".format(probe)),
                      hit.get_field("objdata_{}_sz".format(probe)))
                self.lk.release()
        return process_callback

####################################################################################

# Main #

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Gather timing data from WiredTiger.")
    parser.add_argument('pid',
                        metavar='pid',
                        type=int,
                        nargs=1,
                        help='pid of process emitting probes')
    args = parser.parse_args()
    print(args)

    mr = None
    try:
        time_table = QueryTimeTable(None)

        workers = []
        for probe_name in ["query", "query1", "query1R", "queryR", "query2", "query3"]:
            probe = {PROBE_NAME_KEY: probe_name,
                     PROBE_ARGS_KEY: [{ARG_TYPE_KEY: LONG_STRING_TYPE,
                                       ARG_NAME_KEY: "objdata_{}".format(probe_name)}]}
            worker = USDTThread(args.pid[0], [probe], time_table)
            workers.append(worker)

        mr = WorkerMaster(workers)
        mr.start_all()
        
        # loop until keyboard interrupt
        while True:
            pass

    except KeyboardInterrupt:
        if mr:
            mr.kill_all()
