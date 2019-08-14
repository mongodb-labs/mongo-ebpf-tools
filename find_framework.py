#!/usr/bin/python3

import argparse

from generator.consts import *
from generator.generator import Probe
from probes import ProbeHit, ProbeHistory, TimeTable, USDTThread, USDTArg
from threading import Lock, Condition
from time import sleep
from util import WorkerMaster, WorkerThread
import bson.raw_bson as raw_bson
from bsonjs import dumps

####################################################################################

def list_to_bson(to_conv, sz):
    to_conv = bytes(to_conv[:sz])
    return raw_bson.RawBSONDocument(to_conv)

map_lock = Lock()
cv = Condition(map_lock)
FIND_CMD_RUN = False
OPCTX_TO_BSON = dict()

class FindCmdTimeTable(TimeTable):
    def __init__(self, view):
        TimeTable.__init__(self, view)
        self.on_add = self._callback_gen(view)

    def _callback_gen(self, view):
        def process_callback(probe, hit):
            global FIND_CMD_RUN
            global OPCTX_TO_BSON
            if hit.name == "findCmdRun":
                bson = hit.args['bson']
                bson_sz = hit.args["bson_sz".format(probe)]
                # bson = bytes(bson[:bson_sz])
                rbson = raw_bson.RawBSONDocument(bson)
                with map_lock:
                    OPCTX_TO_BSON[hit.args["opCtx"]] = rbson
                    FIND_CMD_RUN = True
                    cv.notifyAll()
            else:
                assert hit.name == 'beginQueryOp'
                opctx = hit.args['opCtx']
                with cv:
                    while not FIND_CMD_RUN:
                        cv.wait()
                    if opctx not in OPCTX_TO_BSON:
                        print("OPCTX not in map")
                        return
                    my_bson = list_to_bson(hit.args['bson'], hit.args['bson_sz'])
                    print("BSONS match? ", dumps(my_bson.raw), dumps(OPCTX_TO_BSON[opctx].raw))
                    del OPCTX_TO_BSON[opctx]
                    FIND_CMD_RUN = False
                print(hit.args['nss'], hit.args['ntoreturn'], hit.args['ntoskip'])
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
        find_cmd_time_table = FindCmdTimeTable(None)

        workers = []
        findCmdRun = {
                PROBE_NAME_KEY: "findCmdRun",
                PROBE_ARGS_KEY: [
                    {
                        ARG_TYPE_KEY: POINTER_TYPE,
                        ARG_NAME_KEY: "opCtx"
                    },
                    {
                        ARG_TYPE_KEY: LONG_STRING_TYPE,
                        ARG_NAME_KEY: 'bson'
                    }
                ]
        }
        beginQueryOp =  {
                PROBE_NAME_KEY: "beginQueryOp",
                PROBE_ARGS_KEY: [
                     {
                         ARG_TYPE_KEY: POINTER_TYPE,
                         ARG_NAME_KEY: "opCtx"
                     },{
                         ARG_TYPE_KEY: STRING_TYPE,
                         ARG_NAME_KEY: "nss",
                         ARG_STR_LEN_KEY: 50
                     },{
                         ARG_TYPE_KEY: LONG_STRING_TYPE,
                         ARG_NAME_KEY: 'bson'
                     },{
                         ARG_TYPE_KEY: LONG_LONG_TYPE,
                         ARG_NAME_KEY: "ntoreturn"
                     },{
                         ARG_TYPE_KEY: LONG_LONG_TYPE,
                         ARG_NAME_KEY: "ntoskip"
                     }
                ]
        }
        for probe in [findCmdRun, beginQueryOp]:
            worker = USDTThread(args.pid[0], [probe], find_cmd_time_table)
            workers.append(worker)

        mr = WorkerMaster(workers)
        mr.start_all()
        
        # loop until keyboard interrupt
        sleep(99999)

    except KeyboardInterrupt:
        if mr:
            mr.kill_all()
