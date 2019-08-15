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

# can hint that the opCtx did or did not tranform to an aggregation pipeline
# by setting transformedToAgg to True or False
def clear(opCtx, print_query = False):
    #once all the data has been read, free up the memory
    if print_query:
        with FindCmdTimeTable.classLock:
            if opCtx in FindCmdTimeTable.dataDict:
                # TODO: make this more consistent
                # This may run before FindCmdTimeTable's callback has, in which
                # case there is no way to get the query out here unless more
                # concurrency controls are introduced (e.g. wait on a CV here)
                print(FindCmdTimeTable.dataDict[opCtx])
            else:
                print("Query unknown")

    # remove all opCtx entries for every probe
    for klass in PROBES.keys():
        with klass.classLock:
            if opCtx in klass.dataDict:
                del klass.dataDict[opCtx]


def print_if_ready(opCtx):
    # prints all the data associated with the provided opCtx if ready
    # Improvement: make sure all work is actually ready before getting out any
    # of it.
    try:
        request_body = None
        nss = None
        query = None
        ntoreturn = None
        ntoskip = None
        # read data from the first two probes that are always lit up
        # if their callbacks haven't run yet, will raise a KeyError
        with FindCmdTimeTable.classLock, QueryOpBeginTimeTable.classLock:
            if opCtx not in FindCmdTimeTable.dataDict or opCtx not in QueryOpBeginTimeTable.dataDict:
                return
            request_body = FindCmdTimeTable.dataDict[opCtx]
            nss = QueryOpBeginTimeTable.dataDict[opCtx]['nss']
            query = QueryOpBeginTimeTable.dataDict[opCtx]['bson']
            ntoreturn = QueryOpBeginTimeTable.dataDict[opCtx].get('ntoreturn', None)
            ntoskip = QueryOpBeginTimeTable.dataDict[opCtx].get('ntoskip', None)

        aggQuery = None
        # Determine if the query got routed through aggregation
        with FindToAggTimeTable.classLock:
            base = FindToAggTimeTable.dataDict.get(opCtx)
            if base:
                aggQuery = base['aggQuery']
                transformedToAgg = True

        summaryStats = None
        numResults = None
        planSummary = None
        if not aggQuery:
            # if it executed as a find query, there are some stats available
            with QueryOpEndTimeTable.classLock:
                if opCtx not in QueryOpEndTimeTable.dataDict:
                    return
                summaryStats = QueryOpEndTimeTable.dataDict[opCtx]['summaryStats']
                numResults = QueryOpEndTimeTable.dataDict[opCtx]['numResults']
            with FindCmdPlanTimeTable.classLock:
                if opCtx not in FindCmdPlanTimeTable.dataDict:
                    return
                planSummary = FindCmdPlanTimeTable.dataDict[opCtx]['planSummary']

        clear(opCtx)

        #print it all out
        print("Request body: ", request_body)
        print("Namespace: ", nss, ", running query: ", query)
        if ntoreturn:
            print("ntoreturn: ", ntoreturn)
        if ntoskip:
            print("ntoskip: ", ntoskip)
        if aggQuery:
            print("Was re-written to an aggregation query: ", aggQuery)
        else:
            print("Had the plan ", planSummary)
            print("Had statistics: ", summaryStats)
            print("and returned: ", numResults)
        print('\n\n\n')
    except KeyError:
        # we are missing some data. TODO: improve data cleanup here
        print("Missing some info. Skipping this hit!")

# TODO: Make an intermediate class between TimeTable and all of these
# derived classes that encapsulates the classLock and dataDict attributes
# also have the callbacks be hollywood style calls (template method)
# as the style is generally the same: get out the opCtx, probe-specific data,
# call print_if_ready w/ opCtx

# Each probe gets its own TimeTable class in order to get its own callback function.
# Not sure if a full TimeTable class is needed, but I'm sure some more interesting
# data could be scraped out of it.
class FindCmdTimeTable(TimeTable):
    probeName = 'findCmdRun'
    # a class-level dict w/ lock to store the data this probe produces.
    # is accessed and cleared in print_if_ready
    dataDict = dict()
    classLock = Lock()
    def __init__(self, view=None):
        TimeTable.__init__(self, view)
        self.on_add = self._callback_gen(view)

    def _callback_gen(self, view):
        def process_callback(probe, hit):
            bson = hit.args['bson']
            opCtx = hit.args["opCtx"]
            with FindCmdTimeTable.classLock:
                FindCmdTimeTable.dataDict[opCtx] = dumps(bson)
            print_if_ready(opCtx)
        return process_callback

class QueryOpBeginTimeTable(TimeTable):
    probeName = 'beginQueryOp'
    dataDict = dict()
    classLock = Lock()
    def __init__(self):
        TimeTable.__init__(self, None)
        self.on_add = self._callback_gen()

    def _callback_gen(self, view=None):
        def process_callback(probe, hit):
            opCtx = hit.args['opCtx']
            with QueryOpBeginTimeTable.classLock:
                QueryOpBeginTimeTable.dataDict[opCtx] = dict()
                nss = str(hit.args['nss'], 'utf-8')
                QueryOpBeginTimeTable.dataDict[opCtx]['nss'] = nss
                try:
                    QueryOpBeginTimeTable.dataDict[opCtx]['bson'] = dumps(raw_bson.RawBSONDocument(hit.args['bson']).raw)
                except:
                    #TODO: need to determine why we read out invalid BSON at times
                    #Ideas include concurrency issues (read while writing), or a subtle
                    #map usage error (like needing a per-cpu array map vs just an array map)
                    #haven't experienced an invalid BSON issue with other probes here though,
                    #which is interesting
                    print("THIS IS INVALID BSON: ")
                    print(hit.args['bson'].hex())
                if hit.args['ntoreturn'] != -1:
                    QueryOpBeginTimeTable.dataDict[opCtx]['ntoreturn'] = hit.args['ntoreturn']
                if hit.args['ntoskip'] != -1:
                    QueryOpBeginTimeTable.dataDict[opCtx]['ntoskip'] = hit.args['ntoskip']
            print_if_ready(opCtx)
        return process_callback

class FindToAggTimeTable(TimeTable):
    probeName = 'findToAgg'
    dataDict = dict()
    classLock = Lock()
    def __init__(self):
        TimeTable.__init__(self, None)
        self.on_add = self._callback_gen()

    def _callback_gen(self, view=None):
        def process_callback(probe, hit):
            opCtx = hit.args['opCtx']
            with FindToAggTimeTable.classLock:
                FindToAggTimeTable.dataDict[opCtx] = {
                    'aggQuery': dumps(hit.args['aggQuery'])
                }
            print_if_ready(opCtx)
        return process_callback

class FindCmdPlanTimeTable(TimeTable):
    probeName = 'findCmdPlan'
    dataDict = dict()
    classLock = Lock()
    def __init__(self):
        TimeTable.__init__(self, None)
        self.on_add = self._callback_gen()

    def _callback_gen(self, view=None):
        def process_callback(probe, hit):
            opCtx = hit.args['opCtx']
            with FindCmdPlanTimeTable.classLock:
                FindCmdPlanTimeTable.dataDict[opCtx] = dict()
                FindCmdPlanTimeTable.dataDict[opCtx]['planSummary'] = hit.args['planSummary'][:hit.args['planSummary_sz']]
            print_if_ready(opCtx)
        return process_callback

class FindCmdFailedTimeTable(TimeTable):
    probeName = 'findCmdExecFail'
    # kept for a consistent interface. Not really needed as this doesn't
    # have to store that an opCtx ended up failing
    dataDict = dict()
    classLock = Lock()
    def __init__(self):
        TimeTable.__init__(self, None)
        self.on_add = self._callback_gen()

    def _callback_gen(self, view=None):
        def process_callback(probe, hit):
            print("find failed!")
            opCtx = hit.args['opCtx']
            # remove all data collected for this Op
            clear(opCtx, print_query=True)
            print('\n\n\n')
        return process_callback


class QueryOpEndTimeTable(TimeTable):
    probeName = 'endQueryOp'
    dataDict = dict()
    classLock = Lock()
    def __init__(self):
        TimeTable.__init__(self, None)
        self.on_add = self._callback_gen()

    def _callback_gen(self, view=None):
        def process_callback(probe, hit):
            opCtx = hit.args['opCtx']
            with QueryOpEndTimeTable.classLock:
                QueryOpEndTimeTable.dataDict[opCtx] = dict()
                QueryOpEndTimeTable.dataDict[opCtx]['summaryStats'] = hit.args['summaryStats']
                QueryOpEndTimeTable.dataDict[opCtx]['numResults'] = hit.args['numResults']
            print_if_ready(opCtx)
        return process_callback

# Definition of all the probes. The class they are associated to is the key
PROBES = {
    FindCmdTimeTable: {
            PROBE_NAME_KEY: FindCmdTimeTable.probeName,
            PROBE_ARGS_KEY: [
                {
                    ARG_TYPE_KEY: POINTER_TYPE,
                    ARG_NAME_KEY: "opCtx" #TODO: make this key a constant
                },
                {
                    ARG_TYPE_KEY: LONG_STRING_TYPE,
                    ARG_NAME_KEY: 'bson'
                }
            ]
    },
    QueryOpBeginTimeTable:  {
            PROBE_NAME_KEY: QueryOpBeginTimeTable.probeName,
            PROBE_ARGS_KEY: [
                 {
                     ARG_TYPE_KEY: POINTER_TYPE,
                     ARG_NAME_KEY: "opCtx"
                 },{
                     ARG_TYPE_KEY: STRING_TYPE,
                     ARG_NAME_KEY: "nss",
                     ARG_STR_LEN_KEY: 50 #TODO: determine a realistic max length
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
    },
    FindToAggTimeTable: {
        PROBE_NAME_KEY: FindToAggTimeTable.probeName,
        PROBE_ARGS_KEY: [
            {
                ARG_TYPE_KEY: POINTER_TYPE,
                ARG_NAME_KEY: 'opCtx'
            },{
                ARG_TYPE_KEY: LONG_STRING_TYPE,
                ARG_NAME_KEY: 'aggQuery'
            }
        ]
    },
    FindCmdPlanTimeTable: {
        PROBE_NAME_KEY: FindCmdPlanTimeTable.probeName,
        PROBE_ARGS_KEY: [
            {
                ARG_TYPE_KEY: POINTER_TYPE,
                ARG_NAME_KEY: 'opCtx'
            },{
                ARG_TYPE_KEY: STRING_TYPE,
                ARG_STR_LEN_KEY: 100, #TODO: determine a realistic max length
                ARG_NAME_KEY: 'planSummary'
            },{
                ARG_TYPE_KEY: LONG_LONG_TYPE,
                ARG_NAME_KEY: 'planSummary_sz'
            }
        ]
    },
    FindCmdFailedTimeTable: {
        PROBE_NAME_KEY: FindCmdFailedTimeTable.probeName,
        PROBE_ARGS_KEY: [
            {
                ARG_TYPE_KEY: POINTER_TYPE,
                ARG_NAME_KEY: 'opCtx'
            }
        ]
    },
    QueryOpEndTimeTable: {
        PROBE_NAME_KEY: QueryOpEndTimeTable.probeName,
        PROBE_ARGS_KEY: [
            {
                ARG_TYPE_KEY: POINTER_TYPE,
                ARG_NAME_KEY: 'opCtx'
            },
            {
                ARG_TYPE_KEY: STRUCT_TYPE,
                ARG_NAME_KEY: 'summaryStats',
                ARG_STRUCT_FIELDS_KEY: [
                    {
                        ARG_TYPE_KEY: UNSIGNED_LONG_TYPE,
                        ARG_NAME_KEY: 'nReturned'
                    },{
                        ARG_TYPE_KEY: UNSIGNED_LONG_TYPE,
                        ARG_NAME_KEY: 'totalKeysExamined'
                    },{
                        ARG_TYPE_KEY: UNSIGNED_LONG_TYPE,
                        ARG_NAME_KEY: 'totalDocsExamined'
                    },{
                        ARG_TYPE_KEY: LONG_LONG_TYPE,
                        ARG_NAME_KEY: 'executionTimeMillis'
                    },{
                        ARG_TYPE_KEY: LONG_LONG_TYPE,
                        ARG_NAME_KEY: 'collectionScans'
                    },{
                        ARG_TYPE_KEY: LONG_LONG_TYPE,
                        ARG_NAME_KEY: 'collectionScansNonTailable'
                    },{
                        ARG_TYPE_KEY: CHAR_TYPE,
                        ARG_NAME_KEY: 'hasSortStage'
                    },{
                        ARG_TYPE_KEY: CHAR_TYPE,
                        ARG_NAME_KEY: 'usedDisk'
                    },{
                        ARG_TYPE_KEY: CHAR_TYPE,
                        ARG_NAME_KEY: 'fromMultiPlanner'
                    },{
                        ARG_TYPE_KEY: CHAR_TYPE,
                        ARG_NAME_KEY: 'replanned'
                    }
                ]
            },{
                ARG_TYPE_KEY: LONG_LONG_TYPE,
                ARG_NAME_KEY: 'numResults'
            }
        ]
    }
}


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
        workers = []
        for timetable, probe in PROBES.items():
            worker = USDTThread(args.pid[0], [probe], timetable())
            workers.append(worker)

        mr = WorkerMaster(workers)
        mr.start_all()
        
        # loop until keyboard interrupt
        sleep(99999)

    except KeyboardInterrupt:
        if mr:
            mr.kill_all()
