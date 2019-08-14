#!/bin/python3

from sys import exit
from threading import Thread
from time import sleep

#####################################################################################

# Utilities #

class WorkerThread(Thread):
    def __init__(self, target, delay = 0, on_die = None):
        self.should_work = True
        self._do_work = target
        self._delay = delay
        self.on_die = on_die
        Thread.__init__(self, target=self._job)

    def _job(self):
        while self.should_work:
            if self._delay > 0:
                sleep(self._delay)
            self._do_work()
        if self.on_die: self.on_die()
        exit(0)

class WorkerMaster:
    def __init__(self, workers):
        self._workers = workers

    def start_all(self):
        for worker in self._workers:
            worker.start()

    def kill_all(self):
        for worker in self._workers:
            worker.should_work = False
            worker.join()

class Counter:
    """Tracks the proportion of values recieved for a property, like a pie chart."""
    def __init__(self):
        self.props = dict()
        self.total = 0

    def encounter(self, val):
        if val not in self.props:
            self.props[val] = 1
        else:
            self.props[val] = self.props[val] + 1
        self.total = self.total + 1

    def probability(self, val):
        if val in self.props:
            return self.props[val]/self.total
        else:
            return 0

    def __str__(self):
        out = "[total {}]\n".format(str(self.total))
        for prop in self.props:
            p = int(100*self.probability(prop))
            if p > 0:
                line = " - {}: {}%\n".format(prop, p)
                out += line
        return out

class Timer:
    """Tracks time between hits for a single probe."""
    def __init__(self):
        self.avg_frequency = 0
        self.avg_interevent_time = 0
        self.total_interevent_time = 0
        self.count = 0

    def tick(self, hit, prev = None):
        if prev == None:
            prev = hit.prev
        ns = prev.ns if prev != None else hit.ns
        # ns -> s
        last_dt = (hit.ns - ns)/1000000000
        self.total_interevent_time = self.total_interevent_time + last_dt
        self.count = self.count + 1
        # rolling avg, unweighted
        self.avg_interevent_time = self.total_interevent_time / self.count
        self.avg_frequency = self.count / self.total_interevent_time

    def get_unit_str(v, unit):
        if v <= 0.01:
            return "{}m{}".format(round(v*1000, 3), unit)
        elif v >= 1000:
            return "{}k{}".format(round(v/1000, 3), unit)
        else:
            return "{}{}".format(round(v, 3), unit)

    def combine(timers):
        tt = Timer()
        for timer in timers:
            tt.count += timer.count
            tt.total_interevent_time += timer.total_interevent_time
            tt.avg_interevent_time = tt.total_interevent_time / tt.count
            tt.avg_frequency = tt.count / tt.total_interevent_time
        return tt

    def __str__(self):
        out = "samples: {}\n".format(self.count)
        out += "average interval: {}\n".format(Timer.get_unit_str(self.avg_interevent_time, "s"))
        return out

class StartStopTimer(Timer):
    """Tracks time between start and end probe pairs."""
    def __init__(self, start, end):
        Timer.__init__(self)
        self.start = start
        self.end = end
        self.start_stack = []

    def tick(self, hit):
        if hit.name == self.start:
            self.start_stack.append(hit)
        elif len(self.start_stack) > 0:
            assert hit.name == self.end
            prev = self.start_stack[-1]
            self.start_stack.pop(len(self.start_stack) - 1)
            super().tick(hit, prev)
