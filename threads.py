#!/bin/python3

import argparse
import curses
import json
import math

from collections import OrderedDict
from curses import textpad
from datetime import datetime
from threading import Lock

from generator.consts import PROBE_NAME_KEY
from wiredtimer import WiredTimeTable
from probes import TimeTable, USDTThread 
from util import WorkerThread

#################################################################################################################

def format_output(stdscr, string, color = curses.COLOR_WHITE):
        stdscr.add_str("{} | {}".format(datetime.now().time(), string), color)

# Commands #

class Commands:
    def __init__(self, pid, window, stdscr, time_table = None):
        self.history = []
        assert isinstance(window, Window)
        self.time_table = time_table
        self._result_win = window
        self._stdscr = stdscr
        self.pid = pid
        self.ptr = 0
        self.workerThread = None
        self.command_table = {
            "echo": self.echo,
            "exit": self.quit,
            "h": self.print_help,
            "help": self.print_help,
            "p": self.pct,
            "pct": self.pct,
            "t": self.tiger,
            "tiger": self.tiger,
            "q": self.quit,
            "quit": self.quit
        }

    def format_output(self, string, color = curses.COLOR_WHITE):
        format_output(self._stdscr, string, color)

    def echo(self, tokens):
        self.format_output(" ".join(tokens[1:]))

    def print_help(self, tokens):
        del tokens # ignore tokens
        self._stdscr.add_line('List of available commands:')
        for cmd in self.command_table:
            self._stdscr.add_line("- " + cmd)

    def print_error(self, cmd):
        self._stdscr.add_line("INVALID COMMAND: {}".format(cmd), curses.COLOR_RED)

    def quit(self, tokens):
        raise KeyboardInterrupt

    def _thread(self, worker):
        self.close()
        self.workerThread = worker
        self.workerThread.start()

    def close(self):
        if self.workerThread != None:
            self.workerThread.should_work = False
            format_output(self._result_win, "Joining worker...\n")
            self.workerThread.join()
            self._stdscr.erase()

    def pct(self, tokens):
        if len(tokens) < 2:
            self.print_error("Need at least one probe to sample.")
            return

        probe = tokens[1]
        if not self.time_table.has(probe):
            self.print_error("{} is not a valid probe".format(probe))
            return

        def pct_work():
            h = self.time_table.get(probe)
            self._stdscr.add_line(h)
            self._stdscr.add_line(str(time_table))

        self._thread(WorkerThread(pct_work, 1))

    def tiger(self, tokens):
        del tokens
        format_output(self._result_win, "Initializing WiredTiger tool...\n")
        tt = WiredTimeTable(self._stdscr)
        self._thread(USDTThread(self.pid, tt.probes, tt))

    def push(self, command):
        assert isinstance(command, str)
        if len(command) == 0:
            return

        self._stdscr.erase()
        tokens = command.split()
        valid = tokens[0] in self.command_table
        if valid:
            self.command_table[tokens[0]](tokens)
        else:
            self.print_error(command)

        self.history.append(command)
        self.ptr = self.ptr + 1
        format_output(self._result_win, command, curses.COLOR_GREEN if valid else curses.COLOR_RED)

    def prev(self):
        if len(self.history) == 0:
            return ""
        self.ptr = self.ptr - 1
        if self.ptr < 0:
            self.ptr = len(self.history) - 1
        return self.history[self.ptr]

    def next(self):
        if self.ptr == len(self.history):
            return ""
        self.ptr = self.ptr + 1
        return self.history[self.ptr - 1]

#################################################################################################################

# Curses #

# Global lock such that multiple USDT threads listening to the same
# probes don't try to write to the screen at the same time and produce
# garbage output.
lock = Lock()

class EventView:
    def __init__(self, event_win, pct_win):
        self.event_win = event_win
        self.pct_win = pct_win

    def on_probe_hit(self, event, summary, probe, probe_content):
        format_output(self.event_win, event)
        self.pct_win.fill_col("SUMMARY", summary)
        self.pct_win.fill_col(probe, probe_content)

class Window:
    def __init__(self, begin_x, begin_y, width, height):
        self.begin_x = begin_x
        self.begin_y = begin_y
        self.width = width
        # this is the minimum height
        #assert height >= 4
        self.height = height
        self._bgwin = curses.newwin(height, width + 1, begin_y, begin_x)
        self._win_dims = {
            "width": width - 3,
            "height": height - 2,
            "begin_x": begin_x + 1,
            "begin_y": begin_y + 1
        }
        self._window = curses.newwin(self._win_dims["height"],
                                     self._win_dims["width"],
                                     self._win_dims["begin_y"],
                                     self._win_dims["begin_x"])
        self._window.overlay(self._bgwin)
        self._prettify()
        self._bgwin.refresh()

    def _draw_borders(self):
        textpad.rectangle(self._bgwin, 0, 0, self.height - 1, self.width - 1)

    def _prettify(self):
        self._window.scrollok(True)
        self._window.setscrreg(0, self.height - 3)
        self._bgwin.attron(curses.A_DIM)
        self._window.attron(curses.A_BOLD)
        self._draw_borders()

    def _add_str(self, line, color):
        assert isinstance(line, str)
        lock.acquire()
        try:
            self._window.addstr(line, curses.color_pair(color))
        except curses.error:
            self._window.scroll(1)
        self._window.refresh()
        lock.release()

    def add_str(self, line, color=curses.COLOR_WHITE):
        self._add_str(line, color)

    def add_line(self, line, color=curses.COLOR_WHITE):
        self._add_str(line + "\n", color)

    def erase(self):
        lock.acquire()
        self._window.erase()
        lock.release()

    def overlay(self, window):
        assert isinstance(window, Window)
        self._bgwin.overlay(window._window)
        self._bgwin.refresh()

class TallTable(Window):
    def __init__(self, begin_x, begin_y, width, height, titles):
        Window.__init__(self, begin_x, begin_y, width, height)

        ncols = len(titles)
        assert ncols > 0

        self._ncols = ncols
        self._colw = int(self._win_dims["width"]/ncols)
        self.titles = titles
        self._titles = OrderedDict()
        self.cols = OrderedDict()

        # create individual columns
        for i in range(0, ncols):
            col_offset = self._win_dims["begin_x"] + i*self._colw
            self._titles[titles[i]] = Window(begin_x = col_offset,
                                             begin_y = self._win_dims["begin_y"],
                                             width = self._colw,
                                             height = 4)

            self._titles[titles[i]].overlay(self)
            self._titles[titles[i]]._window.refresh()
            self._titles[titles[i]].add_str(titles[i])

            self.cols[titles[i]] = Window(begin_x = col_offset,
                                          begin_y = self._win_dims["begin_y"] + 4,
                                          width = self._colw,
                                          height = self._win_dims["height"] - 4)

            self.cols[titles[i]].overlay(self)

    def add_row(self, string, color=curses.COLOR_WHITE):
        # string must be formatted with column entries separates by " | "
        tokens = string.split(" | ")
        newlns = 0

        # format multiline column entries to have obvious rows
        for token in tokens:
            if len(token) >= self._colw:
                newlns = max(newlns, int(len(token) / self._colw))
        for i in range(0, len(self.cols)):
            self.cols[self.titles[i]].add_line(tokens[i])
            for n in range(0, min(newlns, newlns - int(len(tokens[i]) / self._colw))):
                self.cols[self.titles[i]].add_line("")

    def add_str(self, string, color=curses.COLOR_WHITE):
        self.add_row(string, color)

    def add_line(self, string, color=curses.COLOR_WHITE):
        self.add_row(string, color)

    def fill_col(self, name, string, color=curses.COLOR_WHITE):
        self.cols[name].erase()
        self.cols[name].add_str(string, color)

class TextBox(Window):
    def __init__(self, begin_x, begin_y, width, height, commands = None):
        Window.__init__(self, begin_x, begin_y, width, height)
        self._textbox = textpad.Textbox(self._window)
        self.commands = commands

    def _validator(self, ch):
        if ch in [curses.KEY_BACKSPACE, curses.KEY_LEFT, curses.KEY_RIGHT]:
            self._textbox.do_command(ch)
        # because KEY_ENTER is 'unreliable'
        elif ch in [curses.KEY_ENTER, ord('\n')]:
            self.commands.push(self._textbox.gather())
            self._window.erase()
            self._window.refresh()
        elif ch in [curses.KEY_UP, curses.KEY_DOWN]:
            self._window.erase()
            self._window.addstr(self.commands.prev() if ch == curses.KEY_UP else self.commands.next())
            self._window.refresh()
        else:
            self._window.addch(ch)

    def focus(self):
        self._window.move(0, 0)
        curses.curs_set(1)
        self._window.refresh()
        self._window.leaveok(1)

    def user_edit(self):
        self.focus()
        self._textbox.edit(lambda ch : self._validator(ch))

def init_colors():
    curses.init_pair(curses.COLOR_WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(curses.COLOR_RED, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(curses.COLOR_GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)

#################################################################################################################

# Main #

def main(pid, probes, stdscr):
    """ Collects information about threads from USDT probes. """
    H = curses.LINES
    W = curses.COLS
    MIN_H = 4

    left_w = int(max(0.15*W, 48))
    right_w = W - left_w - 1 

    # left UI column
    tb = TextBox(begin_x = 1,
                 begin_y = 1,
                 width = left_w,
                 height = MIN_H)

    cmd_out_win = Window(begin_x = 1,
                         begin_y = MIN_H + 1,
                         width = left_w,
                         height = int(0.25*(H - MIN_H - 1)))

    out_win = Window(begin_x = 1,
                     begin_y = cmd_out_win.begin_y + cmd_out_win.height + 1,
                     width = left_w,
                     height = int(0.75*(H - MIN_H - 1)))

    tb.commands = Commands(pid, cmd_out_win, out_win)

    # colors
    init_colors()
    format_output(cmd_out_win, "Has colors!\n" if curses.has_colors() else "Sorry, no colors :(\n")

    # right UI column
    pct_cols = ["SUMMARY"] + list([probe[PROBE_NAME_KEY] for probe in probes])

    event_win = TallTable(begin_x = left_w + 1,
                          begin_y = 1,
                          width = right_w,
                          height = int(0.35*(H - 1)),
                          titles = ["TIME", "PROBE", "COMM", "PID", "TID", "NS", "CPU"])

    pct_win = TallTable(begin_x = left_w + 1,
                        begin_y = event_win.begin_y + event_win.height + 1,
                        width = right_w,
                        height = int(0.65*(H - 1)),
                        titles = pct_cols)

    tt_view = EventView(event_win, pct_win)

    # init probes time_table
    time_table = TimeTable(tt_view)
    tb.commands.time_table = time_table
    
    # poll usdt
    format_output(cmd_out_win, "Initializing BPF...\n")
    worker = USDTThread(pid, probes, time_table)
    format_output(cmd_out_win, "BPF Initialized.\n", curses.COLOR_GREEN)
    worker.start()

    # while parent is accepting user input
    try:
        tb.user_edit()
    finally:
        worker.should_work = False
        worker.join()
        tb.commands.close()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Gather generic data about USDT probes and " +
    "run tools to display specific information about certain probes.")

    parser.add_argument('pid',
                        metavar='pid',
                        type=int,
                        nargs=1,
                        help='pid of process emitting probes')

    args = parser.parse_args()
    pid = args.pid[0]
    probes = WiredTimeTable.get_wiredtiger_probes()

    try:
        curses.wrapper(lambda stdscr: main(pid, probes, stdscr))
    except KeyboardInterrupt:
        print("User exited.")
