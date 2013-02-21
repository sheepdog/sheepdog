#! /usr/bin/env python

import sys, os, errno
import json, curses
import atexit

begin_sec, begin_usec = -1, -1

class LogRecord(object):
    def __init__(self, json_line, proc):
        json_obj = json.loads(json_line)

        user_info = json_obj['user_info']
        self.progname = user_info['program_name']
        self.port = user_info['port']

        body = json_obj['body']
        self.timestamp = { 'sec': body['second'], 'usec': body['usecond']}
        self.worker_name = body['worker_name']
        self.worker_idx = body['worker_idx']
        self.func = body['func']
        self.line = body['line']
        self.msg = body['msg']

        self.proc = proc
        self.color = None

    def is_sheep(self):
        return self.progname == 'sheep'

    def get_color(self):
        return self.proc.color

    def pop(self):
        ret = self.proc.__pop_next_record__()
        assert ret == self
        return ret

    def __lt__(self, other):
        if self.timestamp['sec'] < other.timestamp['sec']:
            return True
        elif other.timestamp['sec'] < self.timestamp['sec']:
            return False

        if self.timestamp['usec'] < other.timestamp['usec']:
            return True

        return False

    def format_line(self, max_x):
        sec = self.timestamp['sec']
        usec = self.timestamp['usec']
        udelta = usec - begin_usec
        if udelta < 0:
            udelta += 1000000
            sec -= 1
        t = '%d.%06d' % (sec - begin_sec, udelta)

        ret = '%s+%s: ' % (' ' * (10 - len(t[:10])), t[:10])
        if self.progname == 'sheep':
            hdr = 'sheep %d,%s(%d) ' % \
                (self.port, self.func, self.line)
            ret += hdr[:40] + ' ' * (40 - len(hdr[:40]) + 1)
            ret += self.msg

        return ret[:max_x - 1]

        return self.msg

class Process(object):
    def __init__(self, log_file_path):
        self.log_file = open(log_file_path)

        self.next_record = None
        self.color = None

    def set_color(self, color):
        self.color = color

    def peek_next_record(self):
        if self.next_record == None:
            next_line = self.log_file.readline()
            if next_line == '':
                # end of the log
                return None

            self.next_record = LogRecord(next_line, self)
        return self.next_record

    # __pop_next_record__() must be called by LogRecord
    def __pop_next_record__(self):
        assert self.next_record != None
        ret = self.next_record
        self.next_record = None
        return ret

dying_msg = ''

w = None
curses_colors = [
    curses.COLOR_RED,
    curses.COLOR_GREEN,
    curses.COLOR_YELLOW,
    curses.COLOR_BLUE,
    curses.COLOR_MAGENTA,
    curses.COLOR_CYAN,
    ]
nr_curses_colors = len(curses_colors)

def init_curses():
    global w

    w = curses.initscr()
    curses.nonl()
    curses.cbreak()
    curses.noecho()

    curses.start_color()
    for i in range(1, nr_curses_colors + 1):
        curses.init_pair(i, curses_colors[i - 1], curses.COLOR_BLACK)

def assign_color(procs):
    sheeps = []
    for proc in procs:
        if proc.peek_next_record().is_sheep():
            sheeps.append(proc)
    nr_sheeps = len(sheeps)

    if nr_curses_colors < nr_sheeps:
        # we don't have enough colors to assign...
        return

    for i in range(0, nr_sheeps):
        sheeps[i].set_color(i + 1)

current_y = 0
max_y, max_x = 0, 0
records = []
records_len = 0

def unify_records(procs):
    first_rec = procs[0].peek_next_record()
    for proc in procs[1:]:
        rec = proc.peek_next_record()
        if rec < first_rec:
            first_rec = rec

    records.append(first_rec.pop())

    global begin_sec, begin_usec
    begin_sec = first_rec.timestamp['sec']
    begin_usec = first_rec.timestamp['usec']

    nr_procs = len(procs)
    is_empty = [False] * nr_procs
    nr_empteis = 0
    while nr_empteis != nr_procs:
        next_rec = None

        for i in range(0, nr_procs):
            if is_empty[i]:
                continue

            proc = procs[i]
            rec = proc.peek_next_record()

            if rec == None:
                is_empty[i] = True
                nr_empteis += 1
                continue

            if next_rec == None:
                next_rec = rec
                continue

            if rec < next_rec:
                next_rec = rec
                continue

        if next_rec == None:
            assert nr_empteis == nr_procs
            break

        records.append(next_rec.pop())

def update_terminal():
    w.clear()

    for i in range(0, max_y):
        w.move(i, 0)
        if not current_y + i < records_len:
            break

        record = records[current_y + i]

        color = record.get_color()
        if color:
            w.attrset(curses.color_pair(color))

        w.addstr(record.format_line(max_x))

        if color:
            w.attroff(curses.color_pair(color))

    w.refresh()

if __name__ == '__main__':
    @atexit.register
    def exit_handler():
        curses.endwin()
        if dying_msg != '':
            print dying_msg + '\n'

    init_curses()

    procs = map(lambda x: Process(x), sys.argv[1:])
    assign_color(procs)
    unify_records(procs)
    records_len = len(records)

    tty_file = open('/dev/tty', 'rb')

    max_y, max_x = w.getmaxyx()
    update_terminal()
    running = True

    while running:
        try:
            key = tty_file.read(1)
        except IOError, (enr, msg):
            if enr == errno.EINTR:
                continue

            dying_msg = 'fatal error: %s' % \
                (os.strerror(enr))
            break

        if key == 'q':
            break
        elif key == 'j':
            if current_y + 1 < records_len:
                current_y += 1
        elif key == 'k':
            if current_y:
                current_y -= 1
        elif key == ' ':
            if current_y + max_y < records_len:
                current_y += max_y
        elif key == 'g':
            current_y = 0
        elif key == 'G':
            current_y = records_len - max_y

        update_terminal()
