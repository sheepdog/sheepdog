#! /usr/bin/env python3.4

# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

# Based on: http://lttng.org/docs/#doc-viewing-and-analyzing-your-traces

# how to use:
# request.py <path of directory which contains trace data>
#
# example:
# request.py ~/lttng-traces/sheepdog-rxtx-20150116-151005/ust/uid/0/64-bit/

import sys
import babeltrace
from enum import Enum
import copy

class Phase(Enum):
    Uninitialized = 0
    Rx_work = 1
    Rx_main = 2
    Tx_work = 3
    Tx_main = 4
    Incorrect = 5

nr_completed_reqs = 0
total_required_time = 0
worst_latency = -1
best_latency = sys.maxsize

class Request:
    def __init__(self, id_ptr):
        self.id_ptr = id_ptr
        self.phase = Phase.Uninitialized

        self.events = []

    def is_uninitialized(self):
        return self.phase == Phase.Uninitialized

    def is_finished(self):
        return self.phase == Phase.Tx_main

    def transition(self, evt):
        if self.phase == Phase.Incorrect:
            # do nothing on incorrect request
            return

        if self.phase == Phase.Uninitialized:
            if evt.name != "request:rx_work":
                self.phase = Phase.Incorrect
                return

            self.phase = Phase.Rx_work
            self.rwname = evt.name
            self.rx_work_timestamp = evt.timestamp
        
            return

        if self.phase == Phase.Rx_work:
            if evt.name != "request:rx_main":
                self.phase = Phase.Incorrect
                return

            self.phase = Phase.Rx_main

            return

        if self.phase == Phase.Rx_main:
            if evt.name != "request:tx_work":
                self.phase = Phase.Incorrect
                return

            self.phase = Phase.Tx_work

            return

        if self.phase == Phase.Tx_work:
            if evt.name != "request:tx_main":
                self.phase = Phase.Incorrect
                return

            self.phase = Phase.Tx_main

            global nr_completed_reqs
            global total_required_time
            global worst_latency
            global best_latency

            nr_completed_reqs += 1
            latency = evt.timestamp - self.rx_work_timestamp
            total_required_time += latency
            worst_latency = max(worst_latency, latency)
            best_latency = min(best_latency, latency)

            return
            
clients = {}

class Client:
    def __init__(self, id_fd):
        self.id_fd = id_fd
        self.ongoing_reqs = {}

    def feed_event(self, e):
        if not e['request'] in self.ongoing_reqs:
            if e.name != "request:rx_work":
                return
            req = Request(e['request'])
            self.ongoing_reqs[e['request']] = req
        else:
            req = self.ongoing_reqs[e['request']]

        req.transition(e)


def is_focusing_events(event):
    if event.name == "request:create_client":
        return True
    if event.name == "request:clear_client":
        return True
    if event.name == "request:rx_work":
        return True
    if event.name == "request:rx_main":
        return True
    if event.name == "request:tx_work":
        return True
    if event.name == "request:tx_main":
        return True
    return False

def req_stat():
    if len(sys.argv) != 2:
        msg = 'Usage: python {} TRACEPATH'.format(sys.argv[0])
        raise ValueError(msg)

    # a trace collection holds one to many traces
    col = babeltrace.TraceCollection()

    # add the trace provided by the user
    # (LTTng traces always have the 'ctf' format)
    if col.add_trace(sys.argv[1], 'ctf') is None:
        raise RuntimeError('Cannot add trace')

    # iterate events
    for _event in col.events:
        event = copy.copy(_event)
        if not is_focusing_events(event):
            continue

        if event.name == "request:create_client":
            client = Client(event['fd'])
            clients[event['fd']] = client
            continue
        if event.name == "request:clear_client":
            if event['fd'] in clients:
                clients.pop(event['fd'])
            continue

        # events of rx/tx
        if not event['fd'] in clients:
            continue

        clients[event['fd']].feed_event(event)

    print("stat of request latency from clients (QEMU, tgtd, dog)")
    print("(correctly parsed request: %d)" % nr_completed_reqs)
    print("average latency: %s ns" % "{0:,d}".format(int(total_required_time / nr_completed_reqs)))
    print("worst latency: %s ns" % "{0:,d}".format(worst_latency))
    print("best latency: %s ns" % "{0:,d}".format(best_latency))

if __name__ == '__main__':
    req_stat()
