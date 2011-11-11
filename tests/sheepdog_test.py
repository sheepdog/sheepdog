#
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from subprocess import *
import os
import re

sheep_path = os.environ.get('SHEEP')
collie_path = os.environ.get('COLLIE')


class VirtualMachine:
    def __init__(self, node, vdi):
        self.node = node
        self.vdi = vdi

    def read(self, offset, size):
        """Emulate read requests."""
        vdiname = 'sheepdog:localhost:' + str(self.node.get_port()) \
                  + ':' + self.vdi.name
        p = Popen(['qemu-io', vdiname, 'read', str(offset), str(size)], stdout=PIPE)
        return p

    def write(self, offset, size):
        """Emulate write requests."""
        vdiname = 'sheepdog:localhost:' + str(self.node.get_port()) \
                  + ':' + self.vdi.name
        p = Popen(['qemu-io', vdiname, 'write', str(offset), str(size)], stdout=PIPE)
        return p

    def test_io(self, cmd, case, async=False):
        sed_pattern = "s/[0-9]* ops\; [0-9/:. sec]* ([0-9/.inf]* " \
              + "[EPTGMKiBbytes]*\/sec and [0-9/.inf]* ops\/sec)/" \
              + "X ops\; XX:XX:XX.X (XXX YYY\/sec and XXX ops\/sec)/"
        aio_pattern = "s/bytes at offset [0-9]*/bytes at offset XXX/g"

        vdiname = 'sheepdog:localhost:' + str(self.node.get_port()) \
                  + ':' + self.vdi.name

        p = Popen(cmd + [vdiname], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        (out, err) = p.communicate(case)

        out = re.sub("qemu-io>[\ \n]", "", out).strip()
        p = Popen(["sed", "-e", sed_pattern],  stdin=PIPE, stdout=PIPE)
        (out, _) = p.communicate(out)

        if async:
            p = Popen(["sed", "-e", aio_pattern], stdin=PIPE, stdout=PIPE)
            (out, _) = p.communicate(out.strip())

        return (out.strip(), err.strip())

class VirtualDiskImage:
    def __init__(self, name, size):
        self.name = name
        self.size = size
        self.p = Popen([collie_path, 'vdi', 'create', name, str(size)], stdout=PIPE)

    def wait(self):
        """Wait until this vdi is created."""
        self.p.wait()

    def destroy(self):
        p = Popen([collie_path, 'vdi', 'delete', self.name], stdout=PIPE)
        return p


class Node:
    seq_nr = 0

    def __init__(self):
        self.idx = Node.seq_nr
        Node.seq_nr = Node.seq_nr + 1

        self.started = False
        self.p = None

    def __del__(self):
        self.stop()

    def get_port(self):
        return 7000 + self.idx

    def get_zone(self):
        return 10000 + self.idx

    def start(self):
        """Run a sheep daemon on this node."""
        if self.p and self.p.poll() == None:
            return

        self.p = Popen([sheep_path, '-f', '-d', '-p', str(self.get_port()),
                        str(self.idx), '-z', str(self.get_zone())],
                       stdout=PIPE, stderr=PIPE)

    def wait(self):
        """Wait until this node joins Sheepdog."""
        if self.started:
            return

        while True:
            line = self.p.stderr.readline()
            if not line:
                break
            match = re.search(r'join Sheepdog cluster', line)
            if match:
                self.started = True
                self.p.stderr=None
                break

    def stop(self):
        """Stop the sheep daemon on this node."""
        if self.p != None:
            self.p.terminate()
            self.p = None

        self.started = False

    def create_vm(self, vdi):
        """Create a VM instance on this node."""
        if self.p is None:
            return None

        return VirtualMachine(self, vdi)

    def run_collie(self, cmd):
        """Run administration commands on this node."""
        if self.p is None:
            return None

        p = Popen([collie_path + ' ' + cmd + ' -p ' + str(self.get_port())],
                  shell=True, stdout=PIPE)
        return p


class Sheepdog:
    def __init__(self, nr_nodes = 3):
        """Create a virtual Shepdog cluster with 'nr_nodes' nodes."""
        self.nodes = [Node() for _ in range(nr_nodes)]

    def create_vdi(self, name, size):
        return VirtualDiskImage(name, size)

    def format(self, node = None):
        """Format Sheepdog cluster."""
        if node is None:
            node = self.nodes[0]

        p = Popen([collie_path + ' cluster format -p ' + str(node.get_port())],
                  shell=True, stdout=PIPE)
        return p
