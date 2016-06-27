import struct
import socket
import datetime
import random
import hashlib

import proto


class Connection(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._sock = socket.create_connection((host, port))

    def sendall(self, data):
        return self._sock.sendall(data)

    def recvall(self, totalsize):
        data = ''
        received = 0
        while received < totalsize:
            bufsize = min(4096, totalsize - received)
            buf = self._sock.recv(bufsize)
            received += len(buf)
            data += buf
        return data


class Inode(object):
    fmt = '<256s256sQQQQQBBBBLLLL4092x1048576L2097152L'
    size = struct.calcsize(fmt)
    packer = struct.Struct(fmt)

    def __init__(self, data):
        assert self.size == len(data)
        self.data = data
        pieces = self.packer.unpack(data)

        name = pieces[0]
        length = name.index('\0')
        self.name = name[:length]

        self.tag = pieces[1]
        self.create_time = pieces[2] >> 32
        self.snap_ctime = pieces[3] >> 32
        self.vm_clock_nsec = pieces[4]
        self.vdi_size = pieces[5]
        self.vm_state_size = pieces[6]
        self.copy_policy = pieces[7]
        self.store_policy = pieces[8]
        self.nr_copies = pieces[9]
        self.block_size_shift = pieces[10]
        self.snap_id = pieces[11]
        self.vdi_id = pieces[12]
        self.parent_vdi_id = pieces[13]
        self.btree_counter = pieces[14]

        self.data_vdi_id = pieces[15:1048591]
        self.generation_reference = pieces[1048591:3145728]


class VDIState(object):
    #   40 = sizeof(struct node_id)
    #   31 = SD_MAX_COPIES
    # 1240 = sizeof(struct node_id) * SD_MAX_COPIES
    fmt = '<LBBBBB3xLL40xL31L1240x'
    size = struct.calcsize(fmt)
    packer = struct.Struct(fmt)

    def __init__(self, data):
        assert self.size == len(data)
        self.data = data
        pieces = self.packer.unpack(data)

        self.vid = pieces[0]
        self.nr_copies = pieces[1]
        self.snapshot = pieces[2]
        self.deleted = pieces[3]
        self.copy_policy = pieces[4]
        self.block_size_shift = pieces[5]
        self.parent_vid = pieces[6]
        self.lock_state = pieces[7]
        self.nr_participants = pieces[8]
        self.participants_state = pieces[9:40]


class Request(object):
    fmt = '<BBHLLL32x'
    size = struct.calcsize(fmt)
    packer = struct.Struct(fmt)
    OBJ_OPS = (
        proto.SD_OP_CREATE_AND_WRITE_OBJ,
        proto.SD_OP_READ_OBJ,
        proto.SD_OP_WRITE_OBJ,
        proto.SD_OP_REMOVE_OBJ,
        proto.SD_OP_DISCARD_OBJ,
        proto.SD_OP_CREATE_AND_WRITE_PEER,
        proto.SD_OP_READ_PEER,
        proto.SD_OP_WRITE_PEER,
        proto.SD_OP_REMOVE_PEER,
    )
    VDI_OPS = (
        proto.SD_OP_NEW_VDI,
        proto.SD_OP_LOCK_VDI,
        proto.SD_OP_RELEASE_VDI,
        proto.SD_OP_GET_VDI_INFO,
        proto.SD_OP_READ_VDIS,
        proto.SD_OP_FLUSH_VDI,
        proto.SD_OP_DEL_VDI,
        proto.SD_OP_GET_CLUSTER_DEFAULT,
    )

    def __init__(self):
        self.proto_ver = proto.SD_PROTO_VER
        self.opcode = 0x00
        self.flags = 0x00
        self.epoch = 0
        self.id = 0
        self.data_length = 0
        self.obj = self.Object()
        self.vdi = self.VDI()
        self.data = ''

    def serialize(self):
        data = self.packer.pack(
            self.proto_ver, self.opcode, self.flags,
            self.epoch,
            self.id,
            self.data_length)
        if self.opcode in self.OBJ_OPS:
            data = data[:16] + self.obj.serialize()
        elif self.opcode in self.VDI_OPS:
            data = data[:16] + self.vdi.serialize()
        if self.flags & proto.SD_FLAG_CMD_WRITE != 0:
            data += self.data
        return data

    class Object(object):
        fmt = '<QQBBBBLLL'
        size = struct.calcsize(fmt)
        packer = struct.Struct(fmt)

        def __init__(self):
            self.oid = 0x00000000
            self.cow_oid = 0x00000000
            self.copies = 0
            self.copy_policy = 0
            self.ec_index = 0
            self.tgt_epoch = 0
            self.offset = 0

        def serialize(self):
            return self.packer.pack(
                self.oid,
                self.cow_oid,
                self.copies, self.copy_policy, self.ec_index, 0,
                self.tgt_epoch,
                self.offset,
                0)

    class VDI(object):
        fmt = '<QLBBBBLL8x'
        size = struct.calcsize(fmt)
        packer = struct.Struct(fmt)

        def __init__(self):
            self.vdi_size = 0
            self.base_vdi_id = 0
            self.copies = 0
            self.copy_policy = 0
            self.store_policy = 0
            self.block_size_shift = 0
            self.snapid = 0
            self.type = 0

        def serialize(self):
            return self.packer.pack(
                self.vdi_size,
                self.base_vdi_id,
                self.copies, self.copy_policy,
                self.store_policy, self.block_size_shift,
                self.snapid,
                self.type,
            )


class Response(object):
    fmt = '<BBHLLLL28x'
    size = struct.calcsize(fmt)
    packer = struct.Struct(fmt)

    def __init__(self, data):
        pieces = self.packer.unpack(data)
        self.proto_ver = pieces[0]
        self.opcode = pieces[1]
        self.flags = pieces[2]
        self.epoch = pieces[3]
        self.id = pieces[4]
        self.data_length = pieces[5]
        self.result = pieces[6]
        self.data = ''

        self.vdi = self.VDI(data[20:48])

    class VDI(object):
        fmt = '<4xLLBB2x12x'
        size = struct.calcsize(fmt)
        packer = struct.Struct(fmt)

        def __init__(self, data):
            pieces = self.packer.unpack(data)
            self.vdi_id = pieces[0]
            self.attr_id = pieces[1]
            self.copies = pieces[2]
            self.block_size_shift = pieces[3]


class SheepdogClient(object):
    UINT32_MAX = 2 ** 32

    def __init__(self, host="127.0.0.1", port=7000):
        self._conn = Connection(host, port)
        self._seq_id = random.randint(1, self.UINT32_MAX - 1)

    def _call(self, req):
        self._seq_id = (self._seq_id + 1) % self.UINT32_MAX
        req.id = self._seq_id
        self._conn.sendall(req.serialize())
        rsp = Response(self._conn.recvall(Response.size))
        assert req.id == rsp.id
        if rsp.result == proto.SD_RES_SUCCESS:
            rsp.data = self._conn.recvall(rsp.data_length)
        else:
            raise Exception(hex(rsp.result))
        return rsp

    def _parse_vid_bitmap(self, data):
        vids = set()
        for i, c in enumerate(data):
            if c != '\x00':
                (b,) = struct.unpack('<B', c)
                j = 0
                while b & 255 > 0:
                    if b & 1 == 1:
                        vids.add(i * 8 + j)
                    j += 1
                    b = b >> 1
        return vids

    def _parse_vids(self, data):
        length = len(data) / 8
        fmt = '<%dQ' % length
        vids = struct.unpack(fmt, data)

        def _vid_to_str(vid):
            return '%016x' % vid

        return map(_vid_to_str, vids)

    def _parse_vdi_state(self, data):
        assert len(data) % 1428 == 0
        nr_vdis = len(data) / 1428
        status = []
        for i in range(nr_vdis):
            head = 1428 * i
            tail = 1428 * (i + 1)
            status.append(VDIState(data[head:tail]))
        return status

    def get_vids(self):
        req = Request()
        req.opcode = proto.SD_OP_READ_VDIS
        req.data_length = proto.SD_NR_VDIS / 8
        rsp = self._call(req)
        return self._parse_vid_bitmap(rsp.data)

    def get_del_vids(self):
        req = Request()
        req.opcode = proto.SD_OP_READ_DEL_VDIS
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.data_length = proto.SD_NR_VDIS / 8
        rsp = self._call(req)
        return self._parse_vid_bitmap(rsp.data)

    def read_obj(self, oid, offset, size):
        req = Request()
        req.opcode = proto.SD_OP_READ_OBJ
        req.data_length = size
        req.obj.oid = oid
        req.obj.offset = offset
        return self._call(req)

    def get_vdi_copies(self, epoch):
        req = Request()
        req.opcode = proto.SD_OP_GET_VDI_COPIES
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.data_length = 1428 * 512
        req.epoch = epoch
        rsp = self._call(req)
        return self._parse_vdi_state(rsp.data)

    def get_inode(self, vid):
        rsp = self.read_obj(proto.vid_to_vdi_oid(vid), 0, Inode.size)
        return Inode(rsp.data)

    def get_inodes(self):
        inodes = []
        for vid in self.get_vids():
            inode = self.get_inode(vid)
            if not inode.name:
                continue
            inodes.append(inode)
        return inodes

    def find_inode(self, vdiname, tagname=''):
        req = Request()
        req.opcode = proto.SD_OP_GET_VDI_INFO
        req.flags = proto.SD_FLAG_CMD_WRITE
        req.data_length = 512
        req.data = struct.pack('<256s256s', vdiname, tagname)
        rsp = self._call(req)
        return self.get_inode(rsp.vdi.vdi_id)

    def find_vdi(self, vdiname):
        return SheepdogVDI(self, self.find_inode(vdiname))

    def get_obj_list(self, data_length, epoch):
        req = Request()
        req.opcode = proto.SD_OP_GET_OBJ_LIST
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.data_length = data_length
        req.epoch = epoch
        rsp = self._call(req)
        return self._parse_vids(rsp.data)

    def create_and_write_obj(self, oid, data, offset):
        req = Request()
        req.opcode = proto.SD_OP_CREATE_AND_WRITE_OBJ
        req.proto_ver = proto.SD_PROTO_VER
        req.flags = proto.SD_FLAG_CMD_WRITE
        req.obj.oid = oid
        req.data = data
        req.data_length = len(data)
        req.obj.offset = offset
        return self._call(req)

    def write_obj(self, oid, data, offset):
        req = Request()
        req.opcode = proto.SD_OP_WRITE_OBJ
        req.proto_ver = proto.SD_PROTO_VER
        req.flags = proto.SD_FLAG_CMD_WRITE
        req.obj.oid = oid
        req.data = data
        req.data_length = len(data)
        req.obj.offset = offset
        return self._call(req)

    def remove_obj(self, oid):
        req = Request()
        req.opcode = proto.SD_OP_REMOVE_OBJ
        req.proto_ver = proto.SD_PROTO_VER
        req.obj.oid = oid
        return self._call(req)

    def create_and_write_peer(self, oid, data, epoch, ec_index):
        req = Request()
        req.opcode = proto.SD_OP_CREATE_AND_WRITE_PEER
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.flags = proto.SD_FLAG_CMD_WRITE
        req.obj.oid = oid
        req.data = data
        req.data_length = len(data)
        req.epoch = epoch
        req.obj.ec_index = ec_index
        return self._call(req)

    def write_peer(self, oid, data, epoch, ec_index):
        req = Request()
        req.opcode = proto.SD_OP_WRITE_PEER
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.flags = proto.SD_FLAG_CMD_WRITE
        req.obj.oid = oid
        req.data = data
        req.data_length = len(data)
        req.epoch = epoch
        req.obj.ec_index = ec_index
        return self._call(req)

    def read_peer(self, oid, size, epoch, ec_index):
        req = Request()
        req.opcode = proto.SD_OP_READ_PEER
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.data_length = size
        req.obj.oid = oid
        req.epoch = epoch
        req.obj.ec_index = ec_index
        return self._call(req)

    def remove_peer(self, oid, epoch, ec_index):
        req = Request()
        req.opcode = proto.SD_OP_REMOVE_PEER
        req.proto_ver = proto.SD_SHEEP_PROTO_VER
        req.obj.oid = oid
        req.epoch = epoch
        req.obj.ec_index = ec_index
        return self._call(req)

class SheepdogVDI(object):

    def __init__(self, client, inode):
        self.client = client
        self.inode = inode
        self.object_size = 1 << self.inode.block_size_shift

    def read(self, offset, length):
        data = ''
        iterator = self.OffsetIterator(offset, length, self.object_size)
        for idx, offset, length in iterator:
            vdi_id = self.inode.data_vdi_id[idx]
            if vdi_id == 0:
                data = '\0' * length
                continue
            oid = (vdi_id << proto.VDI_SPACE_SHIFT) + idx
            rsp = self.client.read_obj(oid, offset, length)
            data += rsp.data
        return data

    class OffsetIterator(object):

        def __init__(self, offset, length, object_size):
            self.idx = int(offset / object_size)
            self.offset = offset % object_size
            self.total = length
            self.done = 0
            self.object_size = object_size

        def __iter__(self):
            return self

        def next(self):
            if self.total <= self.done:
                raise StopIteration()

            length = min(self.total - self.done,
                         self.object_size - self.offset)
            ret = (self.idx, self.offset, length)

            self.offset = 0
            self.idx += 1
            self.done += length

            return ret
