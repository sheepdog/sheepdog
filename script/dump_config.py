#!/usr/bin/env python
from datetime import datetime as dt
import struct
import sys

FMT = '<QHB16sBBBHQ'
PACKER = struct.Struct(FMT)
assert struct.calcsize(FMT) == 40

def main():
    data = sys.stdin.read()
    assert len(data) == 40
    pieces = PACKER.unpack(data)

    ctime            = pieces[0]
    flags            = pieces[1]
    copies           = pieces[2]
    default_store    = pieces[3]
    shutdown         = pieces[4]
    copy_policy      = pieces[5]
    block_size_shift = pieces[6]
    version          = pieces[7]
    space            = pieces[8]

    # ctime
    ctime_s  = (ctime >> 32) & 0xFFFFFFFF
    ctime_us = (ctime & 0xFFFFFFFF) / 1000
    ctime_dt = dt.utcfromtimestamp(ctime_s).replace(microsecond=ctime_us)

    # flags
    flags_list = []
    if flags & 0x0001: flags_list.append("STRICT")
    if flags & 0x0002: flags_list.append("DISKMODE")
    if flags & 0x0004: flags_list.append("AUTO_VNODES")
    if flags & 0x0008: flags_list.append("USE_LOCK")
    if flags & 0x0010: flags_list.append("RECYCLE_VID")
    if flags & 0x0020: flags_list.append("AVOID_DISKFULL")
    flags_str = '|'.join(flags_list) if flags_list else None

    # copy_policy
    ec = "ec#{}:{}".format(((copy_policy >> 4) & 0xF) * 2, copy_policy & 0xF)
    copy_policy_str = "replica" if not(copy_policy) else ec

    # space
    space_gib = float(space) / 1024 / 1024 / 1024

    print "ctime            {}+00:00 (0x{:016X})".format(ctime_dt.isoformat(), ctime)
    print "flags            {} (0x{:04X})".format(flags_str, flags)
    print "copies           {}".format(copies)
    print "default_store    {}".format(default_store)
    print "shutdown         {} ({})".format(bool(shutdown), shutdown)
    print "copy_policy      {} (0x{:02X})".format(copy_policy_str, copy_policy)
    print "block_size_shift {}".format(block_size_shift)
    print "version          {}".format(version)
    print "space            {:.1f} GiB ({})".format(space_gib, space)

if __name__ == '__main__':
    main();
