/*
 * Copyright (C) 2009 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package net.osrg.sheepdog;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DirEntry {

    private static final int DIR_ALIGN = 8;

    public DirEntry(long oid, int tag, byte flags, String name
            , int epoch) {
        this.oid = oid;
        this.tag = tag;
        this.flags = flags;
        this.epoch = epoch;
        this.padding = 0;
        this.name = name;
        this.nameLen = (short) name.length();
    }

    public DirEntry(ByteBuffer buf) {
        oid = buf.getLong();
        tag = buf.getInt();
        nameLen = buf.getShort();
        type = buf.get();
        flags = buf.get();
        epoch = buf.getInt();
        padding = buf.getInt();
        int len = roundup(nameLen, DIR_ALIGN);
        byte[] bs = new byte[nameLen];
        for (int i = 0; i < len; i++) {
            if (i < bs.length) {
                bs[i] = buf.get();
            } else {
                buf.get();
            }
        }
        name = new String(bs);
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buf = ByteBuffer.allocate(1024 * 1024); // TODO support larger size
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(oid);
        buf.putInt(tag);
        buf.putShort(nameLen);
        buf.put(type);
        buf.put(flags);
        buf.putInt(epoch);
        buf.putInt(padding);
        int len = roundup(nameLen, DIR_ALIGN);
        byte[] bs = name.getBytes();
        for (int i = 0; i < len; i++) {
            if (i < bs.length) {
                buf.put(bs[i]);
            } else {
                buf.put((byte) 0);
            }
        }
        buf.flip();
        return buf;
    }

    private static int roundup(int x, int y) {
        return ((((x) + ((y) - 1)) / (y)) * (y));
    }

    public long getOid() {
        return oid;
    }

    public int getTag() {
        return tag;
    }

    public short getNameLen() {
        return nameLen;
    }

    public byte getType() {
        return type;
    }

    public byte getFlags() {
        return flags;
    }

    public void setFlags(byte flags) {
        this.flags = flags;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public int getEpoch() {
        return epoch;
    }

    public String getName() {
        return name;
    }

    private long oid;
    private int tag;
    private short nameLen;
    private byte type;
    private byte flags;
    private int epoch;
    private int padding;
    private String name;
}
