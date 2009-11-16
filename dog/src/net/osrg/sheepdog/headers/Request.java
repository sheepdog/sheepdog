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

package net.osrg.sheepdog.headers;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import net.osrg.sheepdog.OpCode;

public class Request implements Externalizable {
    /**
     *
     */
    private static final long serialVersionUID = -2749643747232097287L;
    public static final int HEADER_SIZE = 48;
    public static final short FLAG_CMD_WRITE = 1;

    public Request() { }

    public Request(ByteBuffer buf) {
        protoVersion = buf.get();
        opcode = OpCode.fromValue(buf.get());
        flags = buf.getShort();
        epoch = buf.getInt();
        id = buf.getInt();
        dataLength = buf.getInt();
        remaining = ByteBuffer.allocate(32);
        remaining.order(ByteOrder.LITTLE_ENDIAN);
        buf.get(remaining.array());
        data = buf;
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + dataLength);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(protoVersion);
        buf.put(opcode.getValue());
        buf.putShort(flags);
        buf.putInt(epoch);
        buf.putInt(id);
        buf.putInt(dataLength);
        buf.put(remaining);
        buf.put(data);
        buf.flip();
        return buf;
    }

    public byte getProtoVersion() {
        return protoVersion;
    }

    public void setProtoVersion(byte protoVersion) {
        this.protoVersion = protoVersion;
    }

    public OpCode getOpcode() {
        return opcode;
    }

    public void setOpcode(OpCode opcode) {
        this.opcode = opcode;
    }

    public short getFlags() {
        return flags;
    }

    public void setFlags(short flags) {
        this.flags = flags;
    }

    public int getEpoch() {
        return epoch;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getDataLength() {
        return dataLength;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = dataLength;
    }

    public void setData(ByteBuffer data) {
        this.data = data;
    }

    public ByteBuffer getData() {
        return data;
    }

    private byte protoVersion;
    private OpCode opcode;
    private short flags;
    private int epoch;
    private int id;
    private int dataLength;
    private ByteBuffer remaining;
    public ByteBuffer getRemaining() {
        return remaining;
    }

    public void setRemaining(ByteBuffer remaining) {
        this.remaining = remaining;
    }

    private ByteBuffer data;

    @Override
    public void readExternal(ObjectInput in) throws IOException,
            ClassNotFoundException {
        ByteBuffer header = ByteBuffer.allocate(HEADER_SIZE);
        header.order(ByteOrder.LITTLE_ENDIAN);
        int offset = 0;
        int length = HEADER_SIZE;
        while (offset < length) {
            int ret = in.read(header.array(), offset, length - offset);
            offset += ret;
        }
        // TODO redundant codes
        protoVersion = header.get();
        opcode = OpCode.fromValue(header.get());
        flags = header.getShort();
        epoch = header.getInt();
        id = header.getInt();
        dataLength = header.getInt();
        remaining = ByteBuffer.allocate(32);
        remaining.order(ByteOrder.LITTLE_ENDIAN);
        header.get(remaining.array());

        this.data = ByteBuffer.allocate(dataLength);
        this.data.order(ByteOrder.LITTLE_ENDIAN);
        offset = 0;
        length = dataLength;
        while (offset < length) {
            int ret = in.read(this.data.array(), offset, length - offset);
            offset += ret;
        }
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.write(toBuffer().array());
    }
}
