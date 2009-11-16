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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import net.osrg.sheepdog.OpCode;

public class Response {
    public static final int HEADER_SIZE = 48;
    public static final short FLAG_CMD_WRITE = 1;

    public Response(ByteBuffer buf) {
        protoVersion = buf.get();
        setOpcode(OpCode.fromValue(buf.get()));
        flags = buf.getShort();
        epoch = buf.getInt();
        id = buf.getInt();
        dataLength = buf.getInt();
        result = buf.getInt();
        for (int i = 0; i < 7; i++) {
            buf.getInt();
        }
        setData(buf.slice());
    }

    public Response(Request req, byte op, ByteBuffer data, int res) {
        if (data == null) {
            data = ByteBuffer.allocate(0);
        }
        if (req == null) {
            ByteBuffer buf = ByteBuffer.allocate(Request.HEADER_SIZE);
            buf.order(ByteOrder.LITTLE_ENDIAN);
            req = new Request(buf);
        }
        protoVersion = req.getProtoVersion();
        opcode = OpCode.fromValue(op);
        flags = req.getFlags();
        epoch = req.getEpoch();
        id = req.getId();
        dataLength = data.limit();
        result = res;
        this.data = data;
        if (data.remaining() > 0) {
            flags = FLAG_CMD_WRITE;
        }
    }

    public Response() {
        opcode = OpCode.OP_UNKNOWN;
        data = ByteBuffer.allocate(0);
        data.order(ByteOrder.LITTLE_ENDIAN);
    }

    public void fillHeader(ByteBuffer buf) {
        buf.put(protoVersion);
        buf.put(opcode.getValue());
        buf.putShort(flags);
        buf.putInt(epoch);
        buf.putInt(id);
        buf.putInt(dataLength);
        buf.putInt(result);
    }

    public ByteBuffer getHeader() {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + data.limit());
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(protoVersion);
        buf.put(opcode.getValue());
        buf.putShort(flags);
        buf.putInt(epoch);
        buf.putInt(id);
        buf.putInt(dataLength);
        buf.putInt(result);
        for (int i = 0; i < 7; i++) {
            buf.putInt(0);
        }
        buf.flip();
        return buf;
    }

    public byte getProtoVersion() {
        return protoVersion;
    }

    public OpCode getOpcode() {
        return opcode;
    }

    public short getFlags() {
        return flags;
    }

    public int getEpoch() {
        return epoch;
    }

    public int getId() {
        return id;
    }

    public int getDataLength() {
        return dataLength;
    }

    public int getResult() {
        return result;
    }

    public void setResult(int result) {
        this.result = result;
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

    public void setProtoVersion(byte protoVersion) {
        this.protoVersion = protoVersion;
    }

    public void setOpcode(OpCode opcode) {
        this.opcode = opcode;
    }

    public void setFlags(short flags) {
        this.flags = flags;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setDataLength(int dataLength) {
        this.dataLength = dataLength;
    }

    private int epoch;
    private int id;
    private int dataLength;
    private int result;
    private ByteBuffer data;
}
