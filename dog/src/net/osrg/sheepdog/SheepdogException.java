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

public class SheepdogException extends Exception {

    public static final int SUCCESS = 0x00;
    public static final int UNKNOWN = 0x01;
    public static final int NO_OBJ = 0x02;
    public static final int EIO = 0x03;
    public static final int OLD_NODE_VER = 0x04;
    public static final int NEW_NODE_VER = 0x05;
    public static final int VDI_EXIST = 0x06;
    public static final int INVALID_PARMS = 0x07;
    public static final int SYSTEM_ERROR = 0x08;
    public static final int VDI_LOCKED = 0x09;
    public static final int NO_SUPER_OBJ = 0x0A;
    public static final int NO_VDI = 0x0B;
    public static final int NO_BASE_VDI = 0x0C;
    public static final int DIFFERENT_EPOCH = 0x0D;
    public static final int DIR_READ = 0x0E;
    public static final int DIR_WRITE = 0x0F;
    public static final int VDI_READ = 0x10;
    public static final int VDI_WRITE = 0x11;
    public static final int BASE_VDI_READ = 0x12;
    public static final int BASE_VDI_WRITE = 0x13;
    public static final int NO_TAG = 0x14;
    public static final int STARTUP = 0x15;
    public static final int NO_EPOCH = 0x16;
    public static final int VDI_NOT_LOCKED = 0x17;
    public static final int SHUTDOWN = 0x18;

    private int errorCode;
    private OpCode opcode;
    private long oid;

    private static final long serialVersionUID = -4356595263599187642L;

    public SheepdogException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.oid = 0;
        this.opcode = OpCode.OP_UNKNOWN;
    }

    public SheepdogException(int errorCode, long oid, OpCode opcode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.oid = oid;
        this.opcode = opcode;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public OpCode getOpcode() {
        return opcode;
    }

    public long getOid() {
        return oid;
    }
}
