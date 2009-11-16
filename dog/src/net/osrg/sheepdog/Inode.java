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

public class Inode {

    static final int MAX_CHILDREN = 1024;
    static final int MAX_DATA_OBJS = (1 << 18);
    static final int DATA_OBJ_SIZE = (1 << 22);
    static final int SIZE = 48 + 8 * MAX_CHILDREN + 8 * MAX_DATA_OBJS + 4
            * MAX_DATA_OBJS;

    public Inode(int copies, long oid, long size, long baseOid) {
        this.oid = oid;
        this.vdiSize = size;
        this.blockSize = DATA_OBJ_SIZE;
        long tm = System.currentTimeMillis();
        this.ctime = ((tm / 1000) << 32) | ((tm % 1000) * 1000000);
        this.nrCopies = copies;
        this.parentOid = baseOid;
        childOid = new long[MAX_CHILDREN];
        dataOid = new long[MAX_DATA_OBJS];
        epoch = new int[MAX_DATA_OBJS];
    }

    public Inode(ByteBuffer buf) {
        oid = buf.getLong();
        ctime = buf.getLong();
        vdiSize = buf.getLong();
        blockSize = buf.getLong();
        copyPolicy = buf.getInt();
        nrCopies = buf.getInt();
        parentOid = buf.getLong();
        childOid = new long[MAX_CHILDREN];
        for (int i = 0; i < childOid.length; i++) {
            childOid[i] = buf.getLong();
        }
        dataOid = new long[MAX_DATA_OBJS];
        for (int i = 0; i < dataOid.length; i++) {
            dataOid[i] = buf.getLong();
        }
        epoch = new int[MAX_DATA_OBJS];
        for (int i = 0; i < epoch.length; i++) {
            epoch[i] = buf.getInt();
        }
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buf = ByteBuffer.allocate(SIZE);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(oid);
        buf.putLong(ctime);
        buf.putLong(vdiSize);
        buf.putLong(blockSize);
        buf.putInt(copyPolicy);
        buf.putInt(nrCopies);
        buf.putLong(parentOid);
        for (int i = 0; i < childOid.length; i++) {
            buf.putLong(childOid[i]);
        }
        for (int i = 0; i < dataOid.length; i++) {
            buf.putLong(dataOid[i]);
        }
        for (int i = 0; i < epoch.length; i++) {
            buf.putInt(epoch[i]);
        }
        buf.flip();
        return buf;
    }

    public static int getMaxChildren() {
        return MAX_CHILDREN;
    }

    public static int getMaxDataObjs() {
        return MAX_DATA_OBJS;
    }

    public long getOid() {
        return oid;
    }

    public long getCtime() {
        return ctime;
    }

    public long getVdiSize() {
        return vdiSize;
    }

    public long getBlockSize() {
        return blockSize;
    }

    public int getCopyPolicy() {
        return copyPolicy;
    }

    public int getNrCopies() {
        return nrCopies;
    }

    public long getParentOid() {
        return parentOid;
    }

    public long[] getChildOid() {
        return childOid;
    }

    public long[] getDataOid() {
        return dataOid;
    }

    public void setEpoch(int[] epoch) {
        this.epoch = epoch;
    }

    public int[] getEpoch() {
        return epoch;
    }

    private long oid;
    private long ctime;
    private long vdiSize;
    private long blockSize;
    private int copyPolicy;
    private int nrCopies;
    private long parentOid;
    private long[] childOid;
    private long[] dataOid;
    private int[] epoch;
}
