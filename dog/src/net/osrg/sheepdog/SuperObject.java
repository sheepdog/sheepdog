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
import java.util.ArrayList;

import net.osrg.sheepdog.headers.Request;

public class SuperObject {

    public static final int SUPER_OBJ_SIZE = 1 << 12;
    // TODO these sizes are temporary values
    public static final int NODE_LOG_SIZE = 1 << 24;
    public static final int DIRECTORY_SIZE = 1 << 24;

    public SuperObject(int defaultNrCopies) {
        long tm = System.currentTimeMillis();
        this.ctime = ((tm / 1000) << 32) | ((tm % 1000) * 1000000);
        this.defaultNrCopies = (byte) defaultNrCopies;
        this.nodeHistory = new ArrayList<NodeList>();
        this.directory = new ArrayList<DirEntry>();
    }

    public SuperObject(ByteBuffer buf) {
        buf.mark();
        ctime = buf.getLong();
        defaultNrCopies = buf.get();
        buf.reset();
        buf.position(buf.position() + SUPER_OBJ_SIZE);
        buf.mark();
        nodeHistory = new ArrayList<NodeList>();
        NodeList nodeList = null;
        long nrNodeList = buf.getLong();
        for (int i = 0; i < nrNodeList; i++) {
            nodeList = NodeList.fromLogData(buf);
            if (nodeList != null) {
                nodeHistory.add(nodeList);
            } else {
                break;
            }
        }
        buf.reset();
        buf.position(buf.position() + NODE_LOG_SIZE);
        directory = new ArrayList<DirEntry>();
        while (buf.hasRemaining()) {
            directory.add(new DirEntry(buf));
        }
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buf = ByteBuffer.allocate(SUPER_OBJ_SIZE
                                             + NODE_LOG_SIZE
                                             + DIRECTORY_SIZE);
        buf.mark();
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putLong(ctime);
        buf.put(defaultNrCopies);
        buf.reset();
        buf.position(buf.position() + SUPER_OBJ_SIZE);
        buf.mark();
        buf.putLong(nodeHistory.size());
        for (NodeList nodeList : nodeHistory) {
            buf.put(nodeList.toLogData());
        }
        buf.reset();
        buf.position(buf.position() + NODE_LOG_SIZE);
        for (DirEntry ent : directory) {
            buf.put(ent.toBuffer());
        }
        buf.flip();
        return buf;
    }

    public long getCtime() {
        return ctime;
    }

    public byte getDefaultNrCopies() {
        return defaultNrCopies;
    }

    public ArrayList<DirEntry> getDirectory() {
        return this.directory;
    }

    public void addDirEntry(DirEntry dirEntry) {
        for (DirEntry ent : directory) {
            if (ent.getName().equals(dirEntry.getName())) {
                ent.setFlags((byte) (ent.getFlags() & ~Request.FLAG_CMD_WRITE));
            }
        }
        directory.add(dirEntry);
    }

    public void addNodeList(NodeList nodeList) {
        nodeHistory.add(nodeList);
    }

    public NodeList getNodeList(int epoch) {
        // TODO use Comparable and binarySearch
        for (NodeList nodeList : nodeHistory) {
            if (nodeList.getEpoch() == epoch) {
                return nodeList;
            }
        }
        return null;
    }

    public NodeList getLastNodeList() {
        return nodeHistory.get(nodeHistory.size() - 1);
    }

    public int getEpoch(long oid, int epoch) {
        for (DirEntry ent : directory) {
            if (ent.getOid() == oid) {
                return ent.getEpoch();
            }
        }
        return -1;
    }

    public int setEpoch(long oid, int epoch) {
        for (DirEntry ent : directory) {
            if (ent.getOid() == oid) {
                ent.setEpoch(epoch);
                return SheepdogException.SUCCESS;
            }
        }
        return SheepdogException.NO_VDI;
    }

    public DirEntry findVdi(String vdiName, long tag, long oid) throws SheepdogException {
        int result = SheepdogException.NO_VDI;
        DirEntry dirEntry = null;

        for (DirEntry ent : directory) {
            if (vdiName != null) { // request by name
                if (!ent.getName().equals(vdiName)) {
                    continue;
                }
                if (ent.getTag() == tag) {
                    result = SheepdogException.SUCCESS;
                    dirEntry = ent;
                    break;
                }
                if (tag == -1) {
                    if (ent.getFlags() == Request.FLAG_CMD_WRITE) {
                        result = SheepdogException.SUCCESS;
                        dirEntry = ent;
                        break;
                    } else {
                        // current vdi must exist
                        result = SheepdogException.SYSTEM_ERROR;
                    }
                } else {
                    result = SheepdogException.NO_TAG;
                }
            } else { // request by oid
                if (ent.getOid() == oid) {
                    result = SheepdogException.SUCCESS;
                    dirEntry = ent;
                    break;
                }
            }
        }

        if (dirEntry == null) {
            if (result == SheepdogException.NO_VDI) {
                throw new SheepdogException(result, "vdi ("
                                       + vdiName + ") is not found");
            } else if (result == SheepdogException.NO_TAG) {
                throw new SheepdogException(result, "vdi tag ("
                                       + tag + ") is not found");
            } else if (result == SheepdogException.SYSTEM_ERROR) {
                throw new SheepdogException(result, "there is no current vdi");
            } else {
                throw new SheepdogException(SheepdogException.UNKNOWN, "there is no current vdi");
            }
        }
        return dirEntry;
    }

    private long ctime;
    private byte defaultNrCopies;
    private ArrayList<NodeList> nodeHistory;
    private ArrayList<DirEntry> directory;
}
