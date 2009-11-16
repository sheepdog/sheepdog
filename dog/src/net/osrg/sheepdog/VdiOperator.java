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
import java.util.ArrayList;
import java.util.TreeSet;

import net.osrg.sheepdog.headers.Request;
import net.osrg.sheepdog.messages.GetVdiInfoMessage;
import net.osrg.sheepdog.messages.ReleaseVdiMessage;
import net.osrg.sheepdog.messages.NewVdiMessage;
import net.osrg.sheepdog.messages.SheepdogMessage;

public class VdiOperator {

    private ObjectOperator objectOperator;
    private SuperObject superObject;
    private Inode inode;
    private ArrayList<DirEntry> directory;
    private DirEntry dirEntry = null;
    private String vdiName;
    private long newOid;
    private NodeList nl;
    private long baseOid;
    private long tag;
    private long vdiSize;
    private short flags;
    private OpCode op;
    private SheepdogMessage sm;

    public VdiOperator(long baseOid,
            long tag, long vdiSize, short flags, String vdiName,
            NodeList nl, OpCode op, SheepdogMessage sm) {
        this.objectOperator = new ObjectOperator();
        this.nl = nl;
        this.baseOid = baseOid;
        this.tag = tag;
        this.vdiSize = vdiSize;
        this.flags = flags;
        this.vdiName = vdiName;
        this.op = op;
        this.sm = sm;
    }

    private void lookupVdi(boolean doLock)
            throws SheepdogException {
        DirEntry dirEntry = null;
        try {
            // TODO handle larger buffer
            ByteBuffer object = objectOperator.readObject(nl, ObjectOperator.DIRECTORY_OID, -1,
                    SuperObject.SUPER_OBJ_SIZE + SuperObject.NODE_LOG_SIZE + 1024 * 1024);
            superObject = new SuperObject(object);

            dirEntry = superObject.findVdi(vdiName, tag, baseOid);

            // TODO use common interface
            if (sm instanceof GetVdiInfoMessage) {
                GetVdiInfoMessage msg = (GetVdiInfoMessage) sm;
                msg.setFlags(dirEntry.getFlags());
                msg.setResult(SheepdogException.SUCCESS);
                msg.setOid(dirEntry.getOid());
                msg.setVdiEpoch(dirEntry.getEpoch());
            } else {
                ReleaseVdiMessage msg = (ReleaseVdiMessage) sm;
                msg.setResult(SheepdogException.SUCCESS);
            }
        } catch (SheepdogException oe) {
            int result = oe.getErrorCode();
            if (result == SheepdogException.NO_OBJ) {
                throw new SheepdogException(SheepdogException.NO_SUPER_OBJ,
                                       "directory is not found");
            } else if (result == SheepdogException.OLD_NODE_VER
                    || result == SheepdogException.NEW_NODE_VER) {
                throw new SheepdogException(SheepdogException.DIFFERENT_EPOCH,
                                       "epochs are different between nodes");
            } else {
                // unknown error
                throw new SheepdogException(SheepdogException.DIR_READ,
                                       "cannot read directory");
            }
        }
    }

    private void addVdi() throws SheepdogException {
        try {
            // TODO handle larger buffer
            ByteBuffer object = objectOperator.readObject(nl, ObjectOperator.DIRECTORY_OID, -1,
                    SuperObject.SUPER_OBJ_SIZE + SuperObject.NODE_LOG_SIZE + 1024 * 1024);
            superObject = new SuperObject(object);
            directory = superObject.getDirectory();
            for (DirEntry ent : directory) {
                if (tag == 0 && ent.getName().equals(vdiName)) {
                    throw new SheepdogException(SheepdogException.VDI_EXIST, vdiName
                                           + " already exists");
                }
            }
            long oldOid = 0;
            if (directory.size() > 0) {
                dirEntry = directory.get(directory.size() - 1);
                oldOid = dirEntry.getOid();
            }
            newOid = oldOid + (1 << 18);
            if (baseOid > 0) {
                DirEntry baseEntry = superObject.findVdi(null, 0, baseOid);
                NodeList pastNodeList = superObject.getNodeList(baseEntry.getEpoch());
                object = objectOperator.readObject(new NodeList(nl.getEpoch(),
                                          (TreeSet<Node>) pastNodeList.getNodeSet()), baseOid,
                                          superObject.getDefaultNrCopies(), Inode.SIZE);
                Inode base = new Inode(object);
                inode = new Inode(superObject.getDefaultNrCopies(), newOid,
                                  vdiSize, baseOid);
                for (int i = 0; i < inode.getDataOid().length; i++) {
                    inode.getDataOid()[i] = base.getDataOid()[i];
                }
                for (int i = 0; i < Inode.MAX_CHILDREN; i++) {
                    if (base.getChildOid()[i] == 0) {
                        base.getChildOid()[i] = newOid;
                        break;
                    }
                }
                object = objectOperator.createObject(nl, baseOid, base
                                            .getNrCopies(), base.toBuffer());
            } else {
                inode = new Inode(superObject.getDefaultNrCopies(), newOid,
                                  vdiSize, baseOid);
            }
            object = objectOperator.createObject(nl, newOid, inode.getNrCopies(),
                                        inode.toBuffer());
            dirEntry = new DirEntry(inode.getOid(), (int) tag,
                                    (byte) flags, vdiName,
                                    nl.getEpoch());
            superObject.addDirEntry(dirEntry);
            object = objectOperator.createObject(nl, ObjectOperator.DIRECTORY_OID,
                                        superObject.getDefaultNrCopies(), superObject.toBuffer());
            NewVdiMessage msg = (NewVdiMessage) sm;
            msg.setFlags(Request.FLAG_CMD_WRITE);
            msg.setResult(SheepdogException.SUCCESS);
            msg.setOid(inode.getOid());
            msg.setVdiEpoch(dirEntry.getEpoch());
        } catch (SheepdogException oe) {
            int result = oe.getErrorCode();
            long oid = oe.getOid();
            OpCode opcode = oe.getOpcode();
            if (result == SheepdogException.NO_OBJ) {
                if (oid == 0) {
                    throw new SheepdogException(SheepdogException.NO_SUPER_OBJ,
                                           "directory is not found");
                } else if (oid == newOid) {
                    throw new SheepdogException(SheepdogException.NO_VDI,
                                           "vdi is not found");
                } else if (oid == baseOid) {
                    throw new SheepdogException(SheepdogException.NO_BASE_VDI,
                                           "base vdi is not found");
                } else {
                    throw new SheepdogException(SheepdogException.NO_VDI,
                                           "object is not found");
                }
            } else if (result == SheepdogException.OLD_NODE_VER
                    || result == SheepdogException.NEW_NODE_VER) {
                throw new SheepdogException(SheepdogException.DIFFERENT_EPOCH,
                                       "epochs are different between nodes");
            } else if (opcode == OpCode.OP_READ_OBJ) {
                if (oid == 0) {
                    throw new SheepdogException(SheepdogException.DIR_READ,
                                           "cannot read directory");
                } else if (oid == newOid) {
                    throw new SheepdogException(SheepdogException.VDI_READ,
                                           "cannot read vdi");
                } else if (oid == baseOid) {
                    throw new SheepdogException(SheepdogException.BASE_VDI_READ,
                                           "cannot read base vdi");
                } else {
                    throw new SheepdogException(SheepdogException.EIO,
                                           "failed to read object");
                }
            } else {
                if (oid == 0) {
                    throw new SheepdogException(SheepdogException.DIR_WRITE,
                                           "failed to update directory");
                } else if (oid == newOid) {
                    throw new SheepdogException(SheepdogException.VDI_WRITE,
                                           "failed to create new vdi");
                } else if (oid == baseOid) {
                    throw new SheepdogException(SheepdogException.BASE_VDI_WRITE,
                                           "failed to update base vdi");
                } else {
                    throw new SheepdogException(SheepdogException.EIO,
                                           "failed to write object");
                }
            }
        }
    }

    public int doOperation() {
        try {
            switch (op) {
            case OP_NEW_VDI:
                addVdi();
                break;
            case OP_LOCK_VDI:
                lookupVdi(true);
                break;
            case OP_GET_VDI_INFO:
                lookupVdi(false);
                break;
            default:
                Log.error("Unknown opcode: " + op);
                break;
            }
        } catch (SheepdogException ve) {
            Log.error(ve);

            // TODO use common interface
            switch (op) {
            case OP_NEW_VDI:
                NewVdiMessage newMsg = (NewVdiMessage) sm;
                newMsg.setFlags((short) 0);
                newMsg.setResult(ve.getErrorCode());
                newMsg.setVdiEpoch(0);
                break;
            case OP_LOCK_VDI:
            case OP_GET_VDI_INFO:
                if (sm instanceof GetVdiInfoMessage) {
                    GetVdiInfoMessage lockMsg = (GetVdiInfoMessage) sm;
                    lockMsg.setFlags((short) 0);
                    lockMsg.setResult(ve.getErrorCode());
                    lockMsg.setVdiEpoch(0);
                } else {
                    ReleaseVdiMessage msg = (ReleaseVdiMessage) sm;
                    msg.setResult(ve.getErrorCode());
                }
                break;
            default:
                break;
            }
        }
        return sm.getResult();
    }
}
