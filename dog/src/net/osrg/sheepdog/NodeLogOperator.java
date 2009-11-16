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
import java.util.TreeSet;

import net.osrg.sheepdog.headers.NodeResponse;
import net.osrg.sheepdog.headers.Request;

public class NodeLogOperator {

    public NodeLogOperator() {
    }

    public int updateNodeLog(int oldEpoch, int newEpoch, TreeSet<Node> oldSet, TreeSet<Node> newSet) {
        NodeList nl;
        ObjectOperator objectOperator = new ObjectOperator();
        ByteBuffer object;
        SuperObject superObject;

        try {
            // TODO use defaultNrCopies in the super block
            Log.debug("read the super object");
            nl = new NodeList(oldEpoch, oldSet);
            object = objectOperator.readObject(nl,
                    ObjectOperator.DIRECTORY_OID, -1,
                    SuperObject.SUPER_OBJ_SIZE + SuperObject.NODE_LOG_SIZE
                            + 1024 * 1024);
            superObject = new SuperObject(object);
            nl = new NodeList(newEpoch, newSet);
            superObject.addNodeList(nl);
            nl = new NodeList(oldEpoch, oldSet);
            objectOperator.createObject(nl, ObjectOperator.DIRECTORY_OID,
                    superObject.getDefaultNrCopies(), superObject.toBuffer());
        } catch (SheepdogException oe) {
            OpCode opcode = oe.getOpcode();
            if (opcode == OpCode.OP_READ_OBJ) {
                Log.error("failed to read the old log");
                return SheepdogException.DIR_READ;
            } else {
                Log.error("failed to write the new log");
                return SheepdogException.DIR_WRITE;
            }
        }
        return SheepdogException.SUCCESS;
    }

    public int updateEpoch(int epoch, TreeSet<Node> set, long vdiOid, int vdiEpoch) {
        NodeList nl;
        ObjectOperator objectOperator = new ObjectOperator();
        ByteBuffer object;
        SuperObject superObject;

        try {
            // TODO use defaultNrCopies in the super block
            Log.debug("read the super object");
            nl = new NodeList(epoch, set);
            object = objectOperator.readObject(nl,
                    ObjectOperator.DIRECTORY_OID, -1,
                    SuperObject.SUPER_OBJ_SIZE + SuperObject.NODE_LOG_SIZE
                            + 1024 * 1024);
            superObject = new SuperObject(object);
            int res = superObject.setEpoch(vdiOid, vdiEpoch);
            if (res != SheepdogException.SUCCESS) {
                return res;
            }
            nl = new NodeList(epoch, set);
            objectOperator.createObject(nl, ObjectOperator.DIRECTORY_OID,
                    superObject.getDefaultNrCopies(), superObject.toBuffer());
        } catch (SheepdogException oe) {
            OpCode opcode = oe.getOpcode();
            if (opcode == OpCode.OP_READ_OBJ) {
                Log.error("failed to read the old log");
                return SheepdogException.DIR_READ;
            } else {
                Log.error("failed to write the new log");
                return SheepdogException.DIR_WRITE;
            }
        }
        return SheepdogException.SUCCESS;
    }

    public NodeResponse readPastNodeList(OpCode op, int epoch, TreeSet<Node> set,
            int reqEpoch, Request req) {
        NodeList nl;
        ObjectOperator objectOperator = new ObjectOperator();
        ByteBuffer object;
        SuperObject superObject;

        try {
            // TODO use defaultNrCopies in the super block
            Log.debug("read the super object");
            nl = new NodeList(epoch, set);
            object = objectOperator.readObject(nl,
                    ObjectOperator.DIRECTORY_OID, -1,
                    SuperObject.SUPER_OBJ_SIZE + SuperObject.NODE_LOG_SIZE
                            + 1024 * 1024);
            superObject = new SuperObject(object);
            NodeList nodeList = superObject.getNodeList(reqEpoch);
            ByteBuffer data;
            int nrNodes = 0;
            if (nodeList == null) {
                data = null;
            } else {
                data = nodeList.toRspData();
                nrNodes = nodeList.countNode();
            }
            NodeResponse rsp = new NodeResponse(req, op.getValue(), data, 0);
            rsp.setNrNodes(nrNodes);
            rsp.setLocalIdx(-1);
            rsp.setMasterIdx(-1);
            if (nodeList == null) {
                rsp.setResult(SheepdogException.NO_EPOCH);
            } else {
                rsp.setResult(SheepdogException.SUCCESS);
            }
            return rsp;
        } catch (SheepdogException oe) {
            int result = oe.getErrorCode();
            Log.error("failed to read the old log");
            NodeResponse rsp = new NodeResponse(req, op.getValue(), null, 0);
            if (result == SheepdogException.NO_OBJ) {
                rsp.setResult(SheepdogException.NO_SUPER_OBJ);
            } else {
                rsp.setResult(SheepdogException.DIR_READ);
            }
            return rsp;
        }
    }

    public int mkfs(int epoch, TreeSet<Node> set, int nrCopies) {
        NodeList nl;
        SuperObject superObject;
        ObjectOperator objectOperator = new ObjectOperator();

        try {
            Log.debug("create the super object (mkfs)");
            superObject = new SuperObject(nrCopies);
            nl = new NodeList(epoch + 1, set);
            superObject.addNodeList(nl);
            nl = new NodeList(epoch, set);
            objectOperator.createObject(nl, ObjectOperator.DIRECTORY_OID, nrCopies,
                    superObject.toBuffer());
            return SheepdogException.SUCCESS;
        } catch (SheepdogException e) {
            e.printStackTrace();
            Log.error("failed to make fs");
            return SheepdogException.DIR_WRITE;
        }
    }
}
