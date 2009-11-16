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

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedList;
import java.io.IOException;

import net.osrg.sheepdog.headers.ObjectRequest;
import net.osrg.sheepdog.headers.ObjectResponse;
import net.osrg.sheepdog.headers.Request;
import net.osrg.sheepdog.headers.Response;
import static net.osrg.sheepdog.OpCode.OP_REMOVE_OBJ;
import static net.osrg.sheepdog.OpCode.OP_READ_OBJ;
import static net.osrg.sheepdog.OpCode.OP_WRITE_OBJ;
import static net.osrg.sheepdog.OpCode.OP_CREATE_AND_WRITE_OBJ;

public class ObjectOperator {

    public static final long DIRECTORY_OID = 0;

    public ObjectOperator() {
    }

    public ByteBuffer readObject(NodeList nl, long oid, int copies, int size) throws SheepdogException {
        ObjectRequest req = new ObjectRequest();
        req.setOid(oid);
        req.setNodeList(nl);
        req.setOpcode(OP_READ_OBJ);
        req.setCopies(copies);
        req.setDataLength(size);
        if (nl != null) {
            req.setEpoch(nl.getEpoch());
        } else {
            Log.error("cannot get node list");
            req.setEpoch(0);
        }
        return doOperation(req);
    }

    public ByteBuffer createObject(NodeList nl, long oid, int copies,
            ByteBuffer buf) throws SheepdogException {
        return writeObject(nl, OP_CREATE_AND_WRITE_OBJ, oid, copies, buf);
    }

    public ByteBuffer writeObject(NodeList nl, long oid, int copies,
            ByteBuffer buf) throws SheepdogException {
        return writeObject(nl, OP_WRITE_OBJ, oid, copies, buf);
    }

    private ByteBuffer writeObject(NodeList nl, OpCode opcode, long oid,
                                   int copies, ByteBuffer buf) throws SheepdogException {
        ObjectRequest req = new ObjectRequest();
        req.setOid(oid);
        req.setNodeList(nl);
        req.setOpcode(opcode);
        req.setCopies(copies);
        req.setDataLength(buf.remaining());
        req.setData(buf);
        req.setFlags(Request.FLAG_CMD_WRITE);
        if (nl != null) {
            req.setEpoch(nl.getEpoch());
        } else {
            Log.error("cannot get node list");
            req.setEpoch(0);
        }
        return doOperation(req);
    }

    public ByteBuffer removeObject(NodeList nl, NodeList maskNodeList,
            long oid, int copies) throws SheepdogException {
        ObjectRequest req = new ObjectRequest();
        req.setOid(oid);
        req.setNodeList(nl);
        req.setMaskNodeList(maskNodeList);
        req.setOpcode(OP_REMOVE_OBJ);
        req.setCopies(copies);
        if (nl != null) {
            req.setEpoch(nl.getEpoch());
        } else {
            Log.error("cannot get node list");
            req.setEpoch(0);
        }
        return doOperation(req);
    }

    private Node objToSheep(NodeList nodeList, long oid, int idx) {
        Node[] nodeArray = nodeList.getNodeSet().toArray(new Node[0]);
        Node dummyNode = new Node(oid);
        int index = Arrays.binarySearch(nodeArray, dummyNode);
        if (index < 0) {
            index = -index - 1;
        }
        return nodeArray[(index + idx) % nodeList.countNode()];
    }

    private List<Node> objToSheeps(NodeList nodeList, long oid, int nrCopies) {
        return objToSheeps(nodeList, oid, nrCopies, null);
    }

    private List<Node> objToSheeps(NodeList nodeList, long oid, int nrCopies, List<Node> masks) {
        List<Node> list = new LinkedList<Node>();
        if (nodeList == null) {
            return list;
        }
        for (int i = 0; i < nrCopies; i++) {
            Node node = objToSheep(nodeList, oid, i);
            if (masks == null || !masks.contains(node)) {
                list.add(node);
            }
        }
        return list;
    }

    private void doRead(ReadableByteChannel ch, ByteBuffer buf)
            throws IOException {
        while (buf.hasRemaining()) {
            ch.read(buf);
        }
    }

    private void doWrite(WritableByteChannel ch, ByteBuffer buf)
            throws IOException {
        while (buf.hasRemaining()) {
            ch.write(buf);
        }
    }

    private synchronized ByteBuffer doOperation(ObjectRequest req) throws SheepdogException {
        NodeList nodeList = req.getNodeList();
        NodeList maskNodeList = req.getMaskNodeList();
        int nrCopies;
        long oid = req.getOid();
        OpCode opcode = req.getOpcode();
        if (req.getData() != null) {
            req.getData().mark();
        }
        Log.debug("req.getCopies() = " + req.getCopies());
        nrCopies = req.getCopies();
        if (nrCopies < 0 || nrCopies > nodeList.countNode()) {
            nrCopies = nodeList.countNode();
        }

        ByteBuffer rspData = null;

        List<Node> targetNodes;
        if (maskNodeList != null) {
            List<Node> maskNodes = objToSheeps(maskNodeList, oid, nrCopies);
            targetNodes = objToSheeps(nodeList, oid, nrCopies, maskNodes);
        } else {
            targetNodes = objToSheeps(nodeList, oid, nrCopies);
        }
        int result = SheepdogException.SUCCESS;
        String errMsg = null;
        Log.debug("targetNodes = " + targetNodes);
        for (Node node : targetNodes) {
            try {
                InetSocketAddress address;
                address = new InetSocketAddress(node.getInetAddress(), node
                        .getSheepPort());
                SocketChannel ch = SocketChannel.open();
                ch.connect(address);
                if (req.getData() != null) {
                    req.getData().reset();
                }
                doWrite(ch, req.toBuffer());
                ByteBuffer buf;
                if ((req.getFlags() & Request.FLAG_CMD_WRITE) == Request.FLAG_CMD_WRITE) {
                    buf = ByteBuffer.allocate(Response.HEADER_SIZE);
                } else {
                    buf = ByteBuffer.allocate(Response.HEADER_SIZE
                            + req.getDataLength());
                }
                buf.order(ByteOrder.LITTLE_ENDIAN);
                buf.limit(Response.HEADER_SIZE);
                doRead(ch, buf);
                buf.flip();
                ObjectResponse rsp = new ObjectResponse(buf);
                if ((req.getFlags() & Response.FLAG_CMD_WRITE) != Response.FLAG_CMD_WRITE) {
                    buf.mark();
                    buf.limit(Response.HEADER_SIZE + rsp.getDataLength());
                    doRead(ch, buf);
                    buf.reset();
                    rsp.setData(buf);
                }
                if (opcode == OpCode.OP_READ_OBJ || result == SheepdogException.SUCCESS) {
                    result = rsp.getResult();
                }
                if (rsp.getResult() != SheepdogException.SUCCESS) {
                    errMsg = "Error: nodeList = " + nodeList
                        + ", maskNodeList = " + maskNodeList
                        + ", target = " + node
                        + ", op = " + opcode
                        + ", oid = " + oid
                        + ", code = " + rsp.getResult();
                    Log.error(errMsg);
                    continue;
                }

                rspData = ByteBuffer.allocate(rsp.getDataLength());
                rspData.order(ByteOrder.LITTLE_ENDIAN);
                rspData.put(rsp.getData());
                rspData.flip();

                ch.close();
                if (opcode == OpCode.OP_READ_OBJ) {
                    break;
                }
            } catch (IOException e) {
                errMsg = "cannot access to object " + oid
                    + ": " + e.getLocalizedMessage();
                Log.error(errMsg);
                result = SheepdogException.EIO;
            }
        }
        if (result != SheepdogException.SUCCESS) {
            throw new SheepdogException(result, oid, opcode, errMsg);
        }
        return rspData;
    }
}
