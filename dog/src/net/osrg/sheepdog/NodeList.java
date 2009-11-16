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

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

public class NodeList implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -4381317706988377585L;
    public static final int NODE_LIST_ENTRY_SIZE = 40;

    public void setMasterNode(Node node) {
        masterIndex = getIndex(node);
    }

    public void setMasterIndex(int masterIndex) {
        this.masterIndex = masterIndex;
    }

    private int masterIndex;

    public NodeList() {
        this(0, new TreeSet<Node>());
    }

    @SuppressWarnings("unchecked")
    public NodeList(int v, TreeSet<Node> set) {
        masterIndex = -1;
        epoch = v;
        nodeSet = (TreeSet<Node>) set.clone();
    }

    public int countNode() {
        return nodeSet.size();
    }

    public int getEpoch() {
        return epoch;
    }

    public void setEpoch(int epoch) {
        this.epoch = epoch;
    }

    public Set<Node> getNodeSet() {
        return nodeSet;
    }

    public int getMasterIndex() {
        return masterIndex;
    }

    public int getIndex(Node node) {
        return Arrays.binarySearch(nodeSet.toArray(), node);
    }

    public ByteBuffer toRspData() {
        ByteBuffer buf = ByteBuffer
                .allocate(NODE_LIST_ENTRY_SIZE * countNode());
        buf.order(ByteOrder.LITTLE_ENDIAN);
        for (Node node : nodeSet) {
            buf.put(Arrays.copyOf(node.getId(), 20));
            buf.put(node.toBuffer());
        }
        buf.flip();
        return buf;
    }

    public ByteBuffer toLogData() {
        int nrNodes = nodeSet.size();
        ByteBuffer buf = ByteBuffer.allocate(16 + nrNodes * Node.NODE_SIZE);
        buf.order(ByteOrder.LITTLE_ENDIAN);

        buf.putInt(epoch);
        buf.putInt(nrNodes);
        buf.putInt(masterIndex);
        buf.putInt(0);
        for (Node node : nodeSet) {
            buf.put(node.toBuffer());
        }
        buf.flip();
        return buf;
    }

    public static NodeList fromLogData(ByteBuffer buf) {
        int epoch = buf.getInt();
        int nrNodes = buf.getInt();
        int masterIndex = buf.getInt();
        buf.getInt();
        TreeSet<Node> nodeSet = new TreeSet<Node>();
        for (int i = 0; i < nrNodes; i++) {
            ByteBuffer nodeBuf = ByteBuffer.allocate(Node.NODE_SIZE);
            nodeBuf.order(ByteOrder.LITTLE_ENDIAN);
            buf.get(nodeBuf.array());
            nodeSet.add(Node.fromBuffer(nodeBuf));
        }
        NodeList nodeList = new NodeList(epoch, nodeSet);
        nodeList.setMasterIndex(masterIndex);
        return nodeList;
    }

    @Override
    public String toString() {
        return "[epoch: " + epoch + ", map: " + nodeSet + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof NodeList)) {
            return false;
        }
        NodeList nl = (NodeList) o;
        if (nl == null) {
            return false;
        }
        if (this.epoch != nl.epoch) {
            return false;
        }
        return this.nodeSet.equals(nl.nodeSet);
    }

    @Override
    public int hashCode() {
        return nodeSet.hashCode() + epoch;
    }

    public boolean containsAll(NodeList nl) {
        if (nl == null) {
            return false;
        }
        for (Node node : nl.getNodeSet()) {
            if (!this.nodeSet.contains(node)) {
                return false;
            }
        }
        return true;
    }

    public boolean add(Node node) {
        boolean ret = nodeSet.add(node);
        if (ret) {
            epoch++;
        }
        return ret;
    }

    public boolean remove(Node node) {
        boolean ret = nodeSet.remove(node);
        if (ret) {
            epoch++;
        }
        return ret;
    }

    private int epoch;
    private TreeSet<Node> nodeSet;
}
