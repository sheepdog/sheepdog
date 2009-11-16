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
import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import java.util.Map.Entry;

public class ClusterInformation implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -5465560224627172616L;
    public NodeList nodeList;
    private Map<String, Node> locktbl;
    private boolean complete;
    private Node thisNode;
    private boolean initialized;
    private boolean shutdown;

    public boolean isComplete() {
        return complete;
    }

    public void setComplete(boolean complete) {
        Log.debug("set complete");
        this.complete = complete;
    }

    public ClusterInformation(Node thisNode, boolean logging) {
        nodeList = new NodeList();
        locktbl = new HashMap<String, Node>();
        complete = false;
        setInitialized(false);
        startupNodeList = null;
        this.thisNode = thisNode;
        this.shutdown = false;
    }

    public int lock(String vdiname, Node node) throws Exception {
        if (locktbl.containsKey(vdiname) && locktbl.get(vdiname) != null) {
            // TODO throw Exception when locking is failed
            return -1;
        }
        locktbl.put(vdiname, node);
        return 0;
    }

    public int unlock(String vdiname) throws Exception {
        if (!locktbl.containsKey(vdiname) || locktbl.get(vdiname) == null) {
            // TODO throw Exception when locking is failed
            return -1;
        }
        locktbl.put(vdiname, null);
        return 0;
    }

    public void join(Node node) {
        nodeList.add(node);
    }

    public void leave(Node node) {
        nodeList.remove(node);
    }

    public void merge(ClusterInformation ci) {
        if (!ci.isComplete()) {
            Log.error("unexpected error");
            return;
        }

        setInitialized(ci.isInitialized());
        locktbl = ci.getLockTable();
        nodeList = ci.nodeList;
        complete = true;
    }


    public Map<String, Node> getLockTable() {
        return locktbl;
    }

    public NodeList getNodeList() {
        if (isInitialized()) {
            return nodeList;
        } else {
            TreeSet<Node> set = new TreeSet<Node>();
            set.add(thisNode);
            NodeList nl = new NodeList(0, set);
            return nl;
        }
    }

    public ByteBuffer encodeLockTbl() {
        ByteBuffer buf = ByteBuffer.allocate(lockTblSize());
        buf.order(ByteOrder.LITTLE_ENDIAN);

        for (Entry<String, Node> ent : locktbl.entrySet()) {
            String name = ent.getKey();
            Node node = ent.getValue();
            if (node == null) {
                continue;
            }
            for (int i = 0; i < 32; i++) {
                if (i < name.length()) {
                    buf.put((byte) name.charAt(i));
                } else {
                    buf.put((byte) 0);
                }
            }
            buf.put(node.toBuffer());
            for (int i = 0; i < 4; i++) {
                buf.put((byte) 0); // padding
            }
        }
        buf.flip();
        return buf;
    }

    public int lockTblSize() {
        return 56 * locktbl.size();
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void addStartupNodeList(NodeList nl, long ctime) {
        startupNodeList = nl;
        this.ctime = ctime;
    }

    private NodeList startupNodeList;
    private long ctime;

    public NodeList getStartupNodeList() {
        return startupNodeList;
    }

    public void setInitialized(boolean initialized) {
        this.initialized = initialized;
    }

    public void setShutdown(boolean shutdown) {
        this.shutdown = shutdown;
    }

    public boolean isShutdown() {
        return shutdown;
    }

    public void setCtime(long ctime) {
        this.ctime = ctime;
    }

    public long getCtime() {
        return ctime;
    }
}
