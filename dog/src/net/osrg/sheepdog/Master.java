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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.Channel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import net.osrg.sheepdog.headers.Request;
import net.osrg.sheepdog.headers.Response;
import net.osrg.sheepdog.messages.SheepdogMessage;
import net.osrg.sheepdog.messages.LeaveMessage;

public class Master implements Runnable, ConnectionCallback {

    private Node thisNode;
    private Selector selector;
    private boolean isMaster;
    private NodeList nodeList;
    // TODO too many HashMap
    private Map<Node, SelectionKey> connectedMap;
    private Map<Node, Integer> keepAliveMap;
    private Map<SelectionKey, Node> rconnectedMap;
    private Set<SelectionKey> ackedMap;
    private Map<SelectionKey, Connection> connMap;
    private int epoch;
    private boolean epochUpdated;
    private Sheepdog sd;
    private Lock lock;
    private Condition notMaster;
    private int nrSubmasters;
    private boolean shutdown;

    public static final int KEEPCNT = 15;
    public static final int KEEPIDLE = 1000;

    public void start(NodeList nl, int nrSubmasters, boolean shutdown) {
        this.nrSubmasters = nrSubmasters;
        this.shutdown = shutdown;
        lock.lock();
        try {
            Log.debug(nl);
            nodeList = nl;
            if (!isMaster) {
                isMaster = true;
                try {
                    selector = Selector.open();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                notMaster.signal();
            }
        } finally {
            lock.unlock();
        }
    }

    public void stop() {
        lock.lock();
        try {
            isMaster = false;
        } finally {
            lock.unlock();
        }
    }

    public Master(Node thisNode, Sheepdog s) {
        this.thisNode = thisNode;
        sd = s;
        epoch = -1;
        epochUpdated = false;
        nodeList = new NodeList();
        connectedMap = new HashMap<Node, SelectionKey>();
        keepAliveMap = new HashMap<Node, Integer>();
        rconnectedMap = new HashMap<SelectionKey, Node>();
        connMap = new HashMap<SelectionKey, Connection>();
        ackedMap = new HashSet<SelectionKey>();
        isMaster = false;
        selector = null;
        lock = new ReentrantLock();
        notMaster = lock.newCondition();
        this.nrSubmasters = 0;
        this.shutdown = false;
    }

    private void leave(Node host) {
        Log.debug(host);

        SheepdogMessage sm = new LeaveMessage(thisNode, 0, host);
        sd.addMessage(sm);
    }

    private void timeout() {
        // timeout
        nodeList.setMasterNode(thisNode);
        if (epoch < nodeList.getEpoch()) {
            epoch = nodeList.getEpoch();
            epochUpdated = true;
            Log.debug("epoch is updated. new epoch is " + epoch);
        } else {
            epochUpdated = false;
        }
        Set<Node> nodeSet = nodeList.getNodeSet();
        for (Node node : nodeSet) {
            try {
                if (connectedMap.get(node) != null) {
                    SelectionKey key = connectedMap.get(node);
                    if (connMap.get(key).isConnDead()) {
                        connectedMap.remove(node);
                        keepAliveMap.remove(node);
                        rconnectedMap.remove(key);
                        connMap.remove(key);
                        ackedMap.remove(key);
                    } else {
                        continue;
                    }
                }
                InetSocketAddress address;
                address = new InetSocketAddress(node.getInetAddress(), node
                        .getDogPort());
                SocketChannel ch = SocketChannel.open();
                ch.configureBlocking(false);
                ch.connect(address);

                SelectionKey key = ch.register(selector,
                        SelectionKey.OP_CONNECT);
                connMap.put(key, new Connection(key, node.hashCode(), this));
                rconnectedMap.put(key, node);
            } catch (Exception e) {
                Log.error("Exception caught: " + e);
                SelectionKey key = connectedMap.get(node);
                connectedMap.remove(node);
                keepAliveMap.remove(node);
                rconnectedMap.remove(key);
                connMap.remove(key);
                ackedMap.remove(key);
                continue;
            }
        }

        Iterator<Node> itr = connectedMap.keySet().iterator();
        while (itr.hasNext()) {
            Node node = itr.next();
            SelectionKey key = connectedMap.get(node);
            if (node != null && ackedMap.contains(key)) {
                ackedMap.remove(key); // reset
                Connection conn = connMap.get(key);

                Log.debug("send probe to " + rconnectedMap.get(key));

                // TODO implement KeepAlive header class
                if (epochUpdated) {
                    Response rsp = new Response(null, OpCode.OP_UPDATE_NODELIST
                            .getValue(), nodeList.toLogData(), 0);
                    rsp.setId(nrSubmasters);
                    conn.setTxOn(rsp);
                } else {
                    Response rsp = new Response(null, OpCode.OP_NOP.getValue(), null, 0);
                    if (shutdown) {
                        rsp.setId(1);
                    } else {
                        rsp.setId(0);
                    }
                    conn.setTxOn(rsp);
                }
                keepAliveMap.put(node, 0);
                continue;
            }

            keepAliveMap.put(node, keepAliveMap.get(node) + 1);
            if (keepAliveMap.get(node) < KEEPCNT) {
                Log.debug(node + " may down: " + keepAliveMap.get(node));
                continue;
            }
            Channel c = key.channel();
            try {
                c.close();
            } catch (IOException e) {
                Log.error("failed to close: ", e);
            }
            Log.debug("remove node");
            if (nodeSet.contains(node)) {
                leave(node);
            }
            rconnectedMap.remove(key);
            itr.remove();
            keepAliveMap.remove(node);
            connMap.remove(key);
            ackedMap.remove(key);
        }
    }

    private void stopMaster() {
        try {
            if (selector != null) {
                Iterator<SelectionKey> itr = selector.keys().iterator();
                while (itr.hasNext()) {
                    SelectionKey key = itr.next();
                    Channel c = key.channel();
                    Log.debug("Closing " + c.toString());
                    try {
                        c.close();
                    } catch (IOException e) {
                        Log.error("failed to close: ", e);
                    }
                    Node node = rconnectedMap.remove(key);
                    Set<Node> nodeSet = nodeList.getNodeSet();
                    if (nodeSet != null && nodeSet.contains(node)) {
                        leave(node);
                    }
                    connectedMap.remove(node);
                    keepAliveMap.remove(node);
                    connMap.remove(key);
                    ackedMap.remove(key);
                }
                selector.close();
                selector = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        for (;;) {
            try {
                lock.lock();
                try {
                    while (!isMaster) {
                        stopMaster();
                        notMaster.await();
                    }
                } finally {
                    lock.unlock();
                }

                while (selector.select(KEEPIDLE) > 0) {
                    // Get "selected" objects
                    Iterator<SelectionKey> itr = selector.selectedKeys()
                            .iterator();
                    while (itr.hasNext()) {
                        SelectionKey key = itr.next();
                        itr.remove();

                        if (!key.isValid()) {
                            continue;
                        }

                        try {
                            if (key.isConnectable()) {
                                SocketChannel ch = (SocketChannel) key
                                        .channel();
                                ch.finishConnect();
                                connectedMap.put(rconnectedMap.get(key), key);
                                keepAliveMap.put(rconnectedMap.get(key), 0);
                                ackedMap.add(key);
                                Log.debug("connected: " + rconnectedMap.get(key));

                                Connection conn = connMap.get(key);

                                key.interestOps(0); // remove OP_CONNECT
                                Response rsp = new Response(null, OpCode.OP_UPDATE_NODELIST.getValue(),
                                        nodeList.toLogData(), 0);
                                rsp.setId(nrSubmasters);
                                conn.setTxOn(rsp);

                                Log.debug("send probe to " + rconnectedMap.get(key));
                            } else if (key.isWritable()) {
                                connMap.get(key).txHandler();
                            } else if (key.isReadable()) {
                                Log.debug("ack from "
                                        + rconnectedMap.get(key));
                                connMap.get(key).rxHandler();
                            }
                        } catch (IOException e) {
                            Log.debug("remove node: " + e + " " + rconnectedMap.get(key));
                            Node node = rconnectedMap.remove(key);
                            if (nodeList.getNodeSet().contains(node)) {
                                leave(node);
                            }
                            SocketChannel ch = (SocketChannel) key.channel();
                            ch.close();
                            connectedMap.remove(node);
                            keepAliveMap.remove(node);
                            rconnectedMap.remove(key);
                            connMap.remove(key);
                            ackedMap.remove(key);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            timeout();
        }
    }

    @Override
    public void rxDone(SelectionKey key, OpCode op, Request req, int uid)
            throws IOException {
        ackedMap.add(key);
    }
}
