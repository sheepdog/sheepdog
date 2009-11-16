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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeSet;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import net.osrg.sheepdog.MasterGroup.ROLE;
import net.osrg.sheepdog.headers.NodeRequest;
import net.osrg.sheepdog.headers.NodeResponse;
import net.osrg.sheepdog.headers.ObjectRequest;
import net.osrg.sheepdog.headers.Request;
import net.osrg.sheepdog.headers.Response;
import net.osrg.sheepdog.headers.VdiRequest;
import net.osrg.sheepdog.messages.DelVdiMessage;
import net.osrg.sheepdog.messages.GetVdiInfoMessage;
import net.osrg.sheepdog.messages.GetVmListMessage;
import net.osrg.sheepdog.messages.JoinMessage;
import net.osrg.sheepdog.messages.LeaveMessage;
import net.osrg.sheepdog.messages.MakeFsMessage;
import net.osrg.sheepdog.messages.ReleaseVdiMessage;
import net.osrg.sheepdog.messages.RequestClusterInfoMessage;
import net.osrg.sheepdog.messages.SheepdogMessage;
import net.osrg.sheepdog.messages.NewVdiMessage;
import net.osrg.sheepdog.messages.ShutdownMessage;
import net.osrg.sheepdog.messages.UpdateEpochMessage;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.daemon.Daemon;
import org.apache.commons.daemon.DaemonContext;
import org.apache.log4j.Level;
import org.jgroups.Channel;
import org.jgroups.ChannelClosedException;
import org.jgroups.ChannelException;
import org.jgroups.ChannelNotConnectedException;
import org.jgroups.JChannel;
import org.jgroups.Message;
import org.jgroups.ReceiverAdapter;
import org.jgroups.conf.ConfiguratorFactory;
import org.jgroups.conf.ProtocolData;
import org.jgroups.conf.ProtocolParameter;
import org.jgroups.conf.ProtocolStackConfigurator;
import org.jgroups.conf.XmlConfigurator;

class JGroupsConnector implements Runnable {
    private JChannel jch;
    private Sheepdog sd;
    private MasterGroup mg;
    private Lock lock;
    private Condition connected;

    public JGroupsConnector(Sheepdog sd, MasterGroup mg, JChannel channel) {
        this.sd = sd;
        this.mg = mg;
        jch = channel;
        lock = new ReentrantLock();
        connected = lock.newCondition();
    }

    public void connect() {
        lock.lock();
        try {
            connected.signal();
        } finally {
            lock.unlock();
        }
    }

    public void disconnect() {
        lock.lock();
        try {
            jch.disconnect();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void run() {
        try {
            for (;;) {
                lock.lock();
                try {
                    while (jch.isConnected()) {
                        connected.await();
                    }
                } finally {
                    lock.unlock();
                }
                mg.initialize();
                jch.connect("Sheepdog cluster");
                // TODO if I am SLAVE and there are too many
                // members, disconnect and sleep
                sd.connectDone();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}

public class Sheepdog implements ConnectionCallback, Daemon, Runnable {

    public static final int DEFAULT_LIMIT_MBRS = 6;
    private int limitMbrs;

    public int getLimitMbrs() {
        return limitMbrs;
    }

    public void setLimitMbrs(int limitMbrs) {
        this.limitMbrs = limitMbrs;
    }

    private Node thisNode;
    private JChannel channel;

    private HashMap<Integer, SelectionKey> keyMap;
    private NodeList currentNodeList;

    public NodeList getNodeList() {
        return currentNodeList;
    }

    private Selector selector;
    private JGroupsConnector connector;

    public static final int DEFAULT_DOG_PORT = 7000;
    public static final int DEFAULT_SHEEP_PORT = 10095;
    public static final int DEFAULT_MCAST_PORT = 45566;
    public static final String DEFAULT_CONF_FILE = "sd.xml";
    private boolean shutdown;

    private BlockingQueue<SheepdogMessage> msgQueue;
    private boolean connected;

    public void connectDone() {
        try {
            SheepdogMessage sm;
            sm = new RequestClusterInfoMessage(thisNode, thisNode.hashCode(), channel.getLocalAddress());
            groupMsgCount++;
            channel.send(new Message(null, null, sm));
            // ms_key.interestOps(SelectionKey.OP_READ);
            lock.lock();
            try {
                connected = true;
                notConnected.signalAll();
                doneSignal.countDown();
            } finally {
                lock.unlock();
            }
        } catch (ChannelNotConnectedException e) {
            e.printStackTrace();
        } catch (ChannelClosedException e) {
            e.printStackTrace();
        }
    }

    public void disconnectDone(ROLE role) {
        lock.lock();
        try {
            groupMsgCount--;
            if (role == ROLE.SLAVE && groupMsgCount <= 0) {
                connector.disconnect();
                Log.debug("disconnect");
                // ms_key.interestOps(0);
                connected = false;
            }
        } finally {
            lock.unlock();
        }
    }

    private void accept(SelectionKey key) throws IOException {
        ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
        SocketChannel sc = ssc.accept();
        sc.configureBlocking(false);
        // register new socket to the selector
        SelectionKey sk = sc.register(selector, SelectionKey.OP_READ);
        int uid = sk.hashCode();
        sk.attach(new Connection(sk, uid, this));
        keyMap.put(uid, sk);
    }

    public static void main(String[] argv) {
        Sheepdog sd = new Sheepdog();
        try {
            sd.init(argv);
            sd.start();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Log.debug("exit");
    }

    private int groupMsgCount = 0;

    public void addMessage(SheepdogMessage sm) {
        try {
            msgQueue.put(sm);
            connector.connect();
        } catch (InterruptedException e) {
            // TODO auto generated
            e.printStackTrace();
        }
    }

    public void setResult(int uid, Response rsp) {
        SelectionKey sk = keyMap.get(uid);

        sk = keyMap.get(uid);
        if (sk == null) {
            return; // TODO
        }
        Connection conn = (Connection) sk.attachment();
        if (currentNodeList != null) {
            rsp.setEpoch(currentNodeList.getEpoch());
        } else {
            rsp.setEpoch(0);
        }
        conn.setTxOn(rsp);
        selector.wakeup();
    }

    private NodeResponse readNodeList(NodeRequest req, int uid) {
        NodeResponse response = null;
        int requestEpoch = req.getRequestEpoch();
        NodeList nodeList = currentNodeList;

        if (nodeList.getEpoch() == 0 || doneSignal.getCount() > 0) {
            // start up
            TreeSet<Node> set = new TreeSet<Node>();
            set.add(thisNode);
            nodeList = new NodeList(0, set);
        }

        if (requestEpoch != 0) {
            int epoch = nodeList.getEpoch();
            if (epoch != 0) {
                TreeSet<Node> set = (TreeSet<Node>) nodeList.getNodeSet();
                NodeLogOperator operator = new NodeLogOperator();
                return operator.readPastNodeList(OpCode.OP_GET_NODE_LIST, epoch,
                        set, requestEpoch, req);
            }
            response = new NodeResponse(req, OpCode.OP_GET_NODE_LIST.getValue(), null, 0);
            response.setResult(SheepdogException.STARTUP);
        } else {
            response = new NodeResponse(req, OpCode.OP_GET_NODE_LIST.getValue(), nodeList.toRspData(), 0);
            response.setResult(SheepdogException.SUCCESS);
        }
        response.setNrNodes(nodeList.countNode());
        response.setLocalIdx(nodeList.getIndex(thisNode));
        response.setMasterIdx(nodeList.getMasterIndex());
        return response;
    }

    @Override
    public void rxDone(SelectionKey key, OpCode op, Request req, int uid)
            throws IOException {
        Connection conn = (Connection) key.attachment();
        Log.debug("ioDone: uid = " + uid + ", cmd = " + op);

        SheepdogMessage sm;
        String vdiName;
        VdiRequest vdiReq;

        switch (op) {
        case OP_NEW_VDI:
        case OP_DEL_VDI:
        case OP_LEAVE:
        case OP_LOCK_VDI:
        case OP_RELEASE_VDI:
        case OP_GET_VDI_INFO:
        case OP_GET_VM_LIST:
        case OP_MAKE_FS:
        case OP_UPDATE_EPOCH:
            int currentEpoch = currentNodeList.getEpoch();
            if (shutdown) {
                Response rsp = new Response();
                rsp.setResult(SheepdogException.SHUTDOWN);
                rsp.setEpoch(0);
                conn.setTxOn(rsp);
                return;
            }
            if (doneSignal.getCount() > 0 || currentEpoch == 0
                    && (op != OpCode.OP_MAKE_FS)) {
                Response rsp = new Response();
                rsp.setResult(SheepdogException.STARTUP);
                rsp.setEpoch(0);
                conn.setTxOn(rsp);
                return;
            }
            if (req.getEpoch() < currentEpoch) {
                Response rsp = new Response();
                rsp.setResult(SheepdogException.OLD_NODE_VER);
                rsp.setEpoch(currentEpoch);
                conn.setTxOn(rsp);
                return;
            } else if (req.getEpoch() > currentEpoch) {
                Response rsp = new Response();
                rsp.setResult(SheepdogException.NEW_NODE_VER);
                rsp.setEpoch(currentEpoch);
                conn.setTxOn(rsp);
                return;
            }
            break;
        default:
            break;
        }

        try {
            switch (op) {
            case OP_NEW_VDI:
                vdiReq = new VdiRequest(req);
                vdiName = new String(vdiReq.getData().array());
                vdiName = vdiName.trim(); // remove NULL characters
                sm = new NewVdiMessage(thisNode, vdiName, vdiReq.getBaseOid(),
                        vdiReq.getTag(), vdiReq.getVdiSize(),
                        vdiReq.getFlags(), uid);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_DEL_VDI:
                sm = new DelVdiMessage(thisNode, uid);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_LEAVE:
                sm = new LeaveMessage(thisNode, uid, thisNode);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_LOCK_VDI:
                vdiReq = new VdiRequest(req);
                vdiName = new String(vdiReq.getData().array());
                vdiName = vdiName.trim(); // remove NULL characters
                sm = new GetVdiInfoMessage(thisNode, vdiName, vdiReq
                        .getBaseOid(), vdiReq.getTag(), vdiReq.getVdiSize(),
                        vdiReq.getFlags(), uid, true);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_RELEASE_VDI:
                vdiName = new String(req.getData().array());
                vdiName = vdiName.trim(); // remove NULL characters
                sm = new ReleaseVdiMessage(thisNode, uid, vdiName);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_GET_VDI_INFO:
                vdiReq = new VdiRequest(req);
                vdiName = new String(vdiReq.getData().array());
                vdiName = vdiName.trim(); // remove NULL characters
                sm = new GetVdiInfoMessage(thisNode, vdiName, vdiReq
                        .getBaseOid(), vdiReq.getTag(), vdiReq.getVdiSize(),
                        vdiReq.getFlags(), uid, false);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_GET_EPOCH:
                vdiReq = new VdiRequest(req);
                sm = new GetVdiInfoMessage(thisNode, null, vdiReq
                        .getBaseOid(), vdiReq.getTag(), vdiReq.getVdiSize(),
                        vdiReq.getFlags(), uid, false);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_GET_VM_LIST:
                sm = new GetVmListMessage(thisNode, uid);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_MAKE_FS:
                // TODO do not use ObjectRequest here
                ObjectRequest objReq = new ObjectRequest(req);
                sm = new MakeFsMessage(thisNode, objReq.getCopies(), uid);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_UPDATE_EPOCH:
                vdiReq = new VdiRequest(req);
                sm = new UpdateEpochMessage(thisNode, vdiReq.getBaseOid(),
                        vdiReq.getEpoch(), uid);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_SHUTDOWN:
                sm = new ShutdownMessage(thisNode, uid);
                msgQueue.put(sm);
                connector.connect();
                break;
            case OP_NOP:
                shutdown = (req.getId() > 0);
                conn.setTxOn(ByteBuffer.allocate(0));
                break;
            case OP_UPDATE_NODELIST:
                currentNodeList = NodeList.fromLogData(req.getData());
                Log.debug(currentNodeList);
                conn.setTxOn(ByteBuffer.allocate(0));
                int nrSubmasters = req.getId(); // TODO
                if (nrSubmasters < this.limitMbrs) {
                    connector.connect();
                }
                break;
            case OP_GET_NODE_LIST:
                NodeResponse nodeResp = readNodeList(new NodeRequest(req), uid);
                if (currentNodeList != null) {
                    if (doneSignal.getCount() > 0) {
                        nodeResp.setEpoch(0);
                    } else {
                        nodeResp.setEpoch(currentNodeList
                                .getEpoch());
                    }
                } else {
                    nodeResp.setEpoch(0);
                }
                conn.setTxOn(nodeResp);
                break;
            default:
                Log.error("Unknown command: " + op);
                break;
            }
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void destroy() {
        // TODO Auto-generated method stub
    }

    private boolean checkJgroups(ProtocolStackConfigurator conf) {
        final Lock lock = new ReentrantLock();
        final Condition notConnected = lock.newCondition();
        try {
            JChannel channel = new JChannel(conf);
            channel.setReceiver(new ReceiverAdapter() {
                    public void receive(Message msg) {
                        try {
                            lock.lock();
                            notConnected.signal();
                        } catch (Exception e) {
                            e.printStackTrace();
                        } finally {
                            lock.unlock();
                        }
                    }
                });
            lock.lock();
            channel.connect("jgroups test " + thisNode.toString());
            channel.send(new Message(null, null, null));
            long nanosTimeout = notConnected.awaitNanos(3000000000L);
            channel.close();
            return (nanosTimeout > 0);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            lock.unlock();
        }
        return false;
    }

    private void init(String[] argv) {
        Options options = new Options();
        options.addOption("f", "foreground", false, "run in the foreground");
        options.addOption("c", "conf", true, "config file");
        options.addOption("n", true, "number of master group");
        options.addOption("p", "dport", true, "dog port");
        options.addOption("s", "sport", true, "sheep port");
        options.addOption("m", "mport", true, "multicast port");
        options.addOption("a", true, "bind_addr");
        options.addOption("d", "debug", false, "debug option");
        options.addOption("h", "help", false, "help");
        options.addOption("4", "ipv4", false, "force IPv4");
        options.addOption("6", "ipv6", false, "force IPv6");
        options.addOption("r", "syslog", true, "send logs to the syslog server");

        CommandLineParser parser = new GnuParser();
        CommandLine cl = null;
        int dPort = DEFAULT_DOG_PORT;
        int sPort = DEFAULT_SHEEP_PORT;
        int mPort = DEFAULT_MCAST_PORT;
        int limitMbrs = DEFAULT_LIMIT_MBRS;
        String confFile = DEFAULT_CONF_FILE;

        lock = new ReentrantLock();
        notConnected = lock.newCondition();

        try {
            cl = parser.parse(options, argv);
            if (cl.hasOption("h")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("dog", options, true);
                System.exit(1);
            }
            if (cl.hasOption("c")) {
                confFile = cl.getOptionValue("c");
            }
            if (cl.hasOption("n")) {
                limitMbrs = Integer.parseInt(cl.getOptionValue("n"));
            }
            if (cl.hasOption("p")) {
                dPort = Integer.parseInt(cl.getOptionValue("p"));
            }
            if (cl.hasOption("s")) {
                sPort = Integer.parseInt(cl.getOptionValue("s"));
            }
            if (cl.hasOption("m")) {
                mPort = Integer.parseInt(cl.getOptionValue("m"));
            }
            if (cl.hasOption("a")) {
                System.setProperty("jgroups.bind_addr", cl.getOptionValue("a"));
            }
            if (cl.hasOption("4")) {
                System.setProperty("java.net.preferIPv4Stack", "true");
            }
            if (cl.hasOption("6")) {
                System.setProperty("java.net.preferIPv6Stack", "true");
            }
            if (cl.hasOption("r")) {
                Log.useSyslog(cl.getOptionValue("r"));
            } else {
                Log.useStdout();
            }
            if (cl.hasOption("d")) {
                Log.setLevel(Level.DEBUG);
            }
        } catch (ParseException e) {
            HelpFormatter formatter = new HelpFormatter();
            System.err.println(e.getLocalizedMessage());
            formatter.printHelp("dog", options, true);
            System.exit(1);
        } catch (NumberFormatException e) {
            HelpFormatter formatter = new HelpFormatter();
            System.err.println(e.getLocalizedMessage() + ": must be a number");
            formatter.printHelp("dog", options, true);
            System.exit(1);
        }

        try {
            thisNode = new Node(InetAddress.getLocalHost(), dPort, sPort);
        } catch (UnknownHostException e1) {
            // TODO auto generated
            e1.printStackTrace();
        }

        try {
            ProtocolStackConfigurator conf;
            conf = ConfiguratorFactory.getStackConfigurator(confFile);
            if (!(conf instanceof XmlConfigurator)) {
                HelpFormatter formatter = new HelpFormatter();
                System.err.println("cannot find " + confFile);
                formatter.printHelp("dog", options, true);
                System.exit(1);
            }
            ProtocolParameter[] params = new ProtocolParameter[1];
            params[0] = new ProtocolParameter("mcast_port", Integer
                    .toString(mPort));
            ProtocolData data = new ProtocolData("UDP", params);
            ((XmlConfigurator) conf).override(data);
            if (!checkJgroups(conf)) {
                System.err.println("failed to set up JGroups");
                System.err.println("check the network configuration");
                System.exit(1);
            }
            channel = new JChannel(conf);
            // TODO deal with AUTO_RECONNECT and AUTO_GENSTATE
            channel.setOpt(Channel.BLOCK, true);
            channel.setOpt(Channel.LOCAL, true);
            Master master = new Master(thisNode, this);

            msgQueue = new LinkedBlockingQueue<SheepdogMessage>();
            connected = false;
            keyMap = new HashMap<Integer, SelectionKey>();
            currentNodeList = new NodeList();
            this.limitMbrs = limitMbrs;
            this.shutdown = false;

            InetSocketAddress address;
            ServerSocketChannel ssc = ServerSocketChannel.open();
            ssc.configureBlocking(false);
            address = new InetSocketAddress(dPort);
            ssc.socket().bind(address);

            selector = Selector.open();
            ssc.register(selector, SelectionKey.OP_ACCEPT);

            MasterGroup mg = new MasterGroup(thisNode, master, this, channel);
            connector = new JGroupsConnector(this, mg, channel);

            channel.setReceiver(mg);

            Executor ex = Executors.newCachedThreadPool();
            ex.execute(master);
            ex.execute(connector);
            ex.execute(new MessageDispatcher());
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (ChannelException ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void init(DaemonContext dc) throws Exception {
        String[] argv = dc.getArguments();
        init(argv);
    }

    private CountDownLatch doneSignal;

    private SheepdogMessage createJoinMessage() {
        try {
            // TODO use defaultNrCopies in the super block
            ObjectOperator objectOperator = new ObjectOperator();
            TreeSet<Node> set = new TreeSet<Node>();
            set.add(thisNode);
            NodeList nl = new NodeList(0, set);
            ByteBuffer object = objectOperator.readObject(nl, ObjectOperator.DIRECTORY_OID, 1,
                    SuperObject.SUPER_OBJ_SIZE + SuperObject.NODE_LOG_SIZE + 1024 * 1024);
            SuperObject superObject = new SuperObject(object);

            return new JoinMessage(thisNode, 0,
                    superObject.getLastNodeList(), superObject.getCtime(), false);
        } catch (SheepdogException oe) {
            int result = oe.getErrorCode();
            if (result == SheepdogException.NO_OBJ) {
                return new JoinMessage(thisNode, 0, null, 0, false);
            } else {
                Log.error("failed to read the log");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // TODO auto-generated
                    e.printStackTrace();
                }
                return createJoinMessage();
            }
        }
    }

    @Override
    public void start() throws Exception {
        doneSignal = new CountDownLatch(1);

        Thread thread = new Thread(this);
        thread.start();

        SheepdogMessage sm = createJoinMessage();
        addMessage(sm);

        doneSignal.await();
    }

    @Override
    public void stop() throws Exception {
        // TODO Auto-generated method stub
    }

    private Lock lock;
    private Condition notConnected;

    private class MessageDispatcher implements Runnable {

        @Override
        public void run() {
            for (;;) {
                try {
                    SheepdogMessage sm = msgQueue.take();
                    lock.lock();
                    try {
                        while (!connected) {
                            notConnected.await();
                        }
                        groupMsgCount++; // TODO decrement when cmd is unknown
                    } finally {
                        lock.unlock();
                    }
                    channel.send(new Message(null, null, sm));
                } catch (ChannelNotConnectedException e) {
                    // TODO auto generated
                    e.printStackTrace();
                } catch (ChannelClosedException e) {
                    // TODO auto generated
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    // TODO auto generated
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Override
    public void run() {
        try {
            while (selector.select() >= 0) {
                // Get "selected" objects
                Iterator<SelectionKey> itr = selector.selectedKeys().iterator();
                while (itr.hasNext()) {
                    SelectionKey key = itr.next();
                    itr.remove();

                    if (!key.isValid()) {
                        Log.error("key is invalid");
                        continue;
                    }

                    if (key.isAcceptable()) {
                        accept(key);
                    } else if (key.isReadable()) {
                        Connection conn = (Connection) key.attachment();
                        conn.rxHandler();
                    } else if (key.isWritable()) {
                        Connection conn = (Connection) key.attachment();
                        conn.txHandler();
                    }
                }
            }
            Log.error("ERROR: select returns unexpectedly");
            channel.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
