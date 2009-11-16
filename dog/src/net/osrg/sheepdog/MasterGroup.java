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

import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Vector;

import net.osrg.sheepdog.headers.Response;
import net.osrg.sheepdog.messages.MasterChangedMessage;
import net.osrg.sheepdog.messages.SheepdogMessage;

import org.jgroups.Address;
import org.jgroups.JChannel;
import org.jgroups.Message;
import org.jgroups.ReceiverAdapter;
import org.jgroups.View;

public class MasterGroup extends ReceiverAdapter {
    private Node thisNode;
    private Sheepdog sd;
    private JChannel jchannel;
    private ClusterInformation ci;
    private int nrSubmasters;
    private Queue<SheepdogMessage> pendingMessages;
    private Master master;

    public enum ROLE {
        MASTER, SUBMASTER, SLAVE
    };

    private ROLE role = ROLE.SLAVE;

    public MasterGroup(Node thisNode, Master master, Sheepdog sd, JChannel jch) {
        this.thisNode = thisNode;
        pendingMessages = new LinkedList<SheepdogMessage>();
        this.sd = sd;
        this.master = master;
        jchannel = jch;
        initialize();
        this.nrSubmasters = 0;
    }

    public void initialize() {
        role = ROLE.SLAVE;
        ci = new ClusterInformation(thisNode, true);
    }

    @Override
    public synchronized void receive(Message msg) {
        try {
            SheepdogMessage sm = (SheepdogMessage) msg.getObject();
            Log.debug("receive start: class = " + sm.getClass().toString()
                    + ", isFlushed = " + sm.isFlushed());
            if (sm.isFlushed()) {
                if (pendingMessages.peek() != null) {
                    if (pendingMessages.peek().getMessageId() == sm.getMessageId()) {
                        pendingMessages.remove();
                    }
                }
                if (!ci.isShutdown()) {
                    sm.updateClusterInfo(ci);
                }
                if (role == ROLE.MASTER) {
                    master.start(ci.getNodeList(), nrSubmasters, ci.isShutdown());
                }
                if (thisNode.equals(sm.getFrom())) {
                    Response rsp = sm.reply(ci);
                    if (rsp != null) {
                        sd.setResult(sm.getMessageId(), rsp);
                    }
                    sd.disconnectDone(role);
                }
            } else {
                pendingMessages.add(sm);
                if (role == ROLE.MASTER) {
                    if (!ci.isShutdown()) {
                        sm.updateSuperObject(ci);
                    }
                    sm.setFlushed(true);
                    sd.addMessage(sm);
                } else if (thisNode.equals(sm.getFrom()) && sm instanceof MasterChangedMessage) {
                    role = ROLE.MASTER;
                    while (pendingMessages.peek() != null) {
                        SheepdogMessage pendingMsg = pendingMessages.poll();
                        if (!ci.isShutdown()) {
                            pendingMsg.updateSuperObject(ci);
                        }
                        pendingMsg.setFlushed(true);
                        sd.addMessage(pendingMsg);
                    }
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void suspect(Address address) {
        Log.debug("suspect: " + address);
    }

    @Override
    public void block() {
        Log.debug("blocked");
    }

    @Override
    public synchronized void viewAccepted(View view) {
        Log.debug("new master groups: " + view.getMembers());
        Log.debug("local address: " + jchannel.getLocalAddress());

        try {
            Log.debug("viewAccepted: " + view);
            Log.debug("mbrs: " + view.size());
            Address localAddr = jchannel.getLocalAddress();
            if (view.containsMember(localAddr)) {
                Vector<Address> mbrs = view.getMembers();
                if (mbrs.get(0).equals(localAddr)) {
                    MasterChangedMessage msg = new MasterChangedMessage(thisNode, 0);
                    sd.addMessage(msg);
                    ci.setComplete(true);
                    Log.debug("role = MASTER. ");
                    nrSubmasters = view.size();
                    master.start(ci.getNodeList(), nrSubmasters, ci.isShutdown());
                    return;
                }
                List<Address> submasters = mbrs.subList(1, Math.min(
                        mbrs.size(), sd.getLimitMbrs()));
                Log.debug("new submasters: " + submasters);
                for (Address addr : submasters) {
                    if (addr.equals(localAddr)) {
                        role = ROLE.SUBMASTER;
                        Log.debug("role = SUBMASTER. ");
                        master.stop();
                        return;
                    }
                }
                role = ROLE.SLAVE;
                Log.debug("role = SLAVE. ");
                master.stop();
            }
        } catch (Exception e) {
            // TODO define more suitable Exception (i.e. SheepdogException)
            e.printStackTrace();
        }
    }

}
