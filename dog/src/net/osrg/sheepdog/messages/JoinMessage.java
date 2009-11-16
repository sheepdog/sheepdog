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

package net.osrg.sheepdog.messages;

import java.util.TreeSet;

import net.osrg.sheepdog.Log;
import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.NodeList;
import net.osrg.sheepdog.NodeLogOperator;
import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.SheepdogException;
import net.osrg.sheepdog.headers.Response;

public class JoinMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 6864895435522827559L;
    private NodeList startupNodeList;
    private boolean startSheepdog;
    private long ctime;

    public JoinMessage(Node from, int connectionId, NodeList startupNodeList, long ctime, boolean startSheepdog) {
        super(from, connectionId);
        this.startupNodeList = startupNodeList;
        this.ctime = ctime;
        this.startSheepdog = startSheepdog;
    }

    @Override
    public Response reply(ClusterInformation ci) {
        // TODO implement me
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void updateSuperObject(ClusterInformation ci) {
        NodeList latestStartupList = startupNodeList;
        if (startupNodeList == null
                || ci.getStartupNodeList() != null
                && ci.getStartupNodeList().getEpoch() < startupNodeList.getEpoch()) {
            latestStartupList = ci.getStartupNodeList();
        }

        NodeList nodeList = ci.nodeList;
        int epoch = nodeList.getEpoch();
        // TODO implement NodeList.clone
        NodeList nextNodeList = NodeList.fromLogData(nodeList
                .toLogData());
        nextNodeList.getNodeSet().add(getFrom());
        if (!ci.isInitialized()
                && nextNodeList.containsAll(latestStartupList)) {
            NodeList oldNodeList = latestStartupList;
            NodeList newNodeList = nextNodeList;
            TreeSet<Node> oldSet, newSet;
            oldSet = (TreeSet<Node>) oldNodeList.getNodeSet();
            newSet = (TreeSet<Node>) newNodeList.getNodeSet();
            if (!newSet.equals(oldSet)) {
                epoch = oldNodeList.getEpoch();
                NodeLogOperator operator = new NodeLogOperator();
                int result = operator.updateNodeLog(0, epoch + 1, oldSet, newSet);
                setResult(result);
            }
            startSheepdog = true;
        } else {
            TreeSet<Node> oldSet, newSet;
            oldSet = (TreeSet<Node>) nodeList.getNodeSet();
            newSet = (TreeSet<Node>) oldSet.clone();
            newSet.add(getFrom());
            if (ci.isInitialized()) {
                NodeLogOperator operator = new NodeLogOperator();
                int result = operator.updateNodeLog(epoch, epoch + 1, oldSet, newSet);
                setResult(result);
            }
            startSheepdog = false;
        }
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
        Log.debug(getFrom().toString());
        if (startupNodeList != null) {
            if (ci.getStartupNodeList() == null || ci.getCtime() < ctime
                    || ci.getCtime() == ctime && ci.getStartupNodeList().getEpoch() < startupNodeList
                            .getEpoch()) {
                ci.addStartupNodeList(startupNodeList, ctime);
            }
        }
        if (getResult() == SheepdogException.SUCCESS) {
            ci.join(getFrom());
        }
        if (startSheepdog) {
            if (ci.nodeList.getNodeSet().equals(startupNodeList.getNodeSet())) {
                ci.nodeList.setEpoch(startupNodeList.getEpoch());
            } else {
                ci.nodeList.setEpoch(startupNodeList.getEpoch() + 1);
            }
            ci.setInitialized(true);
        }
    }
}
