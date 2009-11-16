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
import net.osrg.sheepdog.headers.Response;

public class LeaveMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = -9205012528477623953L;
    private Node targetNode;

    public LeaveMessage(Node from, int connectionId, Node targetNode) {
        super(from, connectionId);
        this.targetNode = targetNode;
    }

    @Override
    public Response reply(ClusterInformation ci) {
        // TODO implement me
        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void updateSuperObject(ClusterInformation ci) {
        NodeList nodeList = ci.nodeList;
        int epoch = nodeList.getEpoch();
        TreeSet<Node> oldSet, newSet;
        oldSet = (TreeSet<Node>) nodeList.getNodeSet();
        newSet = (TreeSet<Node>) oldSet.clone();
        newSet.remove(targetNode);
        NodeLogOperator operator = new NodeLogOperator();
        int result = operator.updateNodeLog(epoch, epoch + 1, oldSet, newSet);
        setResult(result);
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
        Log.debug("remove node " + targetNode + " from mgroups");
        try {
            ci.leave(targetNode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Node getTargetNode() {
        return targetNode;
    }
}
