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

import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.NodeLogOperator;
import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.headers.Response;

public class MakeFsMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 8251849116343377179L;
    private int copies;

    public MakeFsMessage(Node from, int copies, int connectionId) {
        super(from, connectionId);
        this.copies = copies;
    }

    @Override
    public Response reply(ClusterInformation ci) {
        Response rsp = new Response();
        rsp.setResult(getResult());
        return rsp;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
        int epoch = ci.nodeList.getEpoch();
        if (!ci.isInitialized()) {
            epoch = 0;
        }
        TreeSet<Node> set;
        set = (TreeSet<Node>) ci.nodeList.getNodeSet();

        NodeLogOperator operator = new NodeLogOperator();
        int result = operator.mkfs(epoch, set, copies);
        setResult(result);
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
        if (!ci.isInitialized()) {
            ci.setInitialized(true);
            ci.nodeList.setEpoch(1);
        } else {
            ci.nodeList.setEpoch(ci.nodeList.getEpoch() + 1);
        }
    }
}
