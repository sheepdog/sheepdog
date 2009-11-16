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
import net.osrg.sheepdog.NodeList;
import net.osrg.sheepdog.NodeLogOperator;
import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.SheepdogException;
import net.osrg.sheepdog.headers.Response;

public class UpdateEpochMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 8873948460930455590L;
    private long oid;
    private int vdiEpoch;

    public UpdateEpochMessage(Node from, long oid, int vdiEpoch,
            int connectionId) {
        super(from, connectionId);
        this.oid = oid;
        this.vdiEpoch = vdiEpoch;
        setResult(SheepdogException.SUCCESS);
    }

    @Override
    public Response reply(ClusterInformation ci) {
        Response rsp = new Response();
        rsp.setResult(getResult());
        return rsp;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
        NodeList nodeList = ci.getNodeList();
        int epoch = nodeList.getEpoch();
        TreeSet<Node> nodeSet = (TreeSet<Node>) nodeList.getNodeSet();
        NodeLogOperator operator =
            new NodeLogOperator();
        int result = operator.updateEpoch(epoch, nodeSet, oid, vdiEpoch);
        setResult(result);
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
    }

}
