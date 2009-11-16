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

import org.jgroups.Address;

import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.headers.Response;

public class RequestClusterInfoMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = -3798212834994474954L;
    private ClusterInformation clusterInfo;
    private Address addr;

    public RequestClusterInfoMessage(Node from, int connectionId, Address localAddress) {
        super(from, connectionId);
        this.addr = localAddress;
    }

    public RequestClusterInfoMessage(Node from, int connectionId,
            Address addr, ClusterInformation clusterInfo) {
        super(from, connectionId);
        this.addr = addr;
        this.clusterInfo = clusterInfo;
    }

    @Override
    public Response reply(ClusterInformation ci) {
        return null;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
        clusterInfo = ci;
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
        ci.merge(clusterInfo);
    }

    public ClusterInformation getClusterInfo() {
        return clusterInfo;
    }

    public Address getAddr() {
        return addr;
    }
}
