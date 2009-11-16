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

import java.nio.ByteBuffer;

import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.headers.Response;

public class GetVmListMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 8659440019009075416L;

    public GetVmListMessage(Node from, int connectionId) {
        super(from, connectionId);
    }

    @Override
    public Response reply(ClusterInformation ci) {
        Response rsp = new Response();
        ByteBuffer buf = ci.encodeLockTbl();
        rsp.setData(buf);
        rsp.setDataLength(buf.remaining());
        if (buf.remaining() > 0) {
            rsp.setFlags((short) 1);
        }
        return rsp;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
    }
}
