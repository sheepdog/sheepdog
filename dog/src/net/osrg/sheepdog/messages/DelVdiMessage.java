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

import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.headers.Response;

public class DelVdiMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 4712886975118264261L;

    public DelVdiMessage(Node from, int connectionId) {
        super(from, connectionId);
    }

    @Override
    public Response reply(ClusterInformation ci) {
        return null;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
    }
}
