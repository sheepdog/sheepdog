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

import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.OpCode;
import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.SheepdogException;
import net.osrg.sheepdog.VdiOperator;
import net.osrg.sheepdog.headers.Response;

public class ReleaseVdiMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 4693006050073828817L;
    private String vdiName;

    public ReleaseVdiMessage(Node from, int connectionId, String vdiName) {
        super(from, connectionId);
        this.vdiName = vdiName;
    }

    @Override
    public Response reply(ClusterInformation ci) {
        Response rsp = new Response();
        rsp.setResult(getResult());
        return rsp;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
        OpCode op; // TODO remove this
        op = OpCode.OP_GET_VDI_INFO;
        VdiOperator vdiOp = new VdiOperator((long) 0, (long) -1, (long) 0, (short) 0, vdiName, ci.getNodeList(), op, this);
        vdiOp.doOperation();
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
        int ret = -1;
        if (getResult() == SheepdogException.SUCCESS) {
            try {
                ret = ci.unlock(vdiName);
            } catch (Exception e) {
                e.printStackTrace();
            }
            // TODO merge to Exception
            if (ret < 0) {
                setResult(SheepdogException.VDI_NOT_LOCKED);
            }
        }
    }

}
