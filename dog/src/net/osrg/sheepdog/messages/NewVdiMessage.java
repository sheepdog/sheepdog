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
import net.osrg.sheepdog.headers.VdiResponse;

public class NewVdiMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = 1135149371238643248L;
    private String vdiName;
    private long baseOid;
    private long tag;
    private long vdiSize;
    private short flags;
    private long oid;
    private int vdiEpoch;

    public void setFlags(short flags) {
        this.flags = flags;
    }

    public void setOid(long oid) {
        this.oid = oid;
    }

    public void setVdiEpoch(int vdiEpoch) {
        this.vdiEpoch = vdiEpoch;
    }

    public NewVdiMessage(Node from, String vdiName, long baseOid,
            long tag, long vdiSize, short flags, int connectionId) {
        super(from, connectionId);
        this.vdiName = vdiName;
        this.baseOid = baseOid;
        this.tag = tag;
        this.vdiSize = vdiSize;
        this.flags = flags;
        setResult(SheepdogException.SUCCESS);
    }

    @Override
    public Response reply(ClusterInformation ci) {
        VdiResponse vdiRsp = new VdiResponse();
        vdiRsp.setOid(oid);
        vdiRsp.setFlags(flags);
        vdiRsp.setVdiEpoch(vdiEpoch);
        vdiRsp.setResult(getResult());
        return vdiRsp;
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
        VdiOperator vdiOp = new VdiOperator(baseOid, tag, vdiSize, flags, vdiName, ci.getNodeList(),
                OpCode.OP_NEW_VDI, this);
        vdiOp.doOperation();
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
    }
}
