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

package net.osrg.sheepdog.headers;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class NodeResponse extends Response {

    public NodeResponse(Request req, byte op, ByteBuffer data, int res) {
        super(req, op, data, res);
    }

    @Override
    public ByteBuffer getHeader() {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        super.fillHeader(buf);
        buf.putInt(nrNodes);
        buf.putInt(localIdx);
        buf.putInt(masterIdx);
        for (int i = 0; i < 4; i++) {
            buf.putInt(0);
        }
        buf.flip();
        return buf;
    }

    public int getNrNodes() {
        return nrNodes;
    }

    public void setNrNodes(int nrNodes) {
        this.nrNodes = nrNodes;
    }

    public int getLocalIdx() {
        return localIdx;
    }

    public void setLocalIdx(int localIdx) {
        this.localIdx = localIdx;
    }

    public int getMasterIdx() {
        return masterIdx;
    }

    public void setMasterIdx(int masterIdx) {
        this.masterIdx = masterIdx;
    }

    private int nrNodes;
    private int localIdx;
    private int masterIdx;
}
