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

public class NodeRequest extends Request {

    private static final long serialVersionUID = -5744819084363637266L;

    public NodeRequest(ByteBuffer buf) {
        super(buf);
        requestEpoch = buf.getInt();
    }

    public NodeRequest(Request req) {
        setProtoVersion(req.getProtoVersion());
        setOpcode(req.getOpcode());
        setFlags(req.getFlags());
        setEpoch(req.getEpoch());
        setId(req.getId());
        setDataLength(req.getDataLength());
        setRemaining(req.getRemaining());
        ByteBuffer buf = req.getRemaining();
        requestEpoch = buf.getInt();
        setData(req.getData());
    }

    public int getRequestEpoch() {
        return requestEpoch;
    }

    public void setRequestEpoch(int requestEpoch) {
        this.requestEpoch = requestEpoch;
    }

    private int requestEpoch;
}
