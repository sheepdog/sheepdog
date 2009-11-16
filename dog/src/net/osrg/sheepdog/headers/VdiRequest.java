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

public class VdiRequest extends Request {

    static final long serialVersionUID = 6790105034454796955L;
    public VdiRequest(ByteBuffer buf) {
        super(buf);
        baseOid = buf.getLong();
        tag = buf.getLong();
        vdiSize = buf.getLong();
    }

    public VdiRequest(Request req) {
        setProtoVersion(req.getProtoVersion());
        setOpcode(req.getOpcode());
        setFlags(req.getFlags());
        setEpoch(req.getEpoch());
        setId(req.getId());
        setDataLength(req.getDataLength());
        ByteBuffer buf = req.getRemaining();
        baseOid = buf.getLong();
        tag = buf.getLong();
        vdiSize = buf.getLong();
        setData(req.getData());
    }

    public long getBaseOid() {
        return baseOid;
    }

    public void setBaseOid(long baseOid) {
        this.baseOid = baseOid;
    }

    public long getTag() {
        return tag;
    }

    public void setTag(long tag) {
        this.tag = tag;
    }

    public long getVdiSize() {
        return vdiSize;
    }

    public void setVdiSize(long vdiSize) {
        this.vdiSize = vdiSize;
    }

    private long baseOid;
    private long tag;
    private long vdiSize;

}
