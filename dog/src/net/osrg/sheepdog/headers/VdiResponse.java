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

public class VdiResponse extends Response {

    public VdiResponse(Request req, byte op, ByteBuffer data, int res) {
        super(req, op, data, res);
    }

    public VdiResponse() {
        super();
    }

    public int getRsvd() {
        return rsvd;
    }

    public void setRsvd(int rsvd) {
        this.rsvd = rsvd;
    }

    public long getOid() {
        return oid;
    }

    public void setOid(long oid) {
        this.oid = oid;
    }

    public void setVdiEpoch(int vdiEpoch) {
        this.vdiEpoch = vdiEpoch;
    }

    public int getVdiEpoch() {
        return vdiEpoch;
    }

    @Override
    public ByteBuffer getHeader() {
        ByteBuffer buf = ByteBuffer.allocate(HEADER_SIZE + getData().limit());
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(getProtoVersion());
        buf.put(getOpcode().getValue());
        buf.putShort(getFlags());
        buf.putInt(getEpoch());
        buf.putInt(getId());
        buf.putInt(getDataLength());
        buf.putInt(getResult());
        buf.putInt(rsvd);
        buf.putLong(oid);
        buf.putInt(vdiEpoch);
        for (int i = 0; i < 3; i++) {
            buf.putInt(0);
        }
        buf.flip();
        return buf;
    }

    private int rsvd;
    private long oid;
    private int vdiEpoch;
}
