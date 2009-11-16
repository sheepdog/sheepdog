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

import net.osrg.sheepdog.NodeList;

public class ObjectRequest extends Request {

    static final long serialVersionUID = 8293249265237308968L;
    public ObjectRequest() {
        super();
    }

    public ObjectRequest(Request req) {
        setProtoVersion(req.getProtoVersion());
        setOpcode(req.getOpcode());
        setFlags(req.getFlags());
        setEpoch(req.getEpoch());
        setId(req.getId());
        setDataLength(req.getDataLength());
        ByteBuffer buf = req.getRemaining();
        oid = buf.getLong();
        cowOid = buf.getLong();
        copies = buf.getInt();
        objVer = buf.getInt();
        offset = buf.getLong();
    }

    @Override
    public ByteBuffer toBuffer() {
        ByteBuffer buf;
        if ((getFlags() & 1) == 1) {
            buf = ByteBuffer.allocate(HEADER_SIZE + getDataLength());
        } else {
            buf = ByteBuffer.allocate(HEADER_SIZE);
        }
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.put(getProtoVersion());
        buf.put(getOpcode().getValue());
        buf.putShort(getFlags());
        buf.putInt(getEpoch());
        buf.putInt(getId());
        buf.putInt(getDataLength());

        buf.putLong(oid);
        buf.putLong(cowOid);
        buf.putInt(copies);
        buf.putInt(objVer);
        buf.putLong(offset);
        if ((getFlags() & 1) == 1) {
            buf.put(getData());
        }
        buf.flip();
        return buf;
   }

    public long getOid() {
        return oid;
    }
    public long getCowOid() {
        return cowOid;
    }
    public int getCopies() {
        return copies;
    }
    public int getObjVer() {
        return objVer;
    }
    public long getOffset() {
        return offset;
    }

    private NodeList nodeList;
    private NodeList maskNodeList;

    public NodeList getNodeList() {
        return nodeList;
    }

    public void setNodeList(NodeList nodeList) {
        this.nodeList = nodeList;
    }

    public NodeList getMaskNodeList() {
        return maskNodeList;
    }

    public void setMaskNodeList(NodeList maskNodeList) {
        this.maskNodeList = maskNodeList;
    }

    private long oid;

    public void setOid(long oid) {
        this.oid = oid;
    }

    private long cowOid;
    private int copies;

    public void setCopies(int copies) {
        this.copies = copies;
    }

    private int objVer;
    private long offset;
}
