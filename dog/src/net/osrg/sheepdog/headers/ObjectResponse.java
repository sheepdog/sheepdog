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

import net.osrg.sheepdog.OpCode;

public class ObjectResponse extends Response {

    public ObjectResponse(ByteBuffer buf) {
        setProtoVersion(buf.get());
        setOpcode(OpCode.fromValue(buf.get()));
        setFlags(buf.getShort());
        setEpoch(buf.getInt());
        setId(buf.getInt());
        setDataLength(buf.getInt());
        setResult(buf.getInt());
        objVer = buf.getInt();
        copies = buf.getInt();
        for (int i = 0; i < 5; i++) {
            buf.getInt();
        }
        setData(buf.slice());
    }

    public ObjectResponse(Request req, byte op, ByteBuffer data, int res) {
        super(req, op, data, res);
    }

    public int getObjVer() {
        return objVer;
    }

    public int getCopies() {
        return copies;
    }

    private int objVer;
    private int copies;
}
