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

package net.osrg.sheepdog;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum OpCode implements Serializable {
    OP_UNKNOWN((byte) 0x00),

    OP_CREATE_AND_WRITE_OBJ((byte) 0x01),
    OP_REMOVE_OBJ((byte) 0x02),
    OP_READ_OBJ((byte) 0x03),
    OP_WRITE_OBJ((byte) 0x04),
    OP_SYNC_OBJ((byte) 0x05),
    OP_APPEND_OBJ((byte) 0x06),

    OP_NEW_VDI((byte) 0x11),
    OP_DEL_VDI((byte) 0x12),
    OP_GET_NODE_NAME((byte) 0x13),
    OP_GET_MASTER_TID((byte) 0x14),
    OP_LOCK_VDI((byte) 0x16),
    OP_RELEASE_VDI((byte) 0x17),
    OP_GET_VDI_INFO((byte) 0x18),
    OP_GET_NODE_LIST((byte) 0x19),
    OP_GET_VM_LIST((byte) 0x20),
    OP_MAKE_FS((byte) 0x21),
    OP_UPDATE_EPOCH((byte) 0x22),
    OP_GET_EPOCH((byte) 0x23),
    OP_SHUTDOWN((byte) 0x24),

    OP_JOIN((byte) 0x81),
    OP_LEAVE((byte) 0x82),
    OP_NOP((byte) 0x86),
    OP_REMOVE_NODE((byte) 0x87),
    OP_UPDATE_NODELIST((byte) 0x88);

    private OpCode(byte v) {
        value = v;
    }

    private byte value;

    private static final Map<Byte, OpCode> REVERSE_DICTIONARY;
    static {
        Map<Byte, OpCode> map = new HashMap<Byte, OpCode>();
        for (OpCode elem : OpCode.values()) {
            map.put(elem.value, elem);
        }
        REVERSE_DICTIONARY = Collections.unmodifiableMap(map);
    }

    public byte getValue() {
        return value;
    }

    public static OpCode fromValue(byte v) {
        return REVERSE_DICTIONARY.get(v);
    }
}
