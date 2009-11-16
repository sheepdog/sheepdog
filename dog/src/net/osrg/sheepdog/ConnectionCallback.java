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

import java.io.IOException;
import java.nio.channels.SelectionKey;

import net.osrg.sheepdog.headers.Request;

public interface ConnectionCallback {
    void rxDone(SelectionKey key, OpCode op, Request req, int uid)
            throws IOException;
}
