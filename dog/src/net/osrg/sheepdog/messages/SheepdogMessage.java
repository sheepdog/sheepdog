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

import java.io.Serializable;

import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.headers.Response;

public abstract class SheepdogMessage implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -8802080283453471007L;

    private final Node from;
    private final int messageId;
    private boolean flushed;
    private int result;

    public SheepdogMessage(Node from, int messageId) {
        this.from = from;
        this.messageId = messageId;
        this.flushed = false;
    }

    public Node getFrom() {
        return from;
    }

    public int getMessageId() {
        return messageId;
    }

    public void setResult(int result) {
        this.result = result;
    }

    public int getResult() {
        return result;
    }

    public void setFlushed(boolean flushed) {
        this.flushed = flushed;
    }

    public boolean isFlushed() {
        return flushed;
    }

    public abstract void updateSuperObject(ClusterInformation ci);

    public abstract void updateClusterInfo(ClusterInformation ci);

    public abstract Response reply(ClusterInformation ci);
}
