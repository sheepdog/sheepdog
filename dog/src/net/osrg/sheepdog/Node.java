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
import java.util.Arrays;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Node implements Serializable, Comparable<Node> {

    /**
     *
     */
    public static final int NODE_SIZE = 20;

    private static final long serialVersionUID = 346960641984069648L;
    private byte[] id;
    private InetAddress address;
    private int sheepPort;
    private int dogPort;

    public Node(long oid) {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA1");
            ByteBuffer buf = ByteBuffer.allocate(8);
            buf.order(ByteOrder.LITTLE_ENDIAN);
            buf.putLong(oid);
            buf.flip();
            md.update(buf.array());
            this.id = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            this.id = null;
        }
    }

    public Node(String h, int dPort, int sPort) throws UnknownHostException {
        this(InetAddress.getByName(h), dPort, sPort);
    }

    public Node(InetAddress address, int dPort, int sPort) {
        this.address = address;
        this.dogPort = dPort;
        this.sheepPort = sPort;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(address.getAddress());
            md.update((byte) dPort);
            md.update((byte) (dPort >> 8));
            id = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            id = null;
        }
    }

    public byte[] getId() {
        return id;
    }

    public InetAddress getInetAddress() {
        return address;
    }

    public int getDogPort() {
        return dogPort;
    }

    public int getSheepPort() {
        return sheepPort;
    }

    public ByteBuffer toBuffer() {
        ByteBuffer buf = ByteBuffer.allocate(NODE_SIZE);
        buf.order(ByteOrder.LITTLE_ENDIAN);

        byte[] addr = address.getAddress();
        if (addr.length == 4) { // IPv4
            for (int i = 0; i < 12; i++) {
                buf.put((byte) 0);
            }
            buf.put(addr);
        } else if (addr.length == 16) { // IPv6
            buf.put(addr);
        } else {
            Log.error("Unknown protocol");
            for (int i = 0; i < 16; i++) {
                buf.put((byte) 0);
            }
        }

        buf.putShort((short) sheepPort);
        buf.putShort((short) dogPort);
        buf.flip();
        return buf;
    }

    public static Node fromBuffer(ByteBuffer buf) {
        try {
            byte [] addr = new byte[16];
            buf.get(addr, 0, 12);
            if (Arrays.equals(addr, new byte[16])) {
                // IPv4
                addr = new byte[4];
                buf.get(addr);
            } else {
                // IPv6
                buf.get(addr, 12, 4);
            }
            InetAddress address = InetAddress.getByAddress(addr);
            int sheepPort = buf.getShort();
            int dogPort = buf.getShort();
            return new Node(address, dogPort, sheepPort);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public String toString() {
        String hostname = address.getHostAddress();
        return hostname + ":" + dogPort + ":" + sheepPort;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Node)) {
            return false;
        }
        Node node = (Node) o;
        if (node == null) {
            return false;
        }
        return (compareTo(node) == 0);
    }

    @Override
    public int hashCode() {
        if (id == null) {
            return 0;
        }
        return id.hashCode();
    }

    @Override
    public int compareTo(Node arg0) {
        byte[] as = this.id;
        byte[] bs = arg0.id;

        for (int i = 0; i < 20; i++) {
            int a = as[i];
            int b = bs[i];
            if (a < 0) {
                a += 256;
            }
            if (b < 0) {
                b += 256;
            }
            if (a > b) {
                return 1;
            } else if (a < b) {
                return -1;
            }
        }
        return 0;
    }
}
