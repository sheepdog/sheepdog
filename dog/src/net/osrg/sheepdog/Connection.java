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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

import net.osrg.sheepdog.headers.Request;
import net.osrg.sheepdog.headers.Response;

public class Connection {

    private SelectionKey key;
    private STATE rxState;
    private Request request;
    private ByteBuffer rxHeader;
    private ByteBuffer rxData;
    private STATE txState;
    private Response response;
    private ByteBuffer txHeader;
    private ByteBuffer txData;
    private ConnectionCallback callback;

    private int uid;

    enum STATE {
        IO_HEADER, IO_DATA, IO_END, IO_CLOSE
    }

    public Connection(SelectionKey k, int u, ConnectionCallback f) {
        key = k;
        uid = u;
        callback = f;
        request = null;
        response = null;
        rxState = STATE.IO_HEADER;
        rxHeader = ByteBuffer.allocate(Request.HEADER_SIZE);
        rxHeader.order(ByteOrder.LITTLE_ENDIAN);
        rxData = null;
        txState = STATE.IO_HEADER;
        response = null;
        txHeader = null;
        txData = null;
    }

    public void setRxOff() {
        int ops = key.interestOps();
        key.interestOps(ops & ~SelectionKey.OP_READ);
    }

    public void setRxOn() {
        rxState = STATE.IO_HEADER;
        rxHeader = ByteBuffer.allocate(Request.HEADER_SIZE);
        rxHeader.order(ByteOrder.LITTLE_ENDIAN);
        rxData = null;

        int ops = key.interestOps();
        key.interestOps(ops | SelectionKey.OP_READ);
    }

    public void setTxOff() {
        int ops = key.interestOps();
        key.interestOps(ops & ~SelectionKey.OP_WRITE);
    }

    public void setTxOn(ByteBuffer data) {
        setTxOn(OpCode.OP_UNKNOWN, data);
    }

    public void setTxOn(OpCode opcode, ByteBuffer data) {
        setTxOn(new Response(request, opcode.getValue(), data, 0));
    }

    public void setTxOn(Response resp) {
        txState = STATE.IO_HEADER;
        this.response = resp;
        txHeader = resp.getHeader();
        txData = resp.getData();

        int ops = key.interestOps();
        key.interestOps(ops | SelectionKey.OP_WRITE);
    }

    public boolean isConnDead() {
        return rxState == STATE.IO_CLOSE || txState == STATE.IO_CLOSE;
    }

    private void rx(ByteBuffer buf, STATE nextState) throws IOException {
        ReadableByteChannel sc = (ReadableByteChannel) key.channel();
        if (sc.read(buf) == -1) {
            Log.debug("The channel has reached end-of-stream. ");
            // TODO remove from HashMap
            throw new IOException("The channel has reached end-of-stream. ");
        }
        if (!buf.hasRemaining()) {
            rxState = nextState;
        }
    }

    private void tx(ByteBuffer buf, STATE nextState) throws IOException {
        SocketChannel sc = (SocketChannel) key.channel();
        sc.write(buf);
        if (!buf.hasRemaining()) {
            txState = nextState;
        }
    }

    public void rxHandler() {
        try {
            switch (rxState) {
            case IO_HEADER:
                rx(rxHeader, STATE.IO_DATA);
                if (rxHeader.hasRemaining()) {
                    break;
                }
                rxHeader.position(0);
                request = new Request(rxHeader);
                if (request.getDataLength() == 0 || request.getFlags() != 1) {
                    rxState = STATE.IO_END;
                    break;
                }
                rxData = ByteBuffer.allocate(request.getDataLength());
                rxData.order(ByteOrder.LITTLE_ENDIAN);
                break;
            case IO_DATA:
                rx(rxData, STATE.IO_END);
                break;
            default:
                Log.error("BUG: unknown state " + rxState);
                break;
            }
        } catch (IOException e) {
            rxState = STATE.IO_CLOSE;
        }

        try {
            if (rxState == STATE.IO_END) {
                if (request.getDataLength() != 0 && request.getFlags() == 1) {
                    rxData.position(0);
                    request.setData(rxData);
                }
                setRxOff();
                callback.rxDone(key, request.getOpcode(), request, uid);
            } else if (rxState == STATE.IO_CLOSE) {
                key.channel().close();
                key.cancel();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void txHandler() {
        try {
            switch (txState) {
            case IO_HEADER:
                tx(txHeader, STATE.IO_DATA);
                if (txHeader.hasRemaining()) {
                    break;
                }
                txHeader.position(0);
                if (response.getDataLength() == 0) {
                    txState = STATE.IO_END;
                    break;
                }
                break;
            case IO_DATA:
                tx(txData, STATE.IO_END);
                break;
            default:
                Log.error("BUG: unknown state " + txState);
                break;
            }
        } catch (IOException e) {
            txState = STATE.IO_CLOSE;
        }
        try {
            if (txState == STATE.IO_END) {
                setTxOff();
                setRxOn();
            } else if (txState == STATE.IO_CLOSE) {
                key.channel().close();
                key.cancel();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
