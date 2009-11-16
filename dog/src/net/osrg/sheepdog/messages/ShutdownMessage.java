package net.osrg.sheepdog.messages;

import net.osrg.sheepdog.ClusterInformation;
import net.osrg.sheepdog.Node;
import net.osrg.sheepdog.SheepdogException;
import net.osrg.sheepdog.headers.Response;

public class ShutdownMessage extends SheepdogMessage {

    /**
     *
     */
    private static final long serialVersionUID = -4309229228671192242L;

    public ShutdownMessage(Node from, int messageId) {
        super(from, messageId);
        setResult(SheepdogException.SUCCESS);
    }

    @Override
    public Response reply(ClusterInformation ci) {
        Response rsp = new Response();
        rsp.setResult(getResult());
        return rsp;
    }

    @Override
    public void updateClusterInfo(ClusterInformation ci) {
        ci.setShutdown(true);
    }

    @Override
    public void updateSuperObject(ClusterInformation ci) {
        ci.setShutdown(true);
    }

}
