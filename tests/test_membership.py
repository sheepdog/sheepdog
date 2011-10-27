from sheepdog_test import *
import time


def test_simultaneous_startup():
    """Start multiple sheep daemons at the same time"""

    nr_nodes = 8
    sdog = Sheepdog(nr_nodes)

    # start 8 daemons at the same time
    for n in sdog.nodes:
        n.start()

    for n in sdog.nodes:
        n.wait()

    for n in sdog.nodes:
        p = n.run_collie('node list -r')
        (out, _) = p.communicate()
        assert len(out.splitlines()) == nr_nodes


def test_mastership():
    """Check master transfer."""

    nr_nodes = 3
    sdog = Sheepdog(nr_nodes)

    sdog.nodes[0].start()
    sdog.nodes[0].wait()

    # start Sheepdog with one node
    p = sdog.format()
    p.wait()

    sdog.nodes[1].start()
    sdog.nodes[1].wait()

    # give mastership to nodes[1]
    sdog.nodes[0].stop()

    sdog.nodes[2].start()
    sdog.nodes[2].wait()

    # give mastership to nodes[2]
    sdog.nodes[1].stop()

    # FIXME: wait until nodes[2] updates membership
    time.sleep(0.5)
    sdog.nodes[2].stop()

    for n in sdog.nodes:
        n.start()
        n.wait()

    # only nodes[2] should be in the cluster
    p = sdog.nodes[2].run_collie('node list -r')
    (out, _) = p.communicate()
    assert len(out.splitlines()) == 1

    sdog.nodes[0].start()
    sdog.nodes[0].wait()
    sdog.nodes[1].start()
    sdog.nodes[1].wait()

    for n in sdog.nodes:
        p = n.run_collie('node list -r')
        (out, _) = p.communicate()
        assert len(out.splitlines()) == nr_nodes
