from sheepdog_test import *
import time


def test_create_vdi():
    """Create many VDIs at the same time."""

    nr_vdis = 5
    sdog = Sheepdog()

    for n in sdog.nodes:
        n.start()
        n.wait()

    p = sdog.format()
    p.wait()

    # create VDIs at the same time
    vdis = [sdog.create_vdi(str(i), 4 * 1024 ** 3) for i in range(nr_vdis)]
    for v in vdis:
        v.wait()

    time.sleep(1)
    p = n.run_collie('vdi list -r')
    (out, _) = p.communicate()
    assert len(out.splitlines()) == nr_vdis
