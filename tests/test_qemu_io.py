from sheepdog_test import *
from qemu_io_testcases import *
import time

def test_io():

    cmd = ["qemu-io"]
    sdog = Sheepdog()

    for n in sdog.nodes:
        n.start()
        n.wait()

    p = sdog.format()
    p.wait()

    for i in io_cases:
        vdi = sdog.create_vdi(str(i), size_cases[i])
        vdi.wait()
        time.sleep(1)
        vm = n.create_vm(vdi)
        for j in io_cases[i]:
            (out, err) = vm.test_io(cmd, j[0] + "\n")
            assert out == j[1]
            time.sleep(1)
        print "Pass"
        vdi.destroy()
        vdi.wait()

    p = sdog.format()
    p.wait()
    for n in sdog.nodes:
        n.stop()

def test_aio():

    cmd = ["qemu-io"]
    sdog = Sheepdog()

    for n in sdog.nodes:
        n.start()
        n.wait()

    p = sdog.format()
    p.wait()

    for i in aio_cases:
        vdi = sdog.create_vdi(str(i), size_cases[i])
        vdi.wait()
        time.sleep(1)
        vm = n.create_vm(vdi)
        for j in aio_cases[i]:
            (out, err) = vm.test_io(cmd, j[0] + "\n", async=True)
            assert out == j[1]
            time.sleep(1)
        print "Pass"
        vdi.destroy()
        vdi.wait()

def test_growable_io():

    cmd = ["qemu-io", "-g"]
    sdog = Sheepdog()

    for n in sdog.nodes:
        n.start()
        n.wait()

    p = sdog.format()
    p.wait()

    for i in io_cases_g:
        vdi = sdog.create_vdi(str(i), size_cases[i])
        vdi.wait()
        time.sleep(1)
        vm = n.create_vm(vdi)
        for j in io_cases_g[i]:
            (out, err) = vm.test_io(cmd, j[0] + "\n")
            assert out == j[1]
            time.sleep(1)
        print "Pass"
        vdi.destroy()
        vdi.wait()
