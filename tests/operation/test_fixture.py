import unittest

import hashlib
import os
import os.path
import subprocess
import tempfile
import time

import fixture


class FileSystemTest(unittest.TestCase):

    def setUp(self):
        self._path = None

    def tearDown(self):
        try:
            if self._path is not None:
                os.unlink(self._path)
        except:
            pass

    def testMakeZeroFile0(self):
        self._path = fixture.MakeZeroFile(0)
        self.assertIsNotNone(self._path)
        self.assertEquals(0, os.stat(self._path).st_size)

    def testMakeZeroFile1(self):
        self._path = fixture.MakeZeroFile(1)
        self.assertIsNotNone(self._path)
        self.assertEquals(1, os.stat(self._path).st_size)

    def testMakeZeroFile1G(self):
        self._path = fixture.MakeZeroFile(1024**3)
        self.assertIsNotNone(self._path)
        self.assertEquals(1024**3, os.stat(self._path).st_size)

    def testMakeXFS(self):
        self._path = fixture.MakeZeroFile(1024**3)
        self.assertIsNotNone(self._path)
        self.assertTrue(fixture.MakeXFS(self._path))


class StoreTest(unittest.TestCase):

    def setUp(self):
        self._img = None
        self._mnt = None

    def tearDown(self):
        try:
            if self._mnt is not None:
                os.rmdir(self._mnt)
            if self._img is not None:
                os.unlink(self._img)
        except:
            pass

    def testMountAndUnmount(self):
        self._img = fixture.MakeZeroFile(1024**3)
        self.assertIsNotNone(self._img)
        self.assertTrue(fixture.MakeXFS(self._img))
        self._mnt = tempfile.mkdtemp()
        self.assertIsNotNone(self._mnt)
        self.assertTrue(fixture.MountLoopbackXFS(self._img, self._mnt))
        self.assertTrue(fixture.UnmountFS(self._mnt))

    def testCreateAndDestroy(self):
        (self._img, self._mnt) = fixture.CreateSheepdogDisk(1024**3)
        self.assertIsNotNone(self._img)
        self.assertIsNotNone(self._mnt)
        self.assertTrue(os.path.isfile(self._img))
        self.assertTrue(os.path.isdir(self._mnt))
        self.assertEquals(1024**3, os.stat(self._img).st_size)
        self.assertTrue(fixture.DestroySheepdogDisk(self._img, self._mnt))
        (self._img, self._mnt) = (None, None)


class NodeAndClusterTest(unittest.TestCase):

    def setUp(self):
        self._disks = []

    def tearDown(self):
        for t in self._disks:
            fixture.DestroySheepdogDisk(t[0], t[1])

    def _SheepExists(self):
        try:
          subprocess.check_output(["sudo", "pgrep", "sheep"])
          return True
        except subprocess.CalledProcessError as e:
          if e.returncode == 1:
            return False
          raise

    def testStartAndKillNode(self):
        self.assertFalse(self._SheepExists())
        t = fixture.CreateSheepdogDisk(1024**3)
        self.assertIsNotNone(t)
        self.assertTrue(fixture.StartSheep(t[1]))
        self._disks.append(t)
        time.sleep(2)
        self.assertTrue(self._SheepExists())
        self.assertTrue(fixture.KillLocalNode(7000))
        time.sleep(2)
        self.assertFalse(self._SheepExists())

    def testFormatAndShutdownCluster(self):
        self.assertFalse(self._SheepExists())
        for i in range(3):
            t = fixture.CreateSheepdogDisk(1024**3)
            p = i + 7000
            z = i + 1
            self.assertTrue(fixture.StartSheep(t[1], port=p, zone=z))
            self._disks.append(t)
        time.sleep(2)
        self.assertTrue(self._SheepExists())
        self.assertTrue(fixture.ForceFormatCluster(3))
        self.assertTrue(fixture.ShutdownCluster())
        time.sleep(2)
        self.assertFalse(self._SheepExists())


class VDITest(unittest.TestCase):

    def setUp(self):
        self._disks = []
        for i in range(3):
            t = fixture.CreateSheepdogDisk(1024**3)
            p = i + 7000
            z = i + 1
            fixture.StartSheep(t[1], port=p, zone=z)
            self._disks.append(t)
        time.sleep(2)
        fixture.ForceFormatCluster(2)

    def tearDown(self):
        fixture.ShutdownCluster()
        time.sleep(2)
        for t in self._disks:
            fixture.DestroySheepdogDisk(t[0], t[1])

    def testCreateAndDeleteVDI(self):
        self.assertEquals(0, len(fixture.ListVDI()))
        self.assertTrue(fixture.CreateVDI("alpha", 128 * (1024**2)))
        self.assertTrue(fixture.CreateVDI("bravo", 192 * (1024**2)))
        vdis = fixture.ListVDI()
        self.assertEquals(2, len(vdis))
        alpha = filter(lambda x: x["name"] == "alpha", vdis)
        self.assertEquals(1, len(alpha))
        self.assertEquals(128 * (1024**2), alpha[0]["nb_size"])
        bravo = filter(lambda x: x["name"] == "bravo", vdis)
        self.assertEquals(1, len(bravo))
        self.assertEquals(192 * (1024**2), bravo[0]["nb_size"])
        self.assertTrue(fixture.DeleteVDI("alpha"))
        self.assertEquals(1, len(fixture.ListVDI()))
        self.assertTrue(fixture.DeleteVDI("bravo"))
        self.assertEquals(0, len(fixture.ListVDI()))

    def testWriteAndReadVDI(self):
        self.assertTrue(fixture.CreateVDI("alpha", 4 * (1024**2)))
        alpha = filter(lambda x: x["name"] == "alpha", fixture.ListVDI())
        self.assertEquals(1, len(alpha))
        alpha = alpha[0]
        self.assertEquals(4 * (1024**2), alpha["nb_size"])

        contentToWrite = os.urandom(4 * (1024**2))
        self.assertEquals(4 * (1024**2), len(contentToWrite))
        self.assertTrue(fixture.WriteVDI("alpha", contentToWrite))

        contentRead = fixture.ReadVDI("alpha")
        self.assertEquals(4 * (1024**2), len(contentRead))

        expected = hashlib.md5(contentToWrite).digest()
        actual = hashlib.md5(contentRead).digest()
        self.assertEquals(expected, actual)

    def testSnapshotVDI(self):
        self.assertTrue(fixture.CreateVDI("alpha", 4 * (1024**2)))
        alpha = filter(lambda x: x["name"] == "alpha", fixture.ListVDI())
        self.assertEquals(1, len(alpha))
        alpha = alpha[0]
        self.assertEquals(4 * (1024**2), alpha["nb_size"])

        contentToWrite = os.urandom(4 * (1024**2))
        self.assertEquals(4 * (1024**2), len(contentToWrite))
        self.assertTrue(fixture.WriteVDI("alpha", contentToWrite))

        self.assertTrue(fixture.SnapshotVDI("alpha", "alpha_1"))
        pred = lambda x: x["snapshot"] and \
            x["name"] == "alpha" and \
            x["tag"] == "alpha_1"
        self.assertEquals(1, len(filter(pred, fixture.ListVDI())))

        self.assertTrue(fixture.WriteVDI("alpha", os.urandom(4 * (1024**2))))

        contentRead = fixture.ReadVDI("alpha", "alpha_1")
        self.assertEquals(4 * (1024**2), len(contentRead))

        expected = hashlib.md5(contentToWrite).digest()
        actual = hashlib.md5(contentRead).digest()
        self.assertEquals(expected, actual)

        self.assertTrue(fixture.DeleteVDI("alpha", "alpha_1"))

    def testCloneVDI(self):
        self.assertTrue(fixture.CreateVDI("alpha", 4 * (1024**2)))
        alpha = filter(lambda x: x["name"] == "alpha", fixture.ListVDI())
        self.assertEquals(1, len(alpha))
        alpha = alpha[0]
        self.assertEquals(4 * (1024**2), alpha["nb_size"])

        contentToWrite = os.urandom(4 * (1024**2))
        self.assertEquals(4 * (1024**2), len(contentToWrite))
        self.assertTrue(fixture.WriteVDI("alpha", contentToWrite))

        self.assertTrue(fixture.SnapshotVDI("alpha", "alpha_1"))
        self.assertTrue(fixture.CloneVDI("alpha", "alpha_1", "bravo"))
        pred = lambda x: x["cloned"] and x["name"] == "bravo"
        self.assertEquals(1, len(filter(pred, fixture.ListVDI())))

        self.assertTrue(fixture.WriteVDI("alpha", os.urandom(4 * (1024**2))))

        contentRead = fixture.ReadVDI("bravo")
        self.assertEquals(4 * (1024**2), len(contentRead))

        expected = hashlib.md5(contentToWrite).digest()
        actual = hashlib.md5(contentRead).digest()
        self.assertEquals(expected, actual)

        self.assertTrue(fixture.DeleteVDI("alpha", "alpha_1"))
        self.assertTrue(fixture.DeleteVDI("alpha"))
        self.assertTrue(fixture.WriteVDI("bravo", os.urandom(4 * (1024**2))))
        self.assertTrue(fixture.DeleteVDI("bravo"))


if __name__ == '__main__':
    unittest.main()
