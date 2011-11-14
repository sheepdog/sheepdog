# Copyright (c) 2011 Taobao.com, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it would be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Based on code from the QEMU I/O test suite (qemu-iotests)
#   Copyright (C) 2009 Red Hat, Inc.
#

# Brief description of each test cases.
cases_desc = {
"001": "Test simple read/write using plain bdrv_read/bdrv_write.",
"002": "Test simple read/write using plain bdrv_pread/bdrv_pwrite.",
"003": "Test simple read/write using bdrv_aio_readv/bdrv_aio_writev.",
"004": "Make sure we can't read and write outside of the image size.",
"008": "Test simple asynchronous read/write operations.",
"011": "Test for AIO allocation on the same cluster.",
"016": "Test I/O after EOF for growable images.",
"025": "Resizing images.",
}

# Used by test_io() method.
io_cases = {
"001":[
("read 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("write -P 0xa 0 128M", """wrote 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read -P 0xa 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
],
"002":[
("read -p 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("write -pP 0xa 0 128M", """wrote 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read -pP 0xa 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("write -pP 0xab 66 42", """wrote 42/42 bytes at offset 66
42.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read -pP 0xab 66 42", """read 42/42 bytes at offset 66
42.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
],
"003":[
("readv 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("writev -P 0xa 0 128M", """wrote 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("readv -P 0xa 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("writev -P 0xb 67M 8k 8k 8k 8k 8k 8k 8k",
"""wrote 57344/57344 bytes at offset 70254592
56 KiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("readv -P 0xb 67M 8k 8k 8k 8k 8k 8k 8k",
"""read 57344/57344 bytes at offset 70254592
56 KiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
],
"004":[
("write 127M 1M", """wrote 1048576/1048576 bytes at offset 133169152
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("write 127M 4M", """write failed: Input/output error"""),
("write 128M 4096", """write failed: Input/output error"""),
("write 140M 4096", """write failed: Input/output error"""),
("write -p 140M 4096", """write failed: Input/output error"""),
("writev 140M 4096","""writev failed: Input/output error"""),
("read 127M 1M", """read 1048576/1048576 bytes at offset 133169152
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read 127M 4M", """read failed: Input/output error"""),
("read 128M 4096", """read failed: Input/output error"""),
("read 140M 4096", """read failed: Input/output error"""),
("read -p 140M 4096", """read failed: Input/output error"""),
("readv 140M 4096", """readv failed: Input/output error"""),
],
"008":[
("aio_read 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("aio_write -P 0xa 0 128M", """wrote 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("aio_read -P 0xa 0 128M", """read 134217728/134217728 bytes at offset 0
128 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
],
"025":[
("length", """128 MiB"""),
("truncate 384M", """"""),
("length", """384 MiB"""),
],
}

# Used by test_growable_io() method.
io_cases_g = {
"016":[
("read -P 0 128M 512", """read 512/512 bytes at offset 134217728
512.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read -P 0 256M 512", """read 512/512 bytes at offset 268435456
512.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("write -P 66 128M 512", """wrote 512/512 bytes at offset 134217728
512.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read -P 66 128M 512", """read 512/512 bytes at offset 134217728
512.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("write -P 66 256M 512", """wrote 512/512 bytes at offset 268435456
512.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("read -P 66 256M 512", """read 512/512 bytes at offset 268435456
512.000000 bytes, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
],
}

# Used by test_aio()
aio_cases = {
"011":[
("""aio_write 1M 1M
aio_write 1536K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 2M 1M
aio_write 2560K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 3M 1M
aio_write 3584K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 4M 1M
aio_write 4608K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 5M 1M
aio_write 5632K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 6M 1M
aio_write 6656K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 7M 1M
aio_write 7680K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 8M 1M
aio_write 8704K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 9M 1M
aio_write 9728K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
("""aio_write 10M 1M
aio_write 10752K 1M""", """wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)
wrote 1048576/1048576 bytes at offset XXX
1 MiB, X ops; XX:XX:XX.X (XXX YYY/sec and XXX ops/sec)"""),
],
}

# Used to specify the image size of each test case.
size_cases = {
"001":128*1024*1024,
"002":128*1024*1024,
"003":128*1024*1024,
"004":128*1024*1024,
"008":128*1024*1024,
"011":6*1024*1024*1024,
"016":128*1024*1024,
"025":128*1024*1024,
}
