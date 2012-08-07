#!/bin/bash

set -ex

DRIVER=${DRIVER:-local}
STORE=${STORE:-/tmp/sheepdog}
SHEEP=${SHEEP:-./sheep/sheep}
COLLIE=${COLLIE:-./collie/collie}

killall -9 sheep collie || true
sleep 1
rm -r $STORE/* || true
mkdir -p $STORE

$SHEEP $STORE/0 -z 0 -p 7000 -c $DRIVER
$SHEEP $STORE/1 -z 1 -p 7001 -c $DRIVER
$COLLIE cluster format -c 2
$COLLIE cluster recover disable

qemu-img create sheepdog:test 4G

# create 20 objects
for i in `seq 0 19`; do
    $COLLIE vdi write test $((i * 4 * 1024 * 1024)) 512 < /dev/zero
done

$SHEEP $STORE/2 -z 2 -p 7002 -c $DRIVER

# overwrite the objects
for i in `seq 0 19`; do
    $COLLIE vdi write test $((i * 4 * 1024 * 1024)) 512 < /dev/zero
done
