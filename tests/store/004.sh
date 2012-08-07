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

dd if=/dev/zero of=$STORE/0.img seek=$((2 * 1024 ** 3 - 1)) bs=1 count=1
dd if=/dev/zero of=$STORE/1.img seek=$((4 * 1024 ** 3 - 1)) bs=1 count=1
dd if=/dev/zero of=$STORE/2.img seek=$((8 * 1024 ** 3 - 1)) bs=1 count=1

for i in 0 1 2; do
    mkfs.xfs $STORE/$i.img
    mkdir $STORE/$i
    mount -o loop $STORE/$i.img $STORE/$i
    $SHEEP $STORE/$i/ -z $i -p 700$i -c $DRIVER
done

sleep 1

echo check the number of vnodes
for i in 0 1 2; do
    $COLLIE node list -p 700$i
done
