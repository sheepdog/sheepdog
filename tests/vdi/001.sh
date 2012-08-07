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

for i in 0 1 2; do
    $SHEEP $STORE/$i -p 700$i -z $i -c $DRIVER
done

sleep 1

$COLLIE cluster format -c 1

qemu-img create sheepdog:test 4G
for i in `seq 1 9`; do
    qemu-io -c "write 0 512 -P $i" sheepdog:test
    qemu-img snapshot -c tag$i sheepdog:test
done

qemu-io -c "read 0 512 -P 9" sheepdog:test
for i in `seq 1 9`; do
    qemu-io -c "read 0 512 -P $i" sheepdog:test:tag$i
done
