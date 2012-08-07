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
qemu-img snapshot -c tag1 sheepdog:test
qemu-img snapshot -c tag2 sheepdog:test
qemu-img snapshot -c tag3 sheepdog:test

qemu-img create sheepdog:test2 4G
qemu-img snapshot -c tag1 sheepdog:test2
qemu-img snapshot -c tag2 sheepdog:test2
qemu-io -c "write 0 512" sheepdog:test2:1
qemu-img snapshot -c tag3 sheepdog:test2

$COLLIE vdi tree

# expected results:
#
# test---[2012-08-07 18:04]---[2012-08-07 18:04]---[2012-08-07 18:04]---(you are here)
# test2---[2012-08-07 18:04]-+-[2012-08-07 18:04]---[2012-08-07 18:04]
#                            `-[2012-08-07 18:04]---(you are here)
