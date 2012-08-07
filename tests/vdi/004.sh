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

sleep 1;

$COLLIE cluster format -c 3
$COLLIE vdi create base 100M -P

qemu-img snapshot -c tag sheepdog:base

sleep 1

$COLLIE vdi clone -s 1 base test

sleep 1

$COLLIE vdi delete test

sleep 1
$COLLIE vdi delete base

sleep 1
$COLLIE vdi delete -s 1 base

sleep 3
echo there should be no vdi
$COLLIE vdi list

echo there should be no object
$COLLIE node info
