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
    $SHEEP $STORE/$i/ -z $i -p 700$i -c $DRIVER
done

# add gateway node
$SHEEP $STORE/4/ -z 4 -p 7004 -c $DRIVER -g

sleep 1

echo check the number of vnodes
$COLLIE node list
