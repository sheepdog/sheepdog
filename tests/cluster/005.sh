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

for i in 0 1; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

# start Sheepdog with two nodes
$COLLIE cluster format -c 1
sleep 1

for i in 2 3 4; do
    pkill -f "sheep $STORE/$((i - 2))"
    sleep 1
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

$COLLIE cluster shutdown -p 7004
sleep 1

for i in 0 1 2 3 4; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

echo check whether Sheepdog is working with two nodes
for i in 3 4; do
    $COLLIE cluster info -p 700$i
done

# add the other nodes
for i in 0 1 2; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

echo check whether all nodes have the same cluster info
for i in 0 1 2 3 4; do
    $COLLIE cluster info -p 700$i
done
