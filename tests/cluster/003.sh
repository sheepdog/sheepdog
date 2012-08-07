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
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

# start Sheepdog with three nodes
$COLLIE cluster format

# kill all sheeps
for i in 0 1 2; do
    pkill -f "sheep $STORE/$i"
    sleep 1
done

# master transfer will happen twice
for i in 0 1 2; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

echo check whether Sheepdog is running with only one node
$COLLIE cluster info -p 7002

# add the other nodes
for i in 0 1; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
    sleep 1
done

echo check whether all nodes have the same cluster info
for i in 0 1 2; do
    $COLLIE cluster info -p 700$i
done
