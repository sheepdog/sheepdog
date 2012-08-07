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
sleep 1

# start Sheepdog with one node
$COLLIE cluster format
sleep 1

# launch sheeps simultaneously
for i in `seq 1 9`; do
       $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
done

sleep 1

echo check whether all nodes have the same cluster info
for i in `seq 0 9`; do
    $COLLIE cluster info -p 700$i
done
