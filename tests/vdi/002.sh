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

for i in 0 2; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
done

sleep 1

$COLLIE cluster format -c 2
$COLLIE vdi create test 4G

echo -n value > $STORE/tmp.dat

echo "key shouldn't be found"
$COLLIE vdi getattr test key || true

$COLLIE vdi setattr test key value
$COLLIE vdi getattr test key | diff - $STORE/tmp.dat

$COLLIE vdi setattr test key value -d

echo "key shouldn't be found"
$COLLIE vdi getattr test key || true
