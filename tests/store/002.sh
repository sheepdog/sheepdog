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

# start three sheep daemons
for i in 0 1 2; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
done

sleep 1
$COLLIE cluster format -c 2

# create a pre-allocated vdi
$COLLIE vdi create test 80M -P

# stop the 3rd node
pkill -f "$SHEEP $STORE/2"

# write data to the vdi
cat /dev/urandom | $COLLIE vdi write test

# restart the 3rd node
$SHEEP $STORE/2 -z 2 -p 7002 -c $DRIVER

# wait for object recovery to finish
sleep 10

# show md5sum of the vdi on each node
for i in 0 1 2; do
    $COLLIE vdi read test -p 700$i | md5sum
done
