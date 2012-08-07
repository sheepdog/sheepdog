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

# create a node who has wrong epoch
$SHEEP $STORE/1 -p 7001 -z 1 -c $DRIVER
sleep 1
$COLLIE cluster format -p 7001 -c 1
$COLLIE cluster shutdown -p 7001
sleep 1

# start Sheepdog with one node
$SHEEP $STORE/0 -p 7000 -z 0 -c $DRIVER
sleep 1
$COLLIE cluster format -p 7000 -c 1

for i in `seq 0 5`; do
    $SHEEP $STORE/1 -p 7001 -z 1 -c $DRIVER  # should fail
    $SHEEP $STORE/2 -p 7002 -z 2 -c $DRIVER  # should succeed
    sleep 1

    if [ "`$COLLIE node list -p 7002 -r | wc -l`" -ne 2 ]; then
	echo "test failed"
	$COLLIE cluster info -p 7000
	$COLLIE cluster info -p 7002
	exit 1
    fi

    pkill -f "$SHEEP $STORE/2"
    sleep 1
done

echo "success"
