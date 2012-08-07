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

for i in `seq 0 7`; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
done
while true; do
        if [ $($COLLIE node list | wc -l) -ne 9 ]; then
		sleep 1
        else
		break
        fi
done

$COLLIE cluster format -c 3
sleep 1

for i in `seq 0 4`; do
    $COLLIE vdi create test$i 100M
done

for i in `seq 0 4`; do
    dd if=/dev/urandom | $COLLIE vdi write test$i -p 7000 &
done

sleep 3

echo begin kill
for i in `seq 1 5`; do
    pkill -f "$SHEEP $STORE/$i -z $i -p 700$i"
    sleep 3
done

for i in `seq 1 5`; do
    $SHEEP $STORE/$i -z $i -p 700$i -c $DRIVER
done

echo wait for object recovery to finish
while true; do
        if [ "$(pgrep collie)" ]; then
                sleep 1
        else
                break
        fi
done

for i in `seq 0 7`; do
        for j in `seq 0 4`; do
                $COLLIE vdi read test$j -p 700$i | md5sum
        done
done
