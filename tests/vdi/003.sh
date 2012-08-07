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
$COLLIE vdi create test 539545600
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi write test 512 512 < /dev/zero
echo "there should be 3 setattr errors"

$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi write test 512 512 < /dev/zero
echo "there should be 8 setattr errors"

$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi write test 512 512 < /dev/zero
echo "there should be 6 setattr errors"

$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi setattr test lock 1 -x &
$COLLIE vdi write test 512 512 < /dev/zero
echo "there should be 5 setattr errors"
