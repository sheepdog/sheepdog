#! /bin/bash

# fault injection for testing journaling with object store

sudo killall -KILL sheep
sudo killall -KILL shepherd

sudo rm -rf /tmp/sheepdog/dynamorio/*
sudo mkdir -p /tmp/sheepdog/dynamorio/0

sudo shepherd

sudo ~/dynamorio/build/bin64/drrun -c libjournaling.so 1 -- \
    sheep -d -c shepherd:127.0.0.1 -p 7000 -j size=64 /tmp/sheepdog/dynamorio/0

sleep 3

dog cluster format -c 1
dog vdi create test 100M

sudo sheep -d -c shepherd:127.0.0.1 -p 7000 -j size=64 /tmp/sheepdog/dynamorio/0
