#! /bin/bash

dd if=/dev/zero of=mnt/junk bs=$((1024 * 1024)) count=16 oflag=sync
