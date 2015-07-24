#!/bin/bash -x

srcdir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
image=${IMAGE:-sheepdog:latest}
docker=${DOCKER:-docker}

$docker build -t $image $srcdir/..
