#!/bin/bash -x

image=${IMAGE:-sheepdog:latest}
nodes=${NODES:-"n1 n2 n3"}
docker=${DOCKER:-docker}

echo "Killing old cluster..."
for node in $nodes; do
    $docker kill $node
    $docker rm $node
done

sleep 1

echo "Starting new cluster..."
for node in $nodes; do
    $docker run -h $node -d --name=$node -t $image
done
