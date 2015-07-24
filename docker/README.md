Installing docker
=================

For complete info, visit the [Docker
site](https://docs.docker.com/installation/). For quick start, see
sections below.

On Ubuntu
---------

Install the docker daemon using apt. Note the package name.

    apt-get install docker.io


On Mac
------

Using homebrew, boot2docker, and virtualbox is easiest.

    brew install boot2docker
    boot2docker init
    boot2docker up


Building container image
==============

Use `docker build .` from the source root directory, or use
`docker/build.sh` to automatically tag the image. Alternatively,
download an image from docker.io and specify the image name in the
next step.

After building or pulling the image, it should be visible when running
`docker images`.


Running a cluster
=================

All scripts are controlled using environment variables (all caps).

    IMAGE - docker image name, for building or starting containers
    NODE - for running commands on containers, the name of the node
    DOCKER - the docker command (try DOCKER="sudo docker" on linux)

Use `docker/start_cluster.sh` to start a 3 node corosync cluster with
sheep running on each one. You can specify the node names with NODES,
or default to "n1 n2 n3". If any of the nodes already exist they will
be killed and removed. You can specify the image with IMAGE, or
default to sheepdog:latest.

Use `docker/cdog` to run dog commands on the cluster nodes. You can
specify the target node with NODE=nodename, or default to n1.

A full example:

    ./docker/build.sh
    ./docker/start_cluster.sh
    ./docker/cdog cluster format
    ./docker/cdog cluster info

Running an image from docker.io:

    export IMAGE=cjdnxx/sheepdog
    docker pull $IMAGE
    ./docker/start_cluster.sh # uses IMAGE env var

After starting the cluster, use `docker ps` to see the running
containers.

Pause containers with `docker pause`, then unpause with `docker
unpause` to simulate machines temporarily leaving the cluster. Use
`docker kill` to nuke a container. Note that IP addresses are assigned
dynamically so a killed container will appear as a new node, even if
it has the same host name.
