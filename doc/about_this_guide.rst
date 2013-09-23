About This Guide
================

This guide is for users who intend to install and administer a sheepdog cluster.

It's divided in three main sections:

- Sheepdog Basics
- Sheepdog Advanced Use
- Suggestions And Special Cases

You have to be familiar with GNU/Linux, the shell, networking and virtualization
(in general), ssh and kvm (specifically).
In this guide we use a "simple" scenario of a small cluster with 4 nodes.

Here are some of the terms used in this document:

::

    cluster = group of servers
    host = a server
    vm / guest = a virtual machine running on a host
    node = a host running sheepdog daemon
    vdi = virtual disk used by sheepdog
    sheep = vary according to the context. It may be
        - the sheepdog daemon process name
        - the command to run the daemon
