#!/bin/bash
# cmd run on container creation (only call within a container)
# leave a bash shell as the foreground process

env
/usr/sbin/corosync
service pacemaker start
/usr/sbin/sheep -c corosync $SHEEPSTORE -p $SHEEPPORT
/bin/bash
