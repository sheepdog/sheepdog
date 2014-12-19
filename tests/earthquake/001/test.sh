#! /bin/bash

PATH=$PATH:`pwd`		# for executing execCmd.sh

echo $PATH

TOP_DIR=/tmp/sheepdog/earthquake
TEST_DIR=$TOP_DIR/001

EARTHQUAKE=../earthquake.git/earthquake/earthquake

pkill -9 earthquake

# check iSCSI stuff

_notrun()
{
    echo "$seq not run: $*"
    status=0
    exit
}

TGTD=../tgt.git/usr/tgtd
TGTADM=../tgt.git/usr/tgtadm
ISCSID=${ISCSID_PROG:-iscsiadm}
ISCSIADM=${ISCSIADM_PROG:-iscsiadm}

SHEEP=../../../sheep/sheep
DOG=../../../dog/dog

which $TGTD > /dev/null || _notrun "Require tgtd but it's not installed"
which $TGTADM > /dev/null || _notrun "Require tgtadm but it's not installed"
which $ISCSID > /dev/null || _notrun "Require iscsid but it's not installed"
which $ISCSIADM > /dev/null || _notrun "Require iscsiadm but it's not installed"

$ISCSIADM -m node --logout &> /dev/null
pkill -9 $ISCSID > /dev/null
pkill -9 $ISCSIADM > /dev/null
pkill -9 tgtd > /dev/null
pkill -9 tgtadm > /dev/null

ORIG_DEVFILES=orig_devfiles
LOGIN_DEVFILES=login_devfiles
DIFF_DEVFILES=diff_devfiles

/bin/ls /dev/sd* > $ORIG_DEVFILES

_setup_tgtd()
# $1: iscsi portal
# $2: VDI name for backing store
{
    $TGTD --iscsi portal=$1
    $TGTADM --lld iscsi --mode target --op new --tid 1 --targetname iqn.2014-12.org.sheepdog-project
    $TGTADM --mode logicalunit --op new --tid 1 --lun 1 --bstype sheepdog --backing-store $2
    $TGTADM --mode target --op bind --tid 1 --initiator-address ALL
}

PORTAL1=127.0.0.1:3260

pkill -9 sheep
rm -rf $TEST_DIR
mkdir -p $TEST_DIR

export EQ_DISABLE=1		# earthquake should be turned off during preparation phase

for i in `seq 0 2`; do
    $SHEEP -l level=debug -c local -p 700$i -z $i  $TEST_DIR/$i
done
sleep 1

VDINAME=test

$DOG cluster format
$DOG vdi create $VDINAME 64M -P

$EARTHQUAKE --launch-orchestrator --daemonize --log-file-path=orchestrator.log --execution-file-path=execution.json

_setup_tgtd $PORTAL1 unix:$TEST_DIR/0/sock:$VDINAME

$ISCSID

$ISCSIADM -m discovery -t sendtargets -p $PORTAL1
$ISCSIADM -m node --login
sleep 15

/bin/ls /dev/sd* > $LOGIN_DEVFILES

comm -3 $LOGIN_DEVFILES $ORIG_DEVFILES > $DIFF_DEVFILES

if [[ "1 $DIFF_DEVFILES" != `wc -l $DIFF_DEVFILES` ]]
then
    _notrun "Device files were not created correctly"
fi

MNTPOINT=`pwd`/mnt
if [ ! -d $MNTPOINT ]
then
    mkdir $MNTPOINT
else
    umount $MNTPOINT
fi

DEVFILE=`cat $DIFF_DEVFILES`

mkfs.ext4 -F $DEVFILE
mount $DEVFILE $MNTPOINT

unset EQ_DISABLE

export EQ_ENV_PROCESS_ID="dog-snapshot"
$DOG vdi snapshot $VDINAME

umount $MNTPOINT
$ISCSIADM -m node --logout
