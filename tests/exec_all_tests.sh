#/bin/bash
set -xueo pipefail
export LANG=C LC_ALL=C

USR_PATH=/usr
VAR_PATH=/var
ULIMIT_SIZE=16384

prepare() {
  sudo apt-get --quiet -y install \
    git pkg-config make autoconf libtool yasm liburcu-dev libzookeeper-mt-dev qemu check python zookeeper xfsprogs
  sudo /usr/share/zookeeper/bin/zkServer.sh start
}

build_sheepdog(){
  ./autogen.sh
  ./configure --prefix=$USR_PATH --localstatedir=$VAR_PATH --enable-zookeeper --disable-corosync --enable-unittest
  make
  sudo make install
}

get_submodule(){
  git submodule update -f --init ./tests/unity
  git submodule update -f --init ./tests/unit/cmock
}

exec_functional() {
  sudo ./tests/functional/check
}

exec_operation() {
  sudo python ./tests/operation/test_3nodes_2copies.py
}

exec_unit() {
  ulimit -s $ULIMIT_SIZE
  make check
}

#main
prepare
build_sheepdog
get_submodule
exec_functional
exec_operation
exec_unit
