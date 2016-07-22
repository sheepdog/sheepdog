#/bin/bash
set -xueo pipefail
export LANG=C LC_ALL=C

USR_PATH=/usr
VAR_PATH=/var

prepare() {
  sudo apt-get --quiet -y install \
    git pkg-config make autoconf libtool yasm liburcu-dev libzookeeper-mt-dev qemu check python zookeeper xfsprogs
  sudo /usr/share/zookeeper/bin/zkServer.sh restart
}

build_sheepdog(){
  ./autogen.sh
  ./configure --prefix=$USR_PATH --localstatedir=$VAR_PATH --enable-zookeeper --disable-corosync --enable-unittest
  make
  sudo make install
}

get_submodule(){
  rm -rf ./tests/unit/unity
  rm -rf ./tests/unit/cmock
  git submodule update --init ./tests/unit/unity
  git submodule update --init ./tests/unit/cmock
}

exec_functional() {
  sudo ./tests/functional/check
}

exec_operation() {
  sudo python ./tests/operation/test_3nodes_2copies.py
}

exec_unit() {
  sudo make check
}

#main
prepare
get_submodule
build_sheepdog
exec_unit
exec_operation
exec_functional
