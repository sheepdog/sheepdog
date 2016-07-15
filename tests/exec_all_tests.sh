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
  cd ~
  if [ ! -d sheepdog ] ; then
    git clone https://github.com/matsu777/sheepdog.git
  fi
  cd ./sheepdog
  ./autogen.sh
  ./configure --prefix=$USR_PATH --localstatedir=$VAR_PATH --enable-zookeeper --disable-corosync --enable-unittest
  make
  sudo make install
}

get_submodule(){
  cd ~
  cd ./sheepdog/tests/unit
  git submodule update -f --init unity
  git submodule update -f --init cmock
}

exec_functional() {
  cd ~
  sudo ./sheepdog/tests/functional/check
}

exec_operation() {
  cd ~
  sudo python ./sheepdog/tests/operation/test_3nodes_2copies.py
}

exec_unit() {
  ulimit -s $ULIMIT_SIZE
  cd ~
  cd ./sheepdog/tests/unit
  make check
}

#main
prepare
build_sheepdog
get_submodule
exec_functional
exec_operation
exec_unit
