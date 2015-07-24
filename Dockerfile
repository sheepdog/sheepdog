FROM ubuntu:14.04
RUN apt-get -qq update
RUN apt-get -qq install -y gcc autoconf yasm pkg-config libtool make
RUN apt-get -qq install -y corosync libcorosync-dev crmsh
RUN apt-get -qq install -y liburcu-dev libqb-dev
ENV SHEEPSRC /usr/src/sheepdog
ENV SHEEPPORT 7000
ENV SHEEPSTORE /store
ADD ./docker/corosync.conf /etc/corosync/corosync.conf
ADD ./docker/run.sh /root/run.sh

WORKDIR $SHEEPSRC
ADD . $SHEEPSRC
RUN ./autogen.sh
RUN ./configure && make && make check && make install

RUN mkdir $SHEEPSTORE

EXPOSE $SHEEPPORT
CMD /bin/bash /root/run.sh
