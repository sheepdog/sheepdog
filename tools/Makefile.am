MAINTAINERCLEANFILES	= Makefile.in

noinst_PROGRAMS		=

if BUILD_ZOOKEEPER
noinst_PROGRAMS		+= zk_control

zk_control_SOURCES = zk_control.c

zk_control_LDADD	= -lzookeeper_mt
endif
