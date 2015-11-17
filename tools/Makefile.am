MAINTAINERCLEANFILES	= Makefile.in

sbin_PROGRAMS		=

if BUILD_ZOOKEEPER
sbin_PROGRAMS		+= zk_control

zk_control_SOURCES = zk_control.c

zk_control_LDADD	= -lzookeeper_mt
endif

noinst_PROGRAMS		= $(sbin_PROGRAMS)
