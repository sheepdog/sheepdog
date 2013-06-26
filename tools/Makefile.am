MAINTAINERCLEANFILES	= Makefile.in

sbin_PROGRAMS		=

if BUILD_ZOOKEEPER
sbin_PROGRAMS		+= kill_zk_session

kill_zk_session_SOURCES = kill_zk_session.c

kill_zk_session_LDADD	= -lzookeeper_mt
endif

noinst_PROGRAMS		= $(sbin_PROGRAMS)
