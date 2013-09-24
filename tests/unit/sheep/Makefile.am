MAINTAINERCLEANFILES	= Makefile.in

TESTS			= test_vdi test_cluster_driver

check_PROGRAMS		= ${TESTS}

AM_CPPFLAGS		= -I$(top_srcdir)/include			\
			  -I$(top_srcdir)/sheep				\
			  -I../mock					\
			  @CHECK_CFLAGS@

LIBS			= $(top_srcdir)/lib/libsheepdog.a		\
			  ../mock/libmock.a -lpthread			\
			  @CHECK_LIBS@

test_vdi_SOURCES	= test_vdi.c mock_sheep.c mock_store.c		\
			  mock_request.c $(top_srcdir)/sheep/vdi.c

test_cluster_driver_SOURCES	= mock_sheep.c mock_group.c		\
				  $(top_srcdir)/sheep/cluster/local.c	\
				  test_cluster_driver.c
test_cluster_driver_CFLAGS	=

if BUILD_ZOOKEEPER
test_cluster_driver_SOURCES	+= $(top_srcdir)/sheep/cluster/zookeeper.c
test_cluster_driver_CFLAGS	+= -DBUILD_ZOOKEEPER
LIBS += -lzookeeper_mt
endif


clean-local:
	rm -f ${check_PROGRAMS} *.o

coverage:
	@lcov -d . -c -o sheep.info
