MAINTAINERCLEANFILES	= Makefile.in

TESTS			= test_vdi test_cluster_driver test_hash

check_PROGRAMS		= ${TESTS}

AM_CPPFLAGS		= -I$(top_srcdir)/include			\
			  -I$(top_srcdir)/sheep				\
			  -I../mock					\
			  @CHECK_CFLAGS@

LIBS			= $(top_srcdir)/lib/libsd.a		\
			  ../mock/libmock.a -lpthread -lm		\
			  @CHECK_LIBS@

test_vdi_SOURCES	= test_vdi.c mock_sheep.c mock_store.c		\
			  mock_request.c sheep/vdi.c

test_cluster_driver_SOURCES	= mock_sheep.c mock_group.c		\
				  sheep/cluster/local.c	\
				  test_cluster_driver.c
test_cluster_driver_CFLAGS	=

if BUILD_ZOOKEEPER
test_cluster_driver_SOURCES	+= sheep/cluster/zookeeper.c
test_cluster_driver_CFLAGS	+= -DBUILD_ZOOKEEPER
LIBS += -lzookeeper_mt
endif

test_hash_SOURCES	= test_hash.c mock_sheep.c mock_group.c \
				mock_plain_store.c mock_gateway.c

clean-local:
	rm -f ${check_PROGRAMS} *.o

coverage:
	@lcov -d . -c -o sheep.info

sheep/%.c: $(top_srcdir)/sheep/%.c
	@mkdir -p $(@D)
	@cp $< $@

distclean-local:
	rm -rf sheep
