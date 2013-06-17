MAINTAINERCLEANFILES	= Makefile.in

TESTS			= test_vdi

check_PROGRAMS		= ${TESTS}

INCLUDES		= -I$(top_srcdir)/include			\
			  -I$(top_srcdir)/sheep				\
			  @CHECK_CFLAGS@

LIBS			= $(top_srcdir)/lib/libsheepdog.a -lpthread	\
			  @CHECK_LIBS@

test_vdi_SOURCES	= test_vdi.c mock_sheep.c mock_store.c		\
			  mock_request.c $(top_srcdir)/sheep/vdi.c

clean-local:
	rm -f ${check_PROGRAMS} *.o

coverage:
	@lcov -d . -c -o sheep.info
