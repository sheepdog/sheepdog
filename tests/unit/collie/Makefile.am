MAINTAINERCLEANFILES	= Makefile.in

TESTS			= test_common

check_PROGRAMS		= ${TESTS}

INCLUDES		= -I$(top_srcdir)/include			\
			  -I$(top_srcdir)/collie			\
			  -I$(top_srcdir)/collie/farm			\
			  -I../mock					\
			  @CHECK_CFLAGS@

LIBS			= $(top_srcdir)/lib/libsheepdog.a -lpthread	\
			  ../mock/libmock.a @CHECK_LIBS@

test_common_SOURCES	= test_common.c mock_collie.c			\
			  $(top_srcdir)/collie/common.c

clean-local:
	rm -f ${check_PROGRAMS} *.o

coverage:
	@lcov -d . -c -o collie.info
