MAINTAINERCLEANFILES	= Makefile.in

TESTS			= test_common

check_PROGRAMS		= ${TESTS}

AM_CPPFLAGS		= -I$(top_srcdir)/include			\
			  -I$(top_srcdir)/dog				\
			  -I$(top_srcdir)/dog/farm			\
			  -I../mock					\
			  @CHECK_CFLAGS@

LIBS			= $(top_srcdir)/lib/libsd.a -lpthread	\
			  ../mock/libmock.a @CHECK_LIBS@

test_common_SOURCES	= test_common.c mock_dog.c			\
			  dog/common.c

clean-local:
	rm -f ${check_PROGRAMS} *.o

coverage:
	@lcov -d . -c -o dog.info

dog/%.c: $(top_srcdir)/dog/%.c
	@mkdir -p $(@D)
	@cp $< $@

distclean-local:
	rm -rf dog
