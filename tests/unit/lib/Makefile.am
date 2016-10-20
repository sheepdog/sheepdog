MAINTAINERCLEANFILES	= Makefile.in

TESTS			= test_util test_work test_punchhole		\
			  test_atomic_create_and_write

check_PROGRAMS		= ${TESTS}

AM_CPPFLAGS		= -I$(top_srcdir)/include			\
			  -I$(top_srcdir)/sheep				\
			  -I$(top_srcdir)/lib/tracepoint		\
			  -I../mocks					\
			  -I../cmock/src				\
			  -I../unity/src				\
			  @CHECK_CFLAGS@

LIBS			= -pthread -lm					\
			  $(top_srcdir)/lib/libsd.a			\
			  @CHECK_LIBS@

test_util_SOURCES	= test_util.c ../../../lib/util.c		\
			  ../mocks/Mocklogger.c				\
			  ../cmock/src/cmock.c ../unity/src/unity.c

test_work_SOURCES	= test_work.c ../../../lib/work.c		\
			  ../unity/src/unity.c

test_punchhole_SOURCES	= test_punchhole.c				\
			  ../../../lib/util.c				\
			  ../mocks/Mocklogger.c				\
			  ../cmock/src/cmock.c ../unity/src/unity.c

test_atomic_create_and_write_SOURCES =					\
			  test_atomic_create_and_write.c		\
			  ../../../lib/common.c				\
			  ../mocks/Mocklogger.c				\
			  ../cmock/src/cmock.c ../unity/src/unity.c

clean-local:
	rm -f ${check_PROGRAMS} *.o sheep.info

coverage:
	@lcov -d . -c -o sheep.info
