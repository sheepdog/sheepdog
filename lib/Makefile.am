MAINTAINERCLEANFILES    = Makefile.in

AM_CPPFLAGS                = -I$(top_builddir)/include -I$(top_srcdir)/include

libsheepdog_a_DEPENDENCIES =

noinst_LIBRARIES	= libisa.a libsheepdog.a

libisa_a_SOURCES	= $(shell find isa-l/ -type f -regex ".*\.\(c\|h\|asm\)") \
			  isa-l/erasure_code/Makefile \
			  isa-l/Makefile \
			  isa-l/Makefile.nmake \
			  isa-l/make.inc

libsheepdog_a_SOURCES	= event.c logger.c net.c util.c rbtree.c strbuf.c \
			  sha1.c option.c work.c sockfd_cache.c fec.c sd_inode.c

libsheepdog_a_LIBADD	= isa-l/bin/ec_base.o \
			  isa-l/bin/ec_highlevel_func.o \
			  isa-l/bin/ec_multibinary.o \
			  isa-l/bin/gf_2vect_dot_prod_sse.o \
		  	  isa-l/bin/gf_3vect_dot_prod_sse.o \
		  	  isa-l/bin/gf_4vect_dot_prod_sse.o \
			  isa-l/bin/gf_5vect_dot_prod_sse.o \
			  isa-l/bin/gf_6vect_dot_prod_sse.o \
			  isa-l/bin/gf_vect_dot_prod_sse.o \
			  isa-l/bin/gf_vect_mul_avx.o \
			  isa-l/bin/gf_vect_mul_sse.o

if BUILD_SHA1_HW
libsheepdog_a_SOURCES	+= sha1_ssse3.S
endif

if BUILD_TRACE
AM_CPPFLAGS		+= -DENABLE_TRACE
endif

# for LTTng ust tracepoints
AM_CPPFLAGS		= -I$(top_srcdir)/lib/tracepoint
noinst_HEADERS		=  tracepoint/work_tp.h tracepoint/sockfd_cache_tp.h

if BUILD_LTTNG_UST
libsheepdog_a_SOURCES	+= tracepoint/work_tp.c tracepoint/sockfd_cache_tp.c
endif

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)

check-style:
	@$(CHECK_STYLE) $(libsheepdog_a_SOURCES)

libisa.a:
	cd isa-l/ && $(MAKE) && cd ..

clean:
	cd isa-l/ && $(MAKE) clean && cd ..
