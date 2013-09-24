MAINTAINERCLEANFILES    = Makefile.in

AM_CPPFLAGS                = -I$(top_builddir)/include -I$(top_srcdir)/include

noinst_LIBRARIES	= libsheepdog.a

libsheepdog_a_SOURCES	= event.c logger.c net.c util.c rbtree.c strbuf.c \
			  sha1.c option.c work.c sockfd_cache.c

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)

check-style:
	@$(CHECK_STYLE) $(libsheepdog_a_SOURCES)
