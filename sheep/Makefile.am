#
# Copyright 2010 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

MAINTAINERCLEANFILES	= Makefile.in

AM_CFLAGS		=

AM_CPPFLAGS		= -I$(top_builddir)/include -I$(top_srcdir)/include \
			  $(libcpg_CFLAGS) $(libcfg_CFLAGS) $(libacrd_CFLAGS)

sbin_PROGRAMS		= sheep

sheep_SOURCES		= sheep.c group.c request.c gateway.c store.c vdi.c \
			  journal.c ops.c recovery.c cluster/local.c \
			  object_cache.c object_list_cache.c \
			  plain_store.c config.c migrate.c md.c \
			  cluster/shepherd.c

if BUILD_HTTP
sheep_SOURCES		+= http.c
endif
if BUILD_COROSYNC
sheep_SOURCES		+= cluster/corosync.c
endif
if BUILD_ZOOKEEPER
sheep_SOURCES		+= cluster/zookeeper.c
endif

if BUILD_TRACE
sheep_SOURCES		+= trace/trace.c trace/mcount.S trace/graph.c trace/checker.c
endif

sheep_LDADD	  	= ../lib/libsheepdog.a -lpthread -lm\
			  $(libcpg_LIBS) $(libcfg_LIBS) $(libacrd_LIBS) $(LIBS)
sheep_DEPENDENCIES	= ../lib/libsheepdog.a


noinst_HEADERS		= sheep_priv.h cluster.h trace/trace.h

EXTRA_DIST		= 

all-local: 
	@echo Built sheep

clean-local:
	rm -f sheep *.o gmon.out *.da *.bb *.bbg

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)

check-style:
	@$(CHECK_STYLE) $(sheep_SOURCES) $(noinst_HEADERS)

coverage:
	@lcov -d . -c -o sheep.info
