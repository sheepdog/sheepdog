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

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include \
			  $(libcpg_CFLAGS) $(libcfg_CFLAGS) $(libacrd_CFLAGS)

sbin_PROGRAMS		= sheep

sheep_SOURCES		= sheep.c group.c sdnet.c store.c vdi.c work.c \
			  journal.c ops.c recovery.c cluster/local.c strbuf.c \
			  simple_store.c object_cache.c object_list_cache.c

if BUILD_COROSYNC
sheep_SOURCES		+= cluster/corosync.c
endif
if BUILD_ZOOKEEPER
sheep_SOURCES		+= cluster/zookeeper.c
endif
if BUILD_ACCORD
sheep_SOURCES		+= cluster/accord.c
endif

if BUILD_FARM
sheep_SOURCES		+= farm/sha1_file.c farm/trunk.c farm/snap.c farm/farm.c
endif

if BUILD_TRACE
sheep_SOURCES		+= trace/trace.c trace/mcount.S trace/stabs.c trace/graph.c
endif

sheep_LDADD	  	= ../lib/libsheepdog.a -lpthread \
			  $(libcpg_LIBS) $(libcfg_LIBS) $(libacrd_LIBS) $(LIBS)
sheep_DEPENDENCIES	= ../lib/libsheepdog.a


noinst_HEADERS		= work.h sheep_priv.h cluster.h strbuf.h farm/farm.h trace/trace.h

EXTRA_DIST		= 

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c

all-local: 
	@echo Built sheep

clean-local:
	rm -f sheep *.o gmon.out *.da *.bb *.bbg

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)
