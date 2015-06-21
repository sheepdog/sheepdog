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
			  $(libacrd_CFLAGS) $(corosync_CFLAGS)

sbin_PROGRAMS		= sheep

sheep_SOURCES		= sheep.c group.c request.c gateway.c vdi.c \
			  journal.c ops.c recovery.c cluster/local.c \
			  object_cache.c object_list_cache.c \
			  store/common.c store/md.c \
			  store/plain_store.c store/tree_store.c \
			  config.c migrate.c

if BUILD_HTTP
sheep_SOURCES		+= http/http.c http/kv.c http/s3.c http/swift.c \
			   http/oalloc.c
endif

if BUILD_NFS
sheep_SOURCES		+= nfs/nfsd.c nfs/nfs.c nfs/xdr.c nfs/mount.c nfs/fs.c
endif

if BUILD_COROSYNC
sheep_SOURCES		+= cluster/corosync.c
endif
if BUILD_ZOOKEEPER
sheep_SOURCES		+= cluster/zookeeper.c
endif
if BUILD_SHEPHERD
sheep_SOURCES		+= cluster/shepherd.c
endif

if BUILD_TRACE
AM_CPPFLAGS		+= -DENABLE_TRACE
sheep_SOURCES		+= trace/trace.c trace/mcount.S trace/graph.c trace/checker.c
endif

if BUILD_ACCELIO
sheep_SOURCES		+= xio.c
endif

sheep_LDADD	  	= ../lib/libsd.a -lpthread -lm \
			  $(libacrd_LIBS) $(corosync_LIBS) $(LIBS)

if BUILD_NFS
sheep_LDADD		+= -lrt
endif

sheep_DEPENDENCIES	= ../lib/libsd.a


noinst_HEADERS		= sheep_priv.h cluster.h http/http.h trace/trace.h
			  nfs/nfs.h nfs/fs.h

EXTRA_DIST		=

if BUILD_EARTHQUAKE
sheep_LDADD		+= -leq_embed
endif

# for LTTng ust tracepoints
AM_CPPFLAGS		+= -I$(top_srcdir)/sheep/tracepoint
noinst_HEADERS		+=  tracepoint/request_tp.h

if BUILD_LTTNG_UST
sheep_SOURCES	+= tracepoint/request_tp.c
endif

if BUILD_ACCELIO
sheep_LDADD		+= -lxio
endif

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
