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

AM_CFLAGS		= $(fuse_CFLAGS) -DFUSE_USE_VERSION=26

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include

sbin_PROGRAMS		= sheepfs

sheepfs_SOURCES		= core.c cluster.c vdi.c shadow_file.c volume.c node.c \
			  config.c

sheepfs_LDADD	  	= ../lib/libsheepdog.a $(fuse_LIBS) $(LIBS)
sheepfs_DEPENDENCIES	= ../lib/libsheepdog.a

noinst_HEADERS		= sheepfs.h

EXTRA_DIST		=

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c

all-local:
	@echo Built sheepfs

clean-local:
	rm -f sheepfs *.o gmon.out *.da *.bb *.bbg

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)
