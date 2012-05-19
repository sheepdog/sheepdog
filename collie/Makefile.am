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

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include

sbin_PROGRAMS		= collie

collie_SOURCES		= collie.c common.c treeview.c vdi.c node.c cluster.c

if BUILD_TRACE
collie_SOURCES          += debug.c
override CFLAGS         := $(subst -pg -gstabs,,$(CFLAGS))
endif

collie_LDADD	  	= ../lib/libsheepdog.a
collie_DEPENDENCIES	= ../lib/libsheepdog.a

noinst_HEADERS		= treeview.h collie.h

EXTRA_DIST		= 

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c

all-local: 
	@echo Built collie

clean-local:
	rm -f collie *.o gmon.out *.da *.bb *.bbg

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)
