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

INCLUDES		= -I$(top_builddir)/include -I$(top_srcdir)/include $(libcpg_CFLAGS) $(libcfg_CFLAGS)

sbin_PROGRAMS		= sheep

sheep_SOURCES		= sheep.c group.c sdnet.c store.c vdi.c work.c ../lib/event.c ../lib/logger.c ../lib/net.c
sheep_LDADD	  	= $(libcpg_LIBS) $(libcfg_LIBS)
sheep_DEPENDENCIES	= 


noinst_HEADERS		= work.h sheep_priv.h

EXTRA_DIST		= 

lint:
	-splint $(INCLUDES) $(LINT_FLAGS) $(CFLAGS) *.c

all-local: 
	@echo Built sheep

clean-local:
	rm -f sheep *.o gmon.out *.da *.bb *.bbg
