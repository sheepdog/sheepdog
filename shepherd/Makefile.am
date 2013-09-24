#
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

AM_CPPFLAGS		= -I$(top_builddir)/include -I$(top_srcdir)/include

sbin_PROGRAMS		= shepherd

shepherd_SOURCES		= shepherd.c

shepherd_LDADD	  	= ../lib/libsheepdog.a
shepherd_DEPENDENCIES	= ../lib/libsheepdog.a

EXTRA_DIST		=

lint:
	-splint $(AM_CPPFLAGS) $(LINT_FLAGS) $(CFLAGS) *.c

all-local:
	@echo Built shepherd

clean-local:
	rm -f shepherd *.o gmon.out *.da *.bb *.bbg

# support for GNU Flymake
check-syntax:
	$(COMPILE) -fsyntax-only $(CHK_SOURCES)
