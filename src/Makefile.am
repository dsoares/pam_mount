#   FILE: Makefile.am -- 
# AUTHOR: W. Michael Petullo <mike@flyn.org>
#   DATE: 03 August 2002
# 
# Copyright (C) 2002 W. Michael Petullo <mike@flyn.org>
# All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


AUTOMAKE_OPTIONS = gnu

bin_PROGRAMS = pmhelper
pmhelper_SOURCES = pmhelper.c misc.c
pmhelper_LDFLAGS = -lcrypt -lssl

moduledir = $(prefix)/../lib/security
module_LTLIBRARIES = pam_mount.la
# miscso.c link is to fix complaint of misc.o being used both with libtool
# and without
pam_mount_la_SOURCES = converse.c miscso.c pam_mount.c readconfig.c dotconf.c
pam_mount_la_LDFLAGS = -module -avoid-version

INCLUDES = -I$(srcdir)/../include

AM_CFLAGS = -g -Werror

install-exec-hook:
	chmod 4755 $(DESTDIR)$(bindir)/pmhelper
