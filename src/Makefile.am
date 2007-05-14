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

moduledir = @PAM_MODDIR@
module_LTLIBRARIES = pam_mount.la
sbin_PROGRAMS = pmvarrun

pam_mount_la_SOURCES = crypto.c misc.c pam_mount.c rdconf1.c rdconf2.c mount.c pair.c optlist.c buffer.c spawn.c xstdlib.c
pam_mount_la_LDFLAGS = -module -avoid-version $(GLIB_LIBS) $(XML_LIBS) -lHX

pmvarrun_SOURCES = pmvarrun.c misc-nolibtool.c buffer-nolibtool.c pair-nolibtool.c xstdlib-nolibtool.c
pmvarrun_LDFLAGS = $(GLIB_LIBS) -lHX

INCLUDES = -I$(srcdir)/../include

AM_CFLAGS = $(GLIB_CFLAGS) $(XML_CPPFLAGS) -DG_DISABLE_DEPRECATED \
	-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe @GCC_FVISIBILITY_HIDDEN@
