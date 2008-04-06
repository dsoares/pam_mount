# -*- Makefile -*-
#
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
bin_PROGRAMS = pmt-fd0ssh
sbin_PROGRAMS = pmvarrun

pam_mount_la_SOURCES = crypto.c misc.c pam_mount.c rdconf1.c rdconf2.c mount.c spawn.c xstdlib.c
pam_mount_la_LIBADD  = -lHX -lpam ${pmt_LIBS}
pam_mount_la_LDFLAGS = -module -avoid-version $(XML_LIBS)

pmt_fd0ssh_SOURCES = fd0ssh.c

pmvarrun_SOURCES = pmvarrun.c misc-nolibtool.c xstdlib-nolibtool.c
pmvarrun_LDADD   = -lHX

AM_CFLAGS = $(XML_CPPFLAGS) $(regular_CFLAGS) $(GCC_FVISIBILITY_HIDDEN)

install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_mount.la;
