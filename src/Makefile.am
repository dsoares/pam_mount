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

if FLYN
# For local development use only.
include /etc/fctk/config.mk
endif

AUTOMAKE_OPTIONS = gnu

moduledir = @PAM_MODDIR@
module_LTLIBRARIES = pam_mount.la
# Use -lfmt_ptrn if it exists else compile locally (see also configure.in).
# ../include-fmt_ptrn should contain libfmt_ptrn's headers for use if
# -lfmt_ptrn does not exist.
if SYSTEM_LIBFMT_PTRN
pam_mount_la_SOURCES = misc.c pam_mount.c readconfig.c dotconf.c mount.c optlist.c
pam_mount_la_LDFLAGS = -module -avoid-version -lfmt_ptrn -ltemplate $(GLIB_LIBS)
else
pam_mount_la_SOURCES = misc.c pam_mount.c readconfig.c dotconf.c mount.c pair.c optlist.c fmt_ptrn.c modifiers.c template.c common.c buffer.c
pam_mount_la_LDFLAGS = -module -avoid-version $(GLIB_LIBS)
endif

INCLUDES = -I$(srcdir)/../include @LOCAL_FMT_PTRN_INCLUDES@

AM_CFLAGS = -g -Werror $(GLIB_CFLAGS)

if FLYN
# For local development use only.
lint:
	$(LINT)
endif
