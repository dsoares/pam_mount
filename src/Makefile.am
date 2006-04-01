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
sbin_PROGRAMS = pmvarrun

if FLYN
noinst_PROGRAMS = check
endif

pam_mount_la_SOURCES = crypto.c misc.c pam_mount.c readconfig.c dotconf.c mount.c pair.c optlist.c fmt_ptrn.c modifiers.c template.c common.c buffer.c spawn.c
pam_mount_la_LDFLAGS = -module -avoid-version -lz $(GLIB_LIBS)

# FIXME: misc.c needs to be compiled both with and without libtool
pmvarrun_SOURCES = pmvarrun.c misc-nolibtool.c fmt_ptrn-nolibtool.c modifiers-nolibtool.c common-nolibtool.c buffer-nolibtool.c template-nolibtool.c pair-nolibtool.c
pmvarrun_LDFLAGS = -lz $(GLIB_LIBS)

if FLYN
check_SOURCES = check.c dotconf-nolibtool.c misc-nolibtool.c fmt_ptrn-nolibtool.c modifiers-nolibtool.c optlist-nolibtool.c common-nolibtool.c buffer-nolibtool.c template-nolibtool.c pair-nolibtool.c readconfig-nolibtool.c
check_INCLUDES = @CHECK_CFLAGS@
check_LDADD = @CHECK_LIBS@
check_LDFLAGS = -lz $(GLIB_LIBS)
endif

INCLUDES = -I$(srcdir)/../include

AM_CFLAGS = $(GLIB_CFLAGS) -DG_DISABLE_DEPRECATED -D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 -D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes -Winline -pipe

install-data-hook:
	( \
		cd $(DESTDIR)$(moduledir) && \
		$(LN_S) pam_mount.so pam_mount_auth.so && \
		$(LN_S) pam_mount.so pam_mount_session.so \
	)

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/pam_mount_auth.so
	rm -f $(DESTDIR)$(libdir)/pam_mount_session.so

if FLYN
# For local development use only.
lint:
	$(LINT)
endif
