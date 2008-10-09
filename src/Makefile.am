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
bin_PROGRAMS = pmt-fd0ssh pmt-ofl
sbin_PROGRAMS = pmt-ehd pmvarrun
ssbin_PROGRAMS = mount.crypt mount.encfs13 umount.crypt

pam_mount_la_SOURCES = loop.c misc.c ofl-lib.c pam_mount.c rdconf1.c rdconf2.c mount.c spawn.c
pam_mount_la_LIBADD  = -lpam ${libHX_LIBS} ${libcrypto_LIBS} ${libssl_LIBS} ${libxml_LIBS}
pam_mount_la_LDFLAGS = -module -avoid-version

mount_crypt_SOURCES   = mtcrypt.c nlt-loop.c nlt-misc.c nlt-spawn.c
mount_crypt_LDADD     = ${libHX_LIBS} ${libcrypto_LIBS} ${libssl_LIBS}

mount_encfs13_SOURCES = mtencfs13.c
mount_encfs13_LDADD   = ${libHX_LIBS}

pmt_ehd_SOURCES = ehd.c nlt-loop.c nlt-misc.c nlt-spawn.c
pmt_ehd_LDADD   = ${libHX_LIBS} ${libcrypto_LIBS} ${libssl_LIBS}

pmt_fd0ssh_SOURCES = fd0ssh.c

pmt_ofl_SOURCES = ofl.c nlt-ofl-lib.c
pmt_ofl_LDADD   = ${libHX_LIBS}

pmvarrun_SOURCES = pmvarrun.c nlt-misc.c
pmvarrun_LDADD   = ${libHX_LIBS}

AM_CFLAGS = ${regular_CFLAGS} ${GCC_FVISIBILITY_HIDDEN} ${libHX_CFLAGS} ${libxml_CFLAGS}

umount.crypt: mount.crypt
	-ln -s $^ $@;

install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_mount.la;
