#   FILE: configure.ac --
# AUTHOR: W. Michael Petullo <mike@flyn.org>
#   DATE: 03 August 2002
#
# Copyright (C) 2002 W. Michael Petullo <mike@flyn.org>
# Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2007
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

AC_INIT(pam_mount, 0.20)
AC_CONFIG_HEADERS(config.h)
AC_PROG_INSTALL
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AM_PATH_GLIB_2_0(,,AC_MSG_ERROR(You are missing glib))
AM_PATH_XML2(,,AC_MSG_ERROR(You are missing libxml2))

AC_ARG_WITH([slibdir], AS_HELP_STRING([--with-slibdir=PATH],
	[Path to the super lib directory [[/lib]]]),
	[slibdir="$withval"], [slibdir="/lib"])
AC_SUBST(slibdir)
AC_ARG_WITH([ssbindir], AS_HELP_STRING([--with-ssbindir=PATH],
	[Path to the super sbin directory [[/sbin]]]),
	[ssbindir="$withval"], [ssbindir="/sbin"])
AC_SUBST(ssbindir)

m4_sinclude(m4lib/gcc4_visibility.m4)
AC_CHECK_LIB(crypto, EVP_DecryptInit_ex) # RH 8.0's OpenSSL does not have?
AC_CHECK_LIB(ssl, SSL_load_error_strings)

regular_CFLAGS="-D_LARGEFILE_SOURCE=1 -D_LARGE_FILES -D_FILE_OFFSET_BITS=64 \
	-D_REENTRANT -Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes \
	-Winline -pipe"
AC_SUBST(regular_CFLAGS)

AC_CHECK_MEMBERS([struct loop_info64.lo_file_name], [], [],
	[#include <linux/loop.h>])

AC_CHECK_HEADER([libHX.h], [],
	AC_MSG_ERROR([Need at least libHX 1.10 (http://jengelh.hopto.org/p/libHX/)]),
	[
#include <libHX.h>
#if !defined(_LIBHX_H) || _LIBHX_H < 20070701
#	error You need a newer version of libHX (at least 1.10.0)
#endif
])
AC_CHECK_HEADER(security/pam_modules.h, [have_pamheader="yes"])
# Mac OS X 10.3 puts PAM headers in /usr/include/pam.
AC_CHECK_HEADER(pam/pam_modules.h, [have_pamheader="yes"])
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR([You are missing PAM headers])
fi

case "$host" in
    (*-*-linux*)
	PAM_MODDIR='${slibdir}/security'
	;;
    (*-*-darwin*)
	PAM_MODDIR="/usr/lib/pam"
	;;
    (*)
	PAM_MODDIR="/usr/lib"
	;;
esac
AC_SUBST(PAM_MODDIR)

AC_OUTPUT([Makefile dry/Makefile src/Makefile scripts/Makefile])
