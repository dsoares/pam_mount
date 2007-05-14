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

AC_INIT(pam_mount, 0.18)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE

AC_ARG_WITH([slibdir], AS_HELP_STRING([--with-slibdir=PATH],
    [Path to the super lib directory [[/lib]]]),
    [slibdir="$withval"], [slibdir="/lib"])
AC_SUBST(slibdir)

AC_PROG_CC

m4_sinclude(m4lib/gcc4_visibility.m4)
AC_PROG_INSTALL
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_LN_S
AM_PATH_GLIB_2_0(,,AC_MSG_ERROR(You are missing glib))
AM_PATH_XML2(,,AC_MSG_ERROR(You are missing libxml2))

AM_CONDITIONAL(FLYN, test "$FLYN")

AC_CHECK_LIB(crypto, EVP_DecryptInit_ex) # RH 8.0's OpenSSL does not have?
AC_CHECK_LIB(ssl, SSL_load_error_strings)
AC_CHECK_FUNCS(setfsuid)

AC_CHECK_MEMBERS([struct loop_info64.lo_file_name], [], [],
	[#include <linux/loop.h>])

AC_CHECK_HEADER(security/pam_modules.h,[have_pamheader="yes"],)
# Mac OS X 10.3 puts PAM headers in /usr/include/pam.
AC_CHECK_HEADER(pam/pam_modules.h,[have_pamheader="yes"],)
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR(You are missing PAM headers)
fi

case "$host" in
  *-*-linux*)
    # See also <configure-flags> in pam_mount.xml.
    PAM_MODDIR="\$(slibdir)/security"
    ;;
  *-*-darwin*)
    PAM_MODDIR="/usr/lib/pam"
    ;;
  *)
    PAM_MODDIR="/usr/lib"
    ;;
esac
AC_SUBST(PAM_MODDIR)

AC_OUTPUT(Makefile config/Makefile dry/Makefile src/Makefile scripts/Makefile)
