#   FILE: configure.in -- 
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

AC_INIT(src/pam_mount.c)

AM_CONFIG_HEADER(config.h)

MAJOR_VERSION=0
MINOR_VERSION=12
MICRO_VERSION=0
AM_INIT_AUTOMAKE(pam_mount, $MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION)

VER_INFO=`expr $MINOR_VERSION + $MAJOR_VERSION`:$MICRO_VERSION:$MINOR_VERSION

AC_SUBST(MAJOR_VERSION)
AC_SUBST(MINOR_VERSION)
AC_SUBST(MICRO_VERSION)
AC_SUBST(VER_INFO)

AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_LIBTOOL
AC_PROG_LN_S
AM_PATH_GLIB_2_0(,,AC_MSG_ERROR(You are missing glib))

AM_CONDITIONAL(FLYN, test "$FLYN")

AC_CHECK_LIB(crypto, EVP_DecryptInit_ex) # RH 8.0's OpenSSL does not have?
AC_CHECK_LIB(ssl, SSL_load_error_strings)
AC_CHECK_FUNCS(setfsuid)

AC_CHECK_HEADER(security/pam_modules.h,[have_pamheader="yes"],)
# Mac OS X 10.3 puts PAM headers in /usr/include/pam.
AC_CHECK_HEADER(pam/pam_modules.h,[have_pamheader="yes"],)
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR(You are missing PAM headers)
fi

#AM_PATH_CHECK(,[have_check="yes"],
#  AC_MSG_WARN([Check not found; cannot run unit tests!])
#      [have_check="no"])
#          AM_CONDITIONAL(HAVE_CHECK, test x"$have_check" = "xyes")

case "$host" in
  *-*-linux*)
    # See also <configure-flags> in pam_mount.xml.
    PAM_MODDIR="/\$(libdir)/security"
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
