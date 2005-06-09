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
MINOR_VERSION=9
MICRO_VERSION=25
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

AM_CONDITIONAL(SYSTEM_LIBFMT_PTRN, false)
AH_TEMPLATE([USE_SYSTEM_FMT_PTRN],
            [Use system -lfmt_ptrn.])
# Use -lfmt_ptrn if it exists else compile locally (see also src/Makefile.am).
# ./include-fmt_ptrn should contain libfmt_ptrn's headers for use if
# -lfmt_ptrn does not exist.
AC_ARG_ENABLE(system-fmt_ptrn,
              AC_HELP_STRING([--enable-system-fmt_ptrn],
                             [use system -lfmt_ptrn]),
              AM_CONDITIONAL(SYSTEM_LIBFMT_PTRN, true), 
              LOCAL_FMT_PTRN_INCLUDES="-I\$(srcdir)/../include-fmt_ptrn")
AC_SUBST(LOCAL_FMT_PTRN_INCLUDES)

AC_CHECK_HEADER(security/pam_modules.h,[have_pamheader="yes"],)
# Mac OS X 10.3 puts PAM headers in /usr/include/pam.
AC_CHECK_HEADER(pam/pam_modules.h,[have_pamheader="yes"],)
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR(You are missing PAM headers)
fi

AM_PATH_CHECK(,[have_check="yes"],
  AC_MSG_WARN([Check not found; cannot run unit tests!])
      [have_check="no"])
          AM_CONDITIONAL(HAVE_CHECK, test x"$have_check" = "xyes")

case "$host" in
  *-*-linux*)
    # See also <configure-flags> in pam_mount.xml.
    PAM_MODDIR="\$(prefix)/../\$(libdir)/security"
    ;;
  *-*-darwin*)
    PAM_MODDIR="/usr/lib/pam"
    ;;
  *)
    PAM_MODDIR="/usr/lib"
    ;;
esac
AC_SUBST(PAM_MODDIR)

AC_OUTPUT(Makefile config/Makefile dry/Makefile debian/Makefile include/Makefile include-fmt_ptrn/Makefile include-fmt_ptrn/new/Makefile src/Makefile scripts/Makefile)
