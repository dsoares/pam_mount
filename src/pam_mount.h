/*=============================================================================
pam_mount.h
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2007

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to:
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
  Boston, MA  02110-1301  USA

  -- For details, see the file named "LICENSE.LGPL2"
=============================================================================*/
#ifndef PMT_PAM_MOUNT_H
#define PMT_PAM_MOUNT_H 1

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct config;
struct pam_args;

enum auth_type {
    GET_PASS,
    USE_FIRST_PASS,
    TRY_FIRST_PASS
};

struct pam_args {
    enum auth_type auth_type;
};

/*
 *      PAM_MOUNT.C
 */
#if defined(__GNUC__) && __GNUC__ < 4
#    define Debug pmt_debug
#endif
extern int Debug;
extern struct config Config;
extern struct pam_args Args;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_PAM_MOUNT_H

//=============================================================================
