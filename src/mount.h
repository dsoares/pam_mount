/*=============================================================================
mount.h
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2006

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
#ifndef PMT_MOUNT_H
#define PMT_MONUT_H 1

#include "fmt_ptrn.h"
#include "private.h"
#include "xstdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

struct config;
struct fmt_ptrn;

typedef int (mount_op_fn_t)(const struct config *, const unsigned int,
    struct fmt_ptrn *, const char *, const bool);

/*
 *      MOUNT.C
 */
extern mount_op_fn_t do_mount, do_unmount;
extern int mount_op(mount_op_fn_t *, const struct config *, const unsigned int,
    const char *, const int);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MOUNT_H

//=============================================================================
