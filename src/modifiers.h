/*=============================================================================
modifiers.h
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
#ifndef PMT_MODIFIERS_H
#define PMT_MODIFIERS_H 1

#include "fmt_ptrn.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MODIFIER_ARG_LEN 80

struct buffer;

struct modifier_info {
    char *id;
    int (*fn)(struct buffer *, struct fmt_ptrn *, char *);
    int has_arg;
};

struct modifier {
    struct modifier_info fn;
    char arg[MODIFIER_ARG_LEN + 1];
};

extern const struct modifier_info mod_fn[];

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MODIFIERS_H

//=============================================================================
