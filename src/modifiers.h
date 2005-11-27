/*=============================================================================
modifiers.h
  Copyright © Jan Engelhardt <jengelh [at] linux01 gwdg de>, 2005

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

#ifdef __cplusplus
extern "C" {
#endif

#include "buffer.h"
#include "fmt_ptrn.h"

#define MODIFIER_ARG_LEN 80

typedef struct modifier_fns_t {
    char *id;
    int (*fn)(buffer_t *, fmt_ptrn_t *, char *);
    int has_arg;
} modifier_fns_t;

typedef struct modifier_t {
    modifier_fns_t fn;
    char arg[MODIFIER_ARG_LEN + 1];
} modifier_t;

extern const modifier_fns_t mod_fn[];

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MODIFIERS_H

//=============================================================================
