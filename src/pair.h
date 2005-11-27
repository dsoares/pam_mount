/*=============================================================================
pair.h
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
#ifndef PMT_PAIR_H
#define PMT_PAIR_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

typedef struct pair_t {
    void *key;
    void *val;
    void (*destroy_k)(void *);
    void (*destroy_v)(void *);
} pair_t;

extern void pair_destroy(pair_t *);
extern void pair_init(pair_t *, void *, void *,
    void (*)(void *), void (*)(void *));
extern gboolean pair_t_valid(const pair_t *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_PAIR_H

//=============================================================================
