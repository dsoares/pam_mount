/*=============================================================================
buffer.h
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
#ifndef PMT_BUFFER_H
#define PMT_BUFFER_H 1

#include <sys/types.h>
#include <glib.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct buffer {
    char *data;
    size_t size;
} buffer_t;

/*
 *      BUFFER.C
 */
extern void buffer_clear(buffer_t *);
extern void buffer_eat(buffer_t, size_t);
extern size_t buffer_len(const buffer_t *);
extern gboolean buffer_t_valid(const buffer_t *);
extern void realloc_n_cat(buffer_t *, const char *);
extern void realloc_n_cpy(buffer_t *, const char *);
extern void realloc_n_ncat(buffer_t *, const char *, size_t);

/*
 *      INLINE FUNCTIONS
 */
static inline void buffer_init(buffer_t *x) {
    x->size = 0;
    x->data = NULL;
    return;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_BUFFER_H

//=============================================================================
