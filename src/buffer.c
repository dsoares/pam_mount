/*=============================================================================
buffer.c
  Copyright (C) W. Michael Putello <mike@flyn.org>, 1999 - 2001
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
#include <assert.h>
#include <glib.h>
#include <string.h>
#include "buffer.h"

/* ============================ buffer_valid () ========================= */
gboolean buffer_valid(const struct buffer *b) {
	int i;
	if (b == NULL)
		return FALSE;
	if(b->data == NULL && b->size > 0)
		return FALSE;
	if(b->data != NULL && b->size == 0)
		return FALSE;
	if(b->data != NULL) {
		for (i = 0; i < b->size; i++) {
			if(b->data[i] == '\0')
				return TRUE;
		}
	}
	return TRUE;
}

/* ============================ buffer_clear () ============================ */
void buffer_clear(struct buffer *buf) {
    assert(buffer_valid(buf));

    if(buf->data != NULL) {
            g_free(buf->data);
 	    buf->data = NULL;
    }
    buf->size = 0;

    assert(buffer_valid(buf));
}

/* ============================ buffer_eat () ============================== */
void buffer_eat(struct buffer buf, size_t n) {
/* Eats n characters off the beginning of buffer. */
    char *p_1, *p_2;

    assert(buffer_valid(&buf));

    p_1 = buf.data;
    if(n > 0)
        for (p_2 = p_1 + n; p_2 <= p_1 + strlen(p_1); p_2++)
	    *p_1++ = *p_2;

    assert(buffer_valid(&buf));
}

/* ============================ buffer_len () ============================== */
size_t buffer_len(const struct buffer *buf) {
    assert(buffer_valid(buf));

    return (buf->data == NULL) ? 0 : strlen(buf->data);
}

/* ============================ realloc_n_cat () =========================== */
void realloc_n_cat(struct buffer *dest, const char *src) {
    size_t new_len;

    assert(buffer_valid(dest));
    assert(src != NULL);

    new_len = ((dest && dest->data) ? strlen(dest->data) : 0) + strlen(src);
    if(dest->data == NULL) {
	dest->size = new_len * 2 + 1;
	dest->data = g_new0(char, dest->size);
    } else if (new_len + 1 > dest->size) {
	dest->size = new_len * 2 + 1;
	dest->data = g_realloc(dest->data, dest->size);
    }
    g_strlcat(dest->data, src, dest->size);

    assert(buffer_valid(dest));
}

/* ============================ realloc_n_ncat () ========================= */
void realloc_n_ncat(struct buffer *dest, const char *src, const size_t nc) {
/* FIXME: this function is displaying memory corruption */
    size_t src_len, new_len;

    assert(buffer_valid(dest));
    assert(src != NULL);

    src_len = strlen(src);
    new_len = ((dest && dest->data) ? strlen(dest->data) : 0) +
              ((src_len < nc) ? src_len : nc);

    if(dest->data == NULL) {
	dest->size = new_len * 2 + 1;
	dest->data = g_new0(char, dest->size);
    } else if (new_len + 1 > dest->size) {
	dest->size = new_len * 2 + 1;
	dest->data = g_realloc(dest->data, dest->size);
    }
    /* g_strlcat will not work because its nc is the size of dest */
    strncat(dest->data, src, nc);
    // g_strlcat(dest->data, src, dest->size); // voilà
    dest->data[dest->size - 1] = '\0';

    assert(buffer_valid(dest));
}

/* ============================ realloc_n_cpy () =========================== */
void realloc_n_cpy(struct buffer *dest, const char *src) {
    assert(buffer_valid(dest));
    assert(src != NULL);

    if(dest->data != NULL)
	*dest->data = '\0';
    realloc_n_cat(dest, src);

    assert(buffer_valid(dest));
}
