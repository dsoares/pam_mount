/*   FILE: buffer.c -- 
 * AUTHOR: W. Michael Petullo <mike@flyn.org>
 *   DATE: 26 December 2001
 *
 * Copyright (c) 1999 W. Michael Petullo <mike@flyn.org>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <assert.h>
#include <glib.h>
#include <new/buffer.h>
#include <string.h>

/* ============================ buffer_t_valid () ========================= */
gboolean buffer_t_valid(const buffer_t *b)
{
	int i;
	if (b == NULL)
		return FALSE;
	if (b->data == 0x00 && b->size > 0)
		return FALSE;
	if (b->data != 0x00 && b->size == 0)
		return FALSE;
	if (b->data != 0x00) {
		for (i = 0; i < b->size; i++) {
			if (b->data[i] == 0x00)
				return TRUE;
		}
	} else
		return TRUE;
	return FALSE;
}

/* ============================ buffer_clear () ============================ */
void buffer_clear(buffer_t *buf)
{
    assert(buffer_t_valid(buf));

    if (buf->data != 0x00) {
            g_free(buf->data);
 	    buf->data = 0x00;
    }
    buf->size = 0;

    assert(buffer_t_valid(buf));
}

/* ============================ buffer_init () ============================= */
buffer_t buffer_init(void)
{
    buffer_t x;

    x.data = 0x00;
    x.size = 0;

    assert(buffer_t_valid(&x));

    return x;
}

/* ============================ buffer_destroy () ========================== */
void buffer_destroy(buffer_t b)
{
    /* FIXME: this function may need to be combined with buffer_clear() */
    assert(buffer_t_valid(&b));

    buffer_clear(&b);
}

/* ============================ buffer_eat () ============================== */
void buffer_eat(buffer_t buf, size_t n)
/* Eats n characters off the beginning of buffer. */
{
    char *p_1, *p_2;

    assert(buffer_t_valid(&buf));

    p_1 = buf.data;
    if (n)
        for (p_2 = p_1 + n; p_2 <= p_1 + strlen(p_1); p_2++)
	    *p_1++ = *p_2;

    assert(buffer_t_valid(&buf));
}

/* ============================ buffer_len () ============================== */
size_t buffer_len(buffer_t *buf)
{
    assert(buffer_t_valid(buf));

    if (buf->data == 0x00)
        return 0;
    else
        return (strlen(buf->data));
}

/* ============================ realloc_n_cat () =========================== */
void realloc_n_cat(buffer_t * dest, const char *src)
{
    size_t new_len;

    assert(buffer_t_valid(dest));
    assert(src != NULL);

    new_len = (dest && dest->data ? strlen(dest->data) : 0) + strlen(src);
    if (dest->data == 0x00) {
	dest->size = new_len * 2 + 1;
	dest->data = g_new0(char, dest->size);
    } else if (new_len + 1 > dest->size) {
	dest->size = new_len * 2 + 1;
	dest->data = g_realloc(dest->data, sizeof(char) * dest->size);
    }
    g_strlcat(dest->data, src, dest->size);

    assert(buffer_t_valid(dest));
}

/* ============================ realloc_n_ncat () ========================= */
void realloc_n_ncat(buffer_t * dest, const char *src,
			    const size_t nc)
{
/* FIXME: this function is displaying memory corruption */
    size_t src_len, new_len;

    assert(buffer_t_valid(dest));
    assert(src != NULL);

    src_len = strlen(src);
    new_len = (dest && dest->data ? strlen(dest->data) : 0) + (src_len <
							 nc ? src_len :
							 nc);
    if (dest->data == 0x00) {
	dest->size = new_len * 2 + 1;
	dest->data = g_new0(char, dest->size);
    } else if (new_len + 1 > dest->size) {
	dest->size = new_len * 2 + 1;
	dest->data = g_realloc(dest->data, sizeof(char) * dest->size);
    }
    /* g_strlcat will not work because its nc is the size of dest */
    strncat(dest->data, src, nc);
    dest->data[dest->size - 1] = 0x00;

    assert(buffer_t_valid(dest));
}

/* ============================ realloc_n_cpy () =========================== */
void realloc_n_cpy(buffer_t * dest, const char *src)
{
    assert(buffer_t_valid(dest));
    assert(src != NULL);

    if (dest->data)
	*dest->data = 0x00;
    realloc_n_cat(dest, src);

    assert(buffer_t_valid(dest));
}
