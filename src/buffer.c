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

#include <glib.h>
#include <new/buffer.h>
#include <string.h>

/* ============================ buffer_init () ============================= */
buffer_t buffer_init(void)
{
    buffer_t x;
    x.data = g_new0(char, INIT_BUF_SIZE);
    x.size = INIT_BUF_SIZE;
    return x;
}

/* ============================ buffer_destroy () ========================== */
void buffer_destroy(buffer_t b)
{
    g_free(b.data);
    b.data = NULL;
    b.size = 0;
}

/* ============================ buffer_eat () ============================== */
void buffer_eat(buffer_t buf, size_t n)
/* Eats n characters off the beginning of buffer. */
{
    char *p_1 = buf.data, *p_2;
    if (!n)
	return;
    for (p_2 = p_1 + n; p_2 <= p_1 + strlen(p_1); p_2++)
	*p_1++ = *p_2;
}

/* ============================ buffer_len () ============================== */
size_t buffer_len(buffer_t buf)
{
    return (buf.size - 1);
}

/* ============================ realloc_n_cat () =========================== */
void realloc_n_cat(buffer_t * dest, const char *src)
{
    size_t new_len = (dest
		      && dest->data ? strlen(dest->data) : 0) +
	strlen(src);
    if (!dest->data) {
	dest->size = new_len * 2 + 1;
	dest->data = g_new0(char, dest->size);
	*dest->data = 0x00;
    } else if (new_len + 1 > dest->size) {
	dest->size = new_len * 2 + 1;
	dest->data = g_realloc(dest->data, sizeof(char) * dest->size);
    }
    g_strlcat(dest->data, src, dest->size);
}

/* ============================ realloc_n_cpy () =========================== */
void realloc_n_cpy(buffer_t * dest, const char *src)
{
    if (dest->data)
	*dest->data = 0x00;
    realloc_n_cat(dest, src);
}

/* ============================ realloc_n_ncat () ========================= */
void realloc_n_ncat(buffer_t * dest, const char *src,
			    const size_t nc)
{
    size_t src_len = strlen(src);
    size_t new_len =
	(dest && dest->data ? strlen(dest->data) : 0) + (src_len <
							 nc ? src_len :
							 nc);
    if (new_len + 1 > dest->size) {
	dest->size = new_len * 2 + 1;
	dest->data = g_realloc(dest->data, sizeof(char) * dest->size);
    }
    /* g_strlcat will not work because its nc is the size of dest */
    strncat(dest->data, src, nc);
}
