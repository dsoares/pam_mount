/*   FILE: buffer.h -- 
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

#ifndef _BUFFER_H
#define _BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <new/sizes.h>

/* ============================ buffer_t =================================== */
typedef struct buffer_t {
	char *data;
	size_t size;
} buffer_t;

/* ============================ buffer_init () ============================= */
buffer_t buffer_init(void);

/* ============================ _buffer_destroy () ========================= */
void buffer_destroy(buffer_t b);

/* ============================ buffer_eat () ============================== */
void buffer_eat(buffer_t buf, size_t n);

/* ============================ buffer_len () ============================== */
size_t buffer_len(buffer_t buf);

/* ============================ realloc_n_cat () =========================== */
void realloc_n_cat(buffer_t * dest, const char *src);

/* ============================ realloc_n_cpy () =========================== */
void realloc_n_cpy(buffer_t * dest, const char *src);

/* ============================ realloc_n_ncat () ========================= */
void realloc_n_ncat(buffer_t * dest, const char *src,
			    const size_t nc);

#endif /* _BUFFER_H */
