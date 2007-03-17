/*=============================================================================
buffer.c
  Copyright (C) W. Michael Putello <mike@flyn.org>, 1999 - 2001
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
#include <assert.h>
#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "xstdlib.h"

/*  buffer_valid
    @b: buffer to check

    Verifies that the buffer structure is consistent.
*/
int buffer_valid(const struct buffer *b)
{
	int i;
	if(b == NULL)
		return 0;
	if((b->data == NULL) ^ (b->size == 0))
		return 0;
	if(b->data != NULL) {
		for(i = 0; i < b->size; i++) {
			if(b->data[i] == '\0')
				return 1;
		}
	}
	return 1;
}


/*  buffer_clear
    @b: buffer to clear

    Clears the contents of the buffer.
*/
void buffer_clear(struct buffer *buf)
{
	assert(buffer_valid(buf));

	if(buf->data != NULL) {
		free(buf->data);
 		buf->data = NULL;
	}
	buf->size = 0;

	assert(buffer_valid(buf));
	return;
}


/*  buffer_eat
    @buf:       buffer to edit
    @n:         characters to consume

    Removes the first @n characters off the beginning of the buffer.
*/
void buffer_eat(struct buffer *buf, size_t n)
{
	size_t z;

	assert(buffer_valid(buf));
	z = strlen(buf->data);
	if(n > z)
		n = z;
	/* +1 to copy the '\0' too */
	memmove(buf->data, buf->data + n, n + 1);
	assert(buffer_valid(buf));
	return;
}


/*  buffer_len
    @b: buffer to analyze

    Returns the string length of the buffer @b.
*/
size_t buffer_len(const struct buffer *buf)
{
	assert(buffer_valid(buf));
	return (buf->data == NULL) ? 0 : strlen(buf->data);
}


/*  realloc_n_cat
    @dest:      destination buffer
    @src:       source string

    Append @src to the buffer pointed to by @dest, necessarily reallocating
    @dest's buffer.
*/
void realloc_n_cat(struct buffer *dest, const char *src)
{
	size_t new_len;

	assert(buffer_valid(dest));
	assert(src != NULL);

	new_len = strlen(src) + ((dest != NULL && dest->data != NULL) ?
	                        strlen(dest->data) : 0);
	if(dest->data == NULL) {
		dest->size  = new_len * 2 + 1;
		dest->data  = xmalloc(dest->size);
		*dest->data = '\0';
	} else if(new_len + 1 > dest->size) {
		dest->size = new_len * 2 + 1;
		dest->data = xrealloc(dest->data, dest->size);
	}
	g_strlcat(dest->data, src, dest->size);

	assert(buffer_valid(dest));
	return;
}


/*  realloc_n_ncat
    @dest:      destination buffer
    @src:       source string
    @nc:        maximum length of string

    Append at most @nc characters from @src to the buffer pointed to by @dest,
    necessarily reallocating @dest's buffer.
*/
void realloc_n_ncat(struct buffer *dest, const char *src, const size_t nc)
{
	size_t src_len, new_len;

	assert(buffer_valid(dest));
	assert(src != NULL);

	src_len = strlen(src);
	new_len = ((dest != NULL && dest->data != NULL) ? strlen(dest->data) : 0) +
	          ((src_len < nc) ? src_len : nc);

	if(dest->data == NULL) {
		dest->size  = new_len * 2 + 1;
		dest->data  = xmalloc(dest->size);
		*dest->data = '\0';
	} else if(new_len + 1 > dest->size) {
		dest->size = new_len * 2 + 1;
		dest->data = xrealloc(dest->data, dest->size);
	}

	/*
	 * g_strlcat() will not work because there is no way to pass @nc. 
	 * HX_strlncat(dest->data, src, dest->size, nc) would be the ideal
	 * solution.
	 */
	strncat(dest->data, src, nc);
	dest->data[dest->size - 1] = '\0';

	assert(buffer_valid(dest));
	return;
}


/*  realloc_n_cpy
    @dest:      destination buffer
    @src:       source string

    Copies @src to the buffer pointed to by @dest, necessarily reallocating
    @dest's buffer.
*/
void realloc_n_cpy(struct buffer *dest, const char *src)
{
	assert(buffer_valid(dest));
	assert(src != NULL);

	if(dest->data != NULL)
		*dest->data = '\0';
	realloc_n_cat(dest, src);

	assert(buffer_valid(dest));
	return;
}
