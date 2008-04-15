/*=============================================================================
pam_mount - xstdlib.c
  Copyright © CC Computer Consultants GmbH, 2006 - 2007
  Contact: Jan Engelhardt <jengelh [at] computergmbh de>

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "compiler.h"
#include "misc.h"
#include "private.h"
#include "xstdlib.h"

/*
 * xmalloc - allocate memory
 * @n:	size of the new buffer
 *
 * Wrapper around malloc() that warns when no new memory block could be
 * obtained.
 */
void *xmalloc(size_t n)
{
	void *ret;
	if ((ret = malloc(n)) == NULL)
		l0g("%s: Could not allocate %lu bytes\n",
		    __func__, static_cast(unsigned long, n));
	return ret;
}

/*
 * xrealloc - resize memory block
 * @orig:	original address of the buffer
 * @n:		new size of the buffer
 *
 * Wrapper around realloc() that warns when no new memory block could be
 * obtained.
 */
void *xrealloc(void *orig, size_t n)
{
	void *ret;
	if ((ret = realloc(orig, n)) == NULL)
		l0g("%s: Could not reallocate to %lu bytes\n",
		    __func__, static_cast(unsigned long, n));
	return ret;
}

/*
 * xstrdup -
 * @src:	source string
 *
 * Basically just the usual strdup(), but with error reporting to fprintf()
 * should allocation fail.
 */
char *xstrdup(const char *src)
{
	char *ret = HX_strdup(src);
	if (ret == NULL)
		l0g("%s: Could not allocate %lu bytes\n",
		    __func__, strlen(src));
	return ret;
}
