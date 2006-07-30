/*=============================================================================
xstdlib.c
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2006

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
#include "xstdlib.h"

//-----------------------------------------------------------------------------
/*  xmalloc
    @n: size of the new buffer

    Wrapper around malloc() that warns when no new memory block could be
    obtained.
*/
void *xmalloc(size_t n) {
    void *ret;
    if((ret = malloc(n)) == NULL)
        l0g(PMPREFIX "xmalloc: Could not allocate %lu bytes\n",
            static_cast(unsigned long, n));
    return ret;
}


/*  xrealloc
    @orig:      original address of the buffer
    @n:         new size of the buffer

    Wrapper around realloc() that warns when no new memory block could be
    obtained.
*/
void *xrealloc(void *orig, size_t n) {
    void *ret;
    if((ret = realloc(orig, n)) == NULL)
        l0g(PMPREFIX "xrealloc: Could not reallocate to %lu bytes\n",
            static_cast(unsigned long, n));
    return ret;
}


/*  xzalloc
    @n: bytes to allocate

    Allocates @n bytes and clears them if the allocation succeded. Returns
    the pointer to the newly allocated memory if any, or %NULL on failure.
*/
void *xzalloc(size_t n) {
    void *ret;
    if((ret = xmalloc(n)) != NULL)
        memset(ret, 0, n);
    return ret;
}

//=============================================================================
