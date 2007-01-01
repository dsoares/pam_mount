/*=============================================================================
modifiers.c
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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "buffer.h"
#include "modifiers.h"
#include "fmt_ptrn.h"
#include "template.h"
#include "xstdlib.h"

// Definitions
typedef int (apply_fn_t)(struct buffer *, struct fmt_ptrn *, char *);

// Functions
static apply_fn_t
    apply_after, apply_basename, apply_before, apply_lower, apply_newlines,
    apply_no_newlines, apply_remove_underscore, apply_upper;

// Variables
const struct modifier_info mod_fn[] = {
    {"upper",             apply_upper,             0},
    {"lower",             apply_lower,             0},
    {"basename",          apply_basename,          0},
    {"before=\"",         apply_before,            1},
    {"after=\"",          apply_after,             1},
    {"newlines",          apply_newlines,          0},
    {"no_newlines",       apply_no_newlines,       0},
    /* FIXME: The following is handled as a special case. */
    {"#",                 NULL,                    0},
    {"remove_underscore", apply_remove_underscore, 0},
    {NULL, NULL, 0},
};

//-----------------------------------------------------------------------------
static int apply_upper(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    int n;
    for(n = 0; n < strlen(dest->data); ++n)
        dest->data[n] = toupper(dest->data[n]);
    return 1;
}

static int apply_lower(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    int n;
    for(n = 0; n < strlen(dest->data); ++n)
        dest->data[n] = tolower(dest->data[n]);
    return 1;
}

static int apply_basename(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    char *ptr = strchr(dest->data, '.');
    if(ptr != NULL)
	*ptr = '\0';
    return 1;
}

static int apply_before(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    /* Done with no malloc'd tmp. */
    size_t i, j, old_len = strlen(dest->data), src_len =
	strlen(arg), new_len = old_len + src_len;
    /* FIXME: use proper buffer interface! */
    if (new_len + 1 > dest->size) {
	dest->size = new_len + 1;
	dest->data = xrealloc(dest->data, dest->size);
    }
    /* Shift dest over to make room for arg. */
    if (old_len > 0)
    /* i is unsigned, so i = old_len - 1 makes no sense if old_len == 0 */
        for (i = old_len - 1, j = new_len - 1; i > 0; i--, j--)
	    dest->data[j] = dest->data[i];
    dest->data[src_len] = dest->data[0];
    dest->data[new_len] = '\0';
    /* Copy arg into dest. */
    for (i = 0; i < src_len; i++)
	dest->data[i] = arg[i];
    return 1;
}

static int apply_no_newlines(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == '\n')
	    dest->data[i] = ' ';
    return 1;
}

static int apply_newlines(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == ' ')
	    dest->data[i] = '\n';
    return 1;
}

static int apply_remove_underscore(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == '_')
	    dest->data[i] = '-';
    return 1;
}

static int apply_after(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    /* Too easy. */
    realloc_n_cat(dest, arg);
    return 1;
}

//=============================================================================
