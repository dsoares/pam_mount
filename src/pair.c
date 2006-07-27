/*=============================================================================
pair.c
  Copyright (C) W. Michael Putello <mike@flyn.org>, 1999 - 2000
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
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "pair.h"

/* ========================== pair_valid () =============================== */
gboolean pair_valid(const struct pair *p) {
    return (p == NULL || p->key == NULL || p->val == NULL) ? FALSE : TRUE;
}


/* ========================== pair_init () ================================== */
void pair_init(struct pair *pair, void *key, void *val,
	       void (*destroy_k)(void *), void (*destroy_v)(void *))
{
    pair->key = key;
    pair->val = val;
    pair->destroy_k = destroy_k;
    pair->destroy_v = destroy_v;
}

/*  pair_destroy
    @pair:      pair to destroy

    Destroy the pair pointed to by @pair.
    Note: This function is currently not called from anywhere.
*/
void pair_destroy(struct pair *pair) {
    if(pair->destroy_k != NULL)
        pair->destroy_k(pair->key);
    if(pair->destroy_v != NULL)
        pair->destroy_v(pair->val);

    memset(pair, 0, sizeof(struct pair));
    free(pair);
}

//=============================================================================
