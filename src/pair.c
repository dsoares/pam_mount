/*   FILE: pair.c
 * AUTHOR: W. Michael Petullo <mike@flyn.org>
 *   DATE: 19 February 2000
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

#include <new/pair.h>
#include <stdlib.h>
#include <string.h>

/* ========================== pair_t_valid () =============================== */
gboolean pair_t_valid(const pair_t *p)
{
    return (p == NULL || p->key == NULL || p->val == NULL) ? FALSE : TRUE;
}


/* ========================== pair_init () ================================== */
void pair_init(pair_t * pair, void *key, void *val,
	       void (*destroy_k)(void *), void (*destroy_v)(void *))
{
    pair->key = key;
    pair->val = val;
    pair->destroy_k = destroy_k;
    pair->destroy_v = destroy_v;
}

/* ========================== pair_destroy () =============================== */
void pair_destroy(void *vp) {
    pair_t *pair = vp;

    if(pair->destroy_k != NULL)
        pair->destroy_k(pair->key);
    if(pair->destroy_v != NULL)
        pair->destroy_v(pair->val);

    memset(pair, 0, sizeof(pair_t));
    g_free(pair);
}
