/*   FILE: pair.h -- 
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

#ifndef _PAIR_H
#define _PAIR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/* ========================== pair_t ======================================== */ typedef struct pair_t {
	void *key;
	void *val;
	void (*destroy_k) (void *k);
	void (*destroy_v) (void *v);
    } pair_t;

/* ========================== pair_init () ================================== */
    void pair_init(pair_t * pair, void *key, void *val,
		   void (*destroy_k) (void *key), void (*destroy_v) (void *val));

/* ========================== pair_destroy () =============================== */
    void pair_destroy(void * pair);

/* ========================== pair_t_valid () =============================== */
    gboolean pair_t_valid(const pair_t *p);

#ifdef __cplusplus
}
#endif
#endif				/* _PAIR_H */
