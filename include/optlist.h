/*   FILE: optlist.h
 * AUTHOR: W. Michael Petullo <mike@flyn.org>
 *   DATE: 2003
 *
 * Copyright (C) 2003 W. Michael Petullo <mike@flyn.org>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _OPTLIST_H
#define _OPTLIST_H

#include <glib.h>
#include <new/pair.h>

typedef GList optlist_t;

/* ============================ str_to_optlist () ========================== */
int str_to_optlist(optlist_t ** optlist, const char *str);

/* ============================ optlist_exists () ========================== */
int optlist_exists(optlist_t * optlist, const char *str);

/* ============================ optlist_value () =========================== */
const char * optlist_value(optlist_t * optlist, const char *str);

/* ============================ optlist_to_str () ========================== */
char *optlist_to_str(char *str, const optlist_t * optlist);

/* ============================ optlist_len () ============================= */
#define optlist_len(list) g_list_length(list)

/* ============================ optlist_key () ============================= */
#define optlist_key(element) ((pair_t *) (element)->data)->key

/* ============================ optlist_val () ============================= */
#define optlist_val(element) ((pair_t *) (element)->data)->val

/* ============================ optlist_next () ============================ */
#define optlist_next(element) g_list_next(element)

#endif				/* _OPTLIST_H */
