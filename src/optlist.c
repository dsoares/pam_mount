/*   FILE: optlist.c
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

#include <optlist.h>
#include <stdlib.h>
#include <pam_mount.h>
#include <assert.h>
#include <string.h>

/* ============================ _parse_string_opt () ======================= */
/* INPUT: str, string to parse
 *        len, should be length up to first ',' or 0x00
 * SIDE AFFECTS: str[0 - len] has been parsed and placed in optlist
 * OUTPUT: if error 0 else 1
 */
static int _parse_string_opt(const char *str, size_t len,
			     optlist_t ** optlist)
{
	pair_t *pair;
	char *delim , *key, *val;

	assert(str);
	assert(len >= 0 && len <= strlen(str));

	delim = strchr(str, '=');
	if (!delim)
		return 0;
	if (len > MAX_PAR || len <= 0)
		return 0;
	if (!delim || delim - str >= len)
		return 0;
	pair = (pair_t *) malloc(sizeof(pair_t));
	key = (char *) malloc(sizeof(char) * (delim - str) + 1);
	val = (char *) malloc(sizeof(char) * len - (delim - str)); /* '=' is +1 */
	if (!pair || !key || !val)
		return 0;
	strncpy(key, str, delim - str);
	key[delim - str] = 0x00;
	strncpy(val, delim + 1, len - (delim - str) - 1);
	val[len - (delim - str) - 1] = 0x00;
	pair_init(pair, key, val, free, free);
	*optlist = g_list_append(*optlist, pair);
	return 1;
}

/* ============================ _parse_opt () ============================== */
/* INPUT: str, string to parse
 *        len, should be length up to first ',' or 0x00
 * SIDE AFFECTS: str[0 - len] has been parsed and placed in optlist
 * OUTPUT: if error 0 else 1
 */
static int _parse_opt(const char *str, size_t len, optlist_t ** optlist)
{
	pair_t *pair;
	char *key, *val;

	assert(str);
	assert(len >= 0 && len <= strlen(str));

	if (len > MAX_PAR)
		return 0;
	pair = (pair_t *) malloc(sizeof(pair_t));
	key = malloc(sizeof(char) * len + 1);
	val = malloc(1);
	if (!pair || !key || !val)
		return 0;
	strncpy(key, str, len);
	key[len] = 0x00;
	*val = 0x00;
	pair_init(pair, key, val, free, free);
	*optlist = g_list_append(*optlist, pair);
	return 1;
}

/* ============================ str_to_optlist () ========================== */
/* INPUT: str, string to parse
 * SIDE AFFECTS: str has been parsed and placed in optlist
 * OUTPUT: if error 0 else 1
 */
int str_to_optlist(optlist_t ** optlist, const char *str)
{
	char *ptr;

	assert(str);

	*optlist = NULL;
	if (!strlen(str))
		return 1;
	while (ptr = strchr(str, ',')) {
		if (!_parse_string_opt(str, ptr - str, optlist))
			if (!_parse_opt(str, ptr - str, optlist))
				return 0;
		str = ptr + 1;
	}
	if (!_parse_string_opt(str, strlen(str), optlist))
		if (!_parse_opt(str, strlen(str), optlist))
			return 0;
	return 1;
}

/* ============================ _compare () ================================ */ 
/* INPUT: x and y
 * OUTPUT: if x->key is the same string as y then 0, else non-0
 */
static int _compare(gconstpointer x, gconstpointer y)
{
	assert(x);
	assert(((pair_t *)x)->key);
	assert(y);

	return strcmp(((pair_t *)x)->key, y);
}

/* ============================ optlist_exists () ========================== */
/* INPUT: optlist and str
 * OUTPUT: if optlist[str] exists 1 else 0
 */
int optlist_exists(optlist_t * optlist, const char *str)
{
	assert(str);

	if (!optlist)
		return 0;
	return g_list_find_custom(optlist, str, _compare) ? 1 : 0;
}

/* ============================ optlist_value () =========================== */
/* INPUT: optlist and str
 * OUTPUT: optlist[str] ("" if no value) else NULL
 */
char *optlist_value(optlist_t * optlist, const char *str)
{
	GList *ptr;

	assert(str);

	if (!optlist)
		return NULL;
	ptr = g_list_find_custom(optlist, str, _compare);
	return ptr ? ((pair_t *)ptr->data)->val : NULL;
}

/* ============================ optlist_to_str () ========================== */
/* INPUT: str and optlist
 *        sizeof str >= MAX_PAR + 1
 * OUTPUT: string encapsulating optlist
 */
char *optlist_to_str(char *str, const optlist_t * optlist)
{
	const optlist_t *ptr = optlist;

	assert(str);

	*str = 0x00;
	if (!optlist)
		return str;
	do {
		strncat(str, ((pair_t *) ptr->data)->key,
			MAX_PAR - strlen(str));
		if (strlen(((pair_t *) ptr->data)->val)) {
			strncat(str, "=", MAX_PAR - strlen(str));
			strncat(str, ((pair_t *) ptr->data)->val,
				MAX_PAR - strlen(str));
		}
		if (ptr = g_list_next(ptr))
			strncat(str, ",", MAX_PAR - strlen(str));
	} while (ptr);
	str[MAX_PAR] = 0x00;
	return str;
}
