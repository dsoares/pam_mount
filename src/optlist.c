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

static int _parse_string_opt(const char *str, size_t, optlist_t **);
static int _parse_opt(const char *, size_t, optlist_t **);
static int _compare(gconstpointer, gconstpointer);

/* ============================ _parse_string_opt () ======================= */
/* INPUT: str, string to parse
 *        len, should be length up to first ',' or terminating '\0'
 * SIDE EFFECTS: str[0 - len] has been parsed and placed in optlist
 * OUTPUT: if error 0 else 1
 */
static int _parse_string_opt(const char *str, size_t len,
			     optlist_t ** optlist)
{
	int ret = 1;
	pair_t *pair;
	char *delim, *key, *val;

	assert(str);
	/* a user could config "loop,,,foo=bar==..." */
	if (len <= 0 || len > MAX_PAR) {
		ret = 0;
		goto _return;
	}
	assert(len > 0 && len <= strlen(str) && len <= MAX_PAR);
	assert(optlist);

	delim = strchr(str, '=');
	if (!delim || delim - str >= len) {
		ret = 0;
		goto _return;
	}
	pair = g_new0(pair_t, 1);
	key = g_new0(char, delim - str + 1);
	val = g_new0(char, len - (delim - str));	/* '=' is +1 */
	strncpy(key, str, delim - str);
	key[delim - str] = '\0';
	strncpy(val, delim + 1, len - (delim - str) - 1);
	val[len - (delim - str) - 1] = '\0';
	pair_init(pair, key, val, g_free, g_free);
	*optlist = g_list_append(*optlist, pair);
      _return:

	assert(!ret || (optlist_exists(*optlist, key)
			&& strcmp(optlist_value(*optlist, key), val) == 0));

	return ret;
}

/* ============================ _parse_opt () ============================== */
/* INPUT: str, string to parse
 *        len, should be length up to first ',' or terminating '\0'
 * SIDE EFFECTS: str[0 - len] has been parsed and placed in optlist
 * OUTPUT: if error 0 else 1
 */
static int _parse_opt(const char *str, size_t len, optlist_t ** optlist)
{
	int ret = 1;
	pair_t *pair;
	char *key, *val;

	assert(str);
	/* a user could config "loop,,,foo=bar==..." */
	if (len <= 0 || len > MAX_PAR) {
		ret = 0;
		goto _return;
	}
	assert(len > 0 && len <= strlen(str) && len <= MAX_PAR);
	assert(optlist);

	pair = g_new0(pair_t, 1);
	key = g_new0(char, len + 1);
	val = g_new0(char, 1);
	strncpy(key, str, len);
	key[len] = '\0';
	*val = '\0';
	pair_init(pair, key, val, g_free, g_free);
	*optlist = g_list_append(*optlist, pair);
      _return:

	assert(!ret || (optlist_exists(*optlist, key)
			&& !strcmp(optlist_value(*optlist, key), val)));

	return ret;
}

/* ============================ str_to_optlist () ========================== */
/* INPUT: str, string to parse
 * SIDE EFFECTS: str has been parsed and placed in optlist
 * OUTPUT: if error 0 else 1
 */
gboolean str_to_optlist(optlist_t ** optlist, const char *str)
{
	int ret = 1;
	char *ptr;

	assert(optlist);
	assert(str);

	*optlist = NULL;
	if(strlen(str) == 0) {
		ret = 0;
		goto _return;
	}
	while ((ptr = strchr(str, ',')) != NULL) {
		if (!_parse_string_opt(str, ptr - str, optlist))
			if (!_parse_opt(str, ptr - str, optlist)) {
				ret = 0;
				goto _return;
			}
		str = ptr + 1;
	}
	if (!_parse_string_opt(str, strlen(str), optlist))
		if (!_parse_opt(str, strlen(str), optlist)) {
			ret = 0;
			goto _return;
		}
      _return:

	assert(!ret || ((strlen(str) == 0 && !*optlist) || *optlist));

	return ret;
}

/* ============================ _compare () ================================ */
/* INPUT: x and y
 * OUTPUT: if x->key is the same string as y then 0, else non-0
 */
static int _compare(gconstpointer x, gconstpointer y)
{
	assert(x);
	assert(((pair_t *) x)->key);
	assert(y);

	return strcmp(((pair_t *) x)->key, y);
}

/* ============================ optlist_exists () ========================== */
/* INPUT: optlist and str
 * OUTPUT: if optlist[str] exists 1 else 0
 */
gboolean optlist_exists(optlist_t * optlist, const char *str)
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
const char *optlist_value(optlist_t * optlist, const char *str)
{
	GList *ptr;

	assert(str);

	if (!optlist)
		return NULL;
	ptr = g_list_find_custom(optlist, str, _compare);

	assert(ptr || !optlist_exists(optlist, str));

	return (ptr != NULL) ? ((pair_t *) ptr->data)->val : NULL;
}

/* ============================ optlist_to_str () ========================== */
/* INPUT: str and optlist
 *        sizeof(str) >= MAX_PAR + 1
 * OUTPUT: string encapsulating optlist
 */
char *optlist_to_str(char *str, const optlist_t * optlist)
{
	const optlist_t *ptr = optlist;

	assert(str);

	*str = '\0';
	if (optlist)
		do {
                        pair_t *pair = ptr->data;
			strncat(str, pair->key, MAX_PAR - strlen(str));
			if(strlen(pair->val) > 0) {
				strncat(str, "=", MAX_PAR - strlen(str));
				strncat(str, pair->
					val, MAX_PAR - strlen(str));
			}
			if ((ptr = g_list_next(ptr)) != NULL)
				strncat(str, ",", MAX_PAR - strlen(str));
		} while (ptr);
	str[MAX_PAR] = '\0';

	assert((!optlist && strlen(str) == 0) || strlen(str));

	return str;
}
