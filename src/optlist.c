/*=============================================================================
pam_mount - optlist.c
  Copyright (C) W. Michael Putello <mike@flyn.org>, 2003
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
#include <sys/types.h>
#include <assert.h>
#include <glib.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "compiler.h"
#include "optlist.h"
#include "pair.h"
#include "private.h"
#include "xstdlib.h"

/* Functions */
static int _compare(gconstpointer, gconstpointer);
static int _parse_opt(const char *, size_t, optlist_t **);
static int _parse_string_opt(const char *str, size_t, optlist_t **);

/*
 * _parse_string_opt -
 * @str:	string to pase
 * @len:	the length up to first ',' or terminating '\0'
 * @optlist:
 *
 * Parses @str[0-len] and placed in optlist. Returns 1 on success, otherwise 0.
 */
static int _parse_string_opt(const char *str, size_t len, optlist_t **optlist)
{
	int ret = 1;
	struct pair *pair;
	char *delim, *key, *val;

	assert(str != NULL);
	/* a user could config "loop,,,foo=bar==..." */
	if (len <= 0 || len > MAX_PAR) {
		ret = 0;
		goto out;
	}
	assert(len > 0 && len <= strlen(str) && len <= MAX_PAR);
	assert(optlist != NULL);

	delim = strchr(str, '=');
	if (delim == NULL || delim - str >= len) {
		ret = 0;
		goto out;
	}
	pair = xmalloc(sizeof(struct pair));
	key  = xmalloc(delim - str + 1); /* +1 for '=' */
	val  = xmalloc(len - (delim - str));
	strncpy(key, str, delim - str);
	key[delim - str] = '\0';
	strncpy(val, delim + 1, len - (delim - str) - 1);
	val[len - (delim - str) - 1] = '\0';
	pair_init(pair, key, val, free, free);
	*optlist = g_list_append(*optlist, pair);

 out:
	assert(!ret || (optlist_exists(*optlist, key) &&
	       strcmp(optlist_value(*optlist, key), val) == 0));
	return ret;
}

/*
 * _parse_opt -
 * @str:	str, string to parse
 * @len:	the length up to first ',' or terminating '\0'
 *
 * Parses @str[0-len] and places it in optlist.
 * Returns 1 on success, otherwise 0.
 */
static int _parse_opt(const char *str, size_t len, optlist_t **optlist)
{
	int ret = 1;
	struct pair *pair;
	char *key, *val;

	assert(str != NULL);
	/* a user could config "loop,,,foo=bar==..." */
	if (len <= 0 || len > MAX_PAR) {
		ret = 0;
		goto out;
	}
	assert(len > 0 && len <= strlen(str) && len <= MAX_PAR);
	assert(optlist != NULL);

	pair = xmalloc(sizeof(struct pair));
	key  = xmalloc(len + 1);
	val  = xmalloc(1); /* wasteful */
	strncpy(key, str, len);
	key[len] = '\0';
	*val = '\0';
	pair_init(pair, key, val, free, free);
	*optlist = g_list_append(*optlist, pair);

 out:
	assert(!ret || (optlist_exists(*optlist, key) &&
	       strcmp(optlist_value(*optlist, key), val) == 0));
	return ret;
}

/*
 * str_to_oplist -
 * @optlist:
 * @str:	string to parse
 */
bool str_to_optlist(optlist_t **optlist, const char *str)
{
	int ret = 1;
	char *ptr;

	assert(optlist != NULL);
	assert(str != NULL);

	*optlist = NULL;
	if (strlen(str) == 0) {
		ret = 0;
		goto out;
	}
	while ((ptr = strchr(str, ',')) != NULL) {
		if (!_parse_string_opt(str, ptr - str, optlist) &&
		    !_parse_opt(str, ptr - str, optlist)) {
			ret = 0;
			goto out;
		}
		str = ptr + 1;
	}
	if (!_parse_string_opt(str, strlen(str), optlist) &&
	    !_parse_opt(str, strlen(str), optlist)) {
		ret = 0;
		goto out;
	}

 out:
	assert(!ret || ((strlen(str) == 0 && *optlist == '\0') ||
	       *optlist != '\0'));
	return ret;
}

static int _compare(gconstpointer x, gconstpointer y)
{
	const struct pair *px = x;
	assert(x != NULL);
	assert(px->key != NULL);
	assert(y != NULL);
	return strcmp(px->key, y);
}

bool optlist_exists(optlist_t *optlist, const char *str)
{
	assert(str != NULL);
	if (optlist == NULL)
		return 0;
	return g_list_find_custom(optlist, str, _compare) ? 1 : 0;
}

/*
 * optlist_value -
 * OUTPUT: optlist[str] ("" if no value) else NULL
 */
const char *optlist_value(optlist_t * optlist, const char *str)
{
	GList *ptr;

	assert(str != NULL);

	if (optlist == NULL)
		return NULL;
	ptr = g_list_find_custom(optlist, str, _compare);

	assert(ptr != NULL || !optlist_exists(optlist, str));

	return (ptr != NULL) ? static_cast(const struct pair *, ptr->data)->val : NULL;
}

/* ============================ optlist_to_str () ========================== */
/* INPUT: str and optlist
 *        sizeof(str) >= MAX_PAR + 1
 * OUTPUT: string encapsulating optlist
 */
char *optlist_to_str(char *str, const optlist_t * optlist)
{
	const optlist_t *ptr = optlist;

	assert(str != NULL);

	*str = '\0';
	if (optlist != NULL)
		do {
			struct pair *pair = ptr->data;
			strncat(str, pair->key, MAX_PAR - strlen(str));
			if (strlen(pair->val) > 0) {
				strncat(str, "=", MAX_PAR - strlen(str));
				strncat(str, pair->val, MAX_PAR - strlen(str));
			}
			if ((ptr = g_list_next(ptr)) != NULL)
				strncat(str, ",", MAX_PAR - strlen(str));
		} while (ptr != NULL);
	str[MAX_PAR] = '\0';

	assert((optlist == NULL && strlen(str) == 0) || strlen(str) > 0);
	return str;
}
