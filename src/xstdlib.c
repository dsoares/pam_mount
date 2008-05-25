/*
 *	Copyright © Jan Engelhardt, 2006 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/clist.h>
#include <libHX/list.h>
#include <libHX/string.h>
#include "compiler.h"
#include "misc.h"
#include "pam_mount.h"
#include "private.h"
#include "xstdlib.h"

bool kvplist_contains(const struct HXclist_head *head, const char *key)
{
	const struct kvp *kvp;

	HXlist_for_each_entry(kvp, head, list)
		if (strcmp(kvp->key, key) == 0)
			return true;
	return false;
}

char *kvplist_get(const struct HXclist_head *head, const char *key)
{
	const struct kvp *kvp;

	HXlist_for_each_entry(kvp, head, list)
		if (strcmp(kvp->key, key) == 0)
			return kvp->value;
	return NULL;
}

void kvplist_genocide(struct HXclist_head *head)
{
	struct kvp *kvp, *next;

	HXlist_for_each_entry_safe(kvp, next, head, list) {
		free(kvp->key);
		free(kvp->value);
		free(kvp);
	}
}

/*
 * kvplist_to_str -
 * @optlist:	option list
 *
 * Transform the option list into a flat string. Allocates and returns the
 * string. Caller has to free it. Used for debugging.
 */
hmc_t *kvplist_to_str(const struct HXclist_head *optlist)
{
	const struct kvp *kvp;
	hmc_t *ret = hmc_sinit("");

	if (optlist == NULL)
		return ret;

	HXlist_for_each_entry(kvp, optlist, list) {
		hmc_strcat(&ret, kvp->key);
		if (kvp->value != NULL && *kvp->value != '\0') {
			hmc_strcat(&ret, "=");
			hmc_strcat(&ret, kvp->value);
		}
		hmc_strcat(&ret, ",");
	}

	if (*ret != '\0')
		/*
		 * When string is not empty, there is always at least one
		 * comma -- nuke it.
		 */
		ret[hmc_length(ret)-1] = '\0';

	return ret;
}

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
