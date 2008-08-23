/*
 *	Copyright (C) Elvis Pfützenreuter, 2000
 *	Copyright © Jan Engelhardt, 2006 - 2008
 *	Copyright © Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/types.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/arbtree.h>
#include <libHX/clist.h>
#include <pwd.h>
#include "compiler.h"
#include "misc.h"
#include "pam_mount.h"
#include "readconfig.h"
#include "xstdlib.h"

/**
 * allow_ok - check for disallowed options
 * @allowed:	list of allowed options
 * @options:	options to check
 *
 * Check if there are any options in @options that are not in @allowed.
 * If so, return false.
 */
static bool allow_ok(const struct HXbtree *allowed,
    const struct HXclist_head *options)
{
	const struct kvp *kvp;

	if (HXbtree_find(allowed, "*") != NULL || options->items == 0)
		return true;

	HXlist_for_each_entry(kvp, options, list)
		if (HXbtree_find(allowed, kvp->key) == NULL) {
			l0g("option %s not allowed\n", kvp->key);
			return false;
		}

	return true;
}

/**
 * required_ok - check for missing options
 * @required:	list of required options
 * @options:	options to check
 *
 * Checks @options whether it contains all options in @required.
 * If so, returns true.
 */
static bool required_ok(const struct HXbtree *required,
    const struct HXclist_head *options)
{
	const struct HXbtree_node *e;
	void *t;

	if ((t = HXbtrav_init(required)) == NULL)
		return false;

	while ((e = HXbtraverse(t)) != NULL)
		if (!kvplist_contains(options, e->data)) {
			l0g("option %s required\n",
			    static_cast(const char *, e->data));
			HXbtrav_free(t);
			return false;
		}

	HXbtrav_free(t);
	return true;
}

/**
 * deny_ok - check for denied options
 * @denied:	list of denied options
 * @options:	options to check
 *
 * Checks @options whether any of them appear in @deny. If so, returns false.
 */
static bool deny_ok(const struct HXbtree *denied,
    const struct HXclist_head *options)
{
	const struct HXbtree_node *e;
	void *t;

	if (denied->items == 0) {
		w4rn("no denied options\n");
		return true;
	} else if (HXbtree_find(denied, "*") != NULL && options->items != 0) {
		l0g("all mount options denied, user tried to specify one\n");
		return false;
	}

	if ((t = HXbtrav_init(denied)) == NULL)
		return false;

	while ((e = HXbtraverse(t)) != NULL)
		if (!kvplist_contains(options, e->data)) {
			l0g("option %s denied\n",
			    static_cast(const char *, e->data));
			HXbtrav_free(t);
			return false;
		}

	HXbtrav_free(t);
	return true;
}

/**
 * options_ok - checks options
 * @config:	current configuration
 * @vol:	current volume
 *
 * Returns whether the volume is ok.
 */
static bool options_ok(const struct config *config, const struct vol *volume)
{
	assert(config != NULL);
	assert(volume != NULL);

	if (!volume->use_fstab) {
		if (!required_ok(config->options_require, &volume->options))
			return false;
		if (config->options_allow->items != 0 &&
		    !allow_ok(config->options_allow, &volume->options))
			return false;
		if (config->options_deny->items != 0 &&
		    !deny_ok(config->options_deny, &volume->options))
			return false;
		if (volume->options.items != 0) {
			l0g("user specified options denied by default\n");
			return false;
		}
	}
	return true;
}

/**
 * luserconf_volume_record_sane -
 * @config:	current configuration
 * @vol:	volume descriptor
 *
 * Check whether the per-user volume is in accordance with wildcard and
 * option restrictions.
 *
 * FIXME: check to ensure input is legal and reject all else instead of
 * rejecting everyhing that is illegal.
 */
bool luserconf_volume_record_sane(const struct config *config,
    const struct vol *vol)
{
	if (vol->used_wildcard) {
		l0g("You may not use wildcards in user-defined volumes\n");
		return false;
	}
	if (!options_ok(config, vol)) {
		l0g("illegal option specified by user\n");
		return false;
	}
	return true;
}

/**
 * volume_record_sane -
 * @config:	current configuration
 * @vpt:	volume descriptor
 *
 * FIXME: check to ensure input is legal and reject all else instead of
 * rejecting everyhing that is illegal.
 */
bool volume_record_sane(const struct config *config, const struct vol *vpt)
{
	w4rn("checking sanity of volume record (%s)\n", vpt->volume);
	if (vpt->type >= _CMD_MAX) {
		misc_log("Illegal volume type\n");
		return false;
	}
	if (config->command[vpt->type][0] == NULL) {
		l0g("mount command not defined for this type\n");
		return false;
	}
	if (vpt->type == CMD_SMBMOUNT || vpt->type == CMD_CIFSMOUNT ||
	    vpt->type == CMD_NCPMOUNT || vpt->type == CMD_NFSMOUNT)
	    	if (strlen(vpt->server) == 0) {
			l0g("remote mount type specified without server\n");
			return false;
		}

	if (vpt->type == CMD_NCPMOUNT &&
	    !kvplist_contains(&vpt->options, "user")) {
		l0g("NCP volume definition missing user option\n");
		return false;
	}
	if (config->command[CMD_UMOUNT][0] == NULL) {
		l0g("umount command not defined\n");
		return false;
	}
	if (strlen(vpt->fs_key_cipher) > 0 && strlen(vpt->fs_key_path) == 0) {
		l0g("fs_key_cipher defined without fs_key_path\n");
		return false;
	}
	if (strlen(vpt->fs_key_cipher) == 0 && strlen(vpt->fs_key_path) > 0) {
		l0g("fs_key_path defined without fs_key_cipher\n");
		return false;
	}
	return true;
}
