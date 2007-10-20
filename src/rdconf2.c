/*=============================================================================
pam_mount - rdconf2.c
  Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
  Copyright © CC Computer Consultants GmbH, 2005 - 2007
  Contact: Jan Engelhardt <jengelh [at] computergmbh de>
  Copyright © Bastian Kleineidam <calvin [at] debian org>, 2005

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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include "compiler.h"
#include "misc.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"

/*
 * allow_ok - check for disallowed options
 * @allowed:	list of allowed options
 * @options:	options to check
 *
 * Check if there are any options in @options that are not in @allowed.
 * If so, return false.
 */
static bool allow_ok(const struct HXbtree *allowed,
    const struct HXbtree *options)
{
	const struct HXbtree_node *e;
	void *t;

	if (HXbtree_find(allowed, "*") != NULL || options->items == 0)
		return true;

	t = HXbtrav_init(options);
	while ((e = HXbtraverse(t)) != NULL)
		if (HXbtree_find(allowed, e->data) != NULL) {
			l0g("option %s not allowed\n",
			    static_cast(const char *, e->data));
			HXbtrav_free(t);
			return false;
		}

	HXbtrav_free(t);
	return true;
}

/*
 * required_ok - check for missing options
 * @required:	list of required options
 * @options:	options to check
 *
 * Checks @options whether it contains all options in @required.
 * If so, returns true.
 */
static bool required_ok(const struct HXbtree *required,
    const struct HXbtree *options)
{
	const struct HXbtree_node *e;
	void *t;

	t = HXbtrav_init(required);
	while ((e = HXbtraverse(t)) != NULL)
		if (HXbtree_find(options, e->data) == NULL) {
			l0g("option %s required\n",
			    static_cast(const char *, e->data));
			HXbtrav_free(t);
			return false;
		}

	HXbtrav_free(t);
	return true;
}

/*
 * deny_ok - check for denied options
 * @denied:	list of denied options
 * @options:	options to check
 *
 * Checks @options whether any of them appear in @deny. If so, returns false.
 */
static bool deny_ok(const struct HXbtree *denied,
    const struct HXbtree *options)
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

	t = HXbtrav_init(denied);
	while ((e = HXbtraverse(t)) != NULL)
		if (HXbtree_find(options, e->data) != NULL) {
			l0g("option %s denied\n",
			    static_cast(const char *, e->data));
			HXbtrav_free(t);
			return false;
		}

	HXbtrav_free(t);
	return true;
}

/*
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

	if (config->options_allow->items != 0 &&
	    config->options_deny->items != 0) {
		l0g("possible conflicting option settings (use allow OR deny)\n");
		return false;
	}
	if (!volume->use_fstab) {
		if (!required_ok(config->options_require, volume->options)) {
			return false;
		} else if (config->options_allow->items != 0) {
			if (!allow_ok(config->options_allow, volume->options))
				return false;
		} else if (config->options_deny->items != 0) {
			if (!deny_ok(config->options_deny, volume->options))
				return false;
		} else if (volume->options->items != 0) {
			l0g("user specified options denied by default\n");
			return false;
		}
	}
	return true;
}

/*
 * luserconf_volume_record_sane -
 * @config:	current configuration
 * @vol:	volume index
 *
 * Check whether the per-user volume is in accordance with wildcard and
 * option restrictions.
 *
 * FIXME: check to ensure input is legal and reject all else instead of
 * rejecting everyhing that is illegal.
 */
bool luserconf_volume_record_sane(const struct config *config,
    unsigned int vol)
{
	const struct vol *vpt;
	assert(config != NULL);
	assert(config->volume != NULL);
	vpt = &config->volume[vol];

	if (config->volume[vol].used_wildcard) {
		l0g("You may not use wildcards in user-defined volumes\n");
		return false;
	}
	if (!options_ok(config, &config->volume[vol])) {
		l0g("illegal option specified by user\n");
		return false;
	}
	return true;
}

/*
 * volume_record_sane -
 * @config:	current configuration
 * @vol:	volume index
 *
 * FIXME: check to ensure input is legal and reject all else instead of
 * rejecting everyhing that is illegal.
 */
bool volume_record_sane(const struct config *config, unsigned int vol)
{
	const struct vol *vpt;

	assert(config != NULL);
	assert(config->volume != NULL);
	vpt = &config->volume[vol];

	w4rn("checking sanity of volume record (%s)\n", vpt->volume);
	if (config->command[vpt->type][0] == NULL) {
		l0g("mount command not defined for this type\n");
		return false;
	}
	if (vpt->type == CMD_SMBMOUNT || vpt->type == CMD_CIFSMOUNT ||
	    vpt->type == CMD_NCPMOUNT || vpt->type == CMD_NFSMOUNT ||
	    vpt->type == CMD_DAVMOUNT)
	    	if (strlen(vpt->server) == 0) {
			l0g("remote mount type specified without server\n");
			return false;
		}

	if (vpt->type == CMD_NCPMOUNT &&
	    HXbtree_find(vpt->options, "user") != NULL) {
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
