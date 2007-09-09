/*=============================================================================
pam_mount - rdconf1.c
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2006 - 2007

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
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#	include <fstab.h>
#elif defined(__linux__)
#	include <mntent.h>
#endif
#include <libHX.h>
#include "compiler.h"
#include "misc.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"
#include "xstdlib.h"

/* Definitions */
enum {
	CONTEXT_GLOBAL = 0,
	CONTEXT_LUSER,
};

enum fstab_field {
	FSTAB_VOLUME,
	FSTAB_MNTPT,
	FSTAB_FSTYPE,
	FSTAB_OPTS,
};

enum wildcard_type {
	WC_NONE,
	WC_ANYUSER,
	WC_PGRP,    /* as primary group */
	WC_SGRP,    /* in secondary group */
};

enum {
	CMDA_AUTHPW,
	CMDA_SESSIONPW,
};

struct callbackmap {
	const char *name;
	const char *(*func)(xmlNode *, struct config *, unsigned int);
	unsigned int cmd;
};

struct pmt_command {
	enum command_type type;
	const char *fs, *command_name, *def[MAX_PAR + 1];
};

struct volume_attrs {
	char *user, *pgrp, *sgrp, *fstype, *server, *path, *mntpt,
	     *options, *fskeycipher, *fskeypath;
	unsigned int invert;
};

/* Functions */
static char *expand_home(const char *, char *, size_t);
static char *expand_user(const char *, char *, size_t);
static inline int strcmp_1u(const xmlChar *, const char *);

/* Variables */
static const struct callbackmap cf_tags[];
static const struct pmt_command default_command[];

//-----------------------------------------------------------------------------
/*
 * expandconfig -
 * @config:	configuration structure
 *
 * Expands all wildcards in the structure.
 */
bool expandconfig(const struct config *config)
{
	const char *u = config->user;
	struct vol *vpt;
	unsigned int i;

	for (i = 0; i < config->volcount; ++i) {
		vpt = &config->volume[i];

		if (expand_home(u, vpt->mountpoint, sizeof(vpt->mountpoint)) == NULL ||
		    expand_user(u, vpt->mountpoint, sizeof(vpt->mountpoint)) == NULL ||
		    expand_home(u, vpt->volume, sizeof(vpt->volume)) == NULL ||
		    expand_user(u, vpt->volume, sizeof(vpt->volume)) == NULL ||
		    expand_home(u, vpt->fs_key_path, sizeof(vpt->fs_key_path)) == NULL ||
		    expand_user(u, vpt->fs_key_path, sizeof(vpt->fs_key_path)) == NULL)
			return false;

		if (strcmp(vpt->user, "*") == 0 || *vpt->user == '@')
			vpt->used_wildcard = true;

		strcpy(vpt->user, config->user);
	}

	return true;
}

/*
 * freeconfig -
 * @config:	config struct
 *
 * All dynamically allocated memory in the structure is freed.
 */
void freeconfig(struct config *config)
{
	unsigned int i, j;

	for (i = 0; i < _CMD_MAX; ++i) {
		free(config->command[i][0]);
		for (j = 0; config->command[i][j] != NULL; ++j)
			config->command[i][j] = NULL;
	}

	HXbtree_free(config->options_allow);
	HXbtree_free(config->options_require);
	HXbtree_free(config->options_deny);
	free(config->user);
	free(config->msg_authpw);
	free(config->msg_sessionpw);
	return;
}

void initconfig(struct config *config)
{
	unsigned int i, j;
	static const unsigned int flags =
		HXBT_MAP | HXBT_CKEY | HXBT_CDATA | HXBT_SCMP | HXBT_CID;

	memset(config, 0, sizeof(*config));
	config->debug      = true;
	config->mkmntpoint = true;
	strcpy(config->fsckloop, "/dev/loop7");

	for (i = 0; default_command[i].type != -1; ++i)
		for (j = 0; default_command[i].def[j] != NULL; ++j)
			config->command[default_command[i].type][j] =
				xstrdup(default_command[i].def[j]);

	config->options_allow   = HXbtree_init(flags);
	config->options_require = HXbtree_init(flags);
	config->options_deny    = HXbtree_init(flags);

	return;
}

bool readconfig(const char *file, bool global_conf, struct config *config)
{
	const struct callbackmap *cmp;
	const char *err;
	xmlDoc *doc;
	xmlNode *ptr;

	if ((doc = xmlParseFile(file)) == NULL)
		return false;
	ptr = xmlDocGetRootElement(doc);
	if (ptr == NULL || strcmp_1u(ptr->name, "pam_mount") != 0) {
		xmlFreeDoc(doc);
		return false;
	}

	for (ptr = ptr->children; ptr != NULL; ptr = ptr->next) {
		if (ptr->type != XML_ELEMENT_NODE)
			continue;
		for (cmp = cf_tags; cmp->name != NULL; ++cmp)
			if (strcmp_1u(ptr->name, cmp->name) == 0) {
				err = (*cmp->func)(ptr, config, cmp->cmd);
				if (err != NULL)
					l0g("%s\n", err);
				break;
			}
	}

	xmlFreeDoc(doc);
	return true;
}

//-----------------------------------------------------------------------------
/*
 * expand_home -
 * @user:	username to use for home directory lookup
 * @path:	pathname to expand
 * @size:	size of @path
 *
 * Expands tildes in @path to the user home directory and updates @path.
 * Returns @dest.
 */
static char *expand_home(const char *user, char *path, size_t size)
{
	struct passwd *pe;
	char *buf;

	if (*path != '~')
		return path;

	if ((pe = getpwnam(user)) == NULL) {
		l0g("Could not lookup account information for %s\n", user);
		return NULL;
	}

	if ((buf = xmalloc(size)) == NULL) {
		l0g("%s\n", strerror(errno));
		return NULL;
	}
	if (snprintf(buf, size, "%s%s", pe->pw_dir, path + 1) >= size)
		l0g("Warning: Not enough buffer space in expand_home()\n");

	strncpy(path, buf, size);
	free(buf);
	return path;
}

/*
 * expand_user -
 * @user:	username to substitue for placeholder
 * @dest:	buffer to operate on
 * @size:	size of @dest
 *
 * Substitutes all occurrences of %(USER) by the username. Returns NULL on
 * failure, otherwise @dest.
 *
 * (This should probably be done by the fmt_ptrn stuff, but is not at the
 * moment due to to-XML transition period.)
 */
static char *expand_user(const char *user, char *dest, size_t size)
{
	struct HXbtree *vinfo;

	if (dest == NULL)
		l0g("expand_user_wildcard(dest=NULL), please fix\n");

	vinfo = HXformat_init();
	HXformat_add(vinfo, "USER", user, HXTYPE_STRING);
	misc_add_ntdom(vinfo, user);
	HXformat_sprintf(vinfo, dest, size, dest);
	HXformat_free(vinfo);
	return dest;
}

/*
 * fstab_value -
 * @volume:	path to volume
 * @field:	-
 * @dest:	destination buffer
 * @size:	size of @dest
 *
 * Search for @volume in /etc/fstab and if it is found, copy the @field'th
 * field to @dest which is of size @size. Returns 0 on error, 1 on success.
 */
static int fstab_value(const char *volume, const enum fstab_field field,
    char *dest, int size)
{
	const char *val;
#if defined(__linux__)
	struct mntent *fstab_record;
	FILE *fstab;

	if ((fstab = setmntent("/etc/fstab", "r")) == NULL) {
		l0g("could not open fstab\n");
		return 0;
	}

	for (fstab_record = getmntent(fstab);
	    fstab_record != NULL &&
	    strcmp(fstab_record->mnt_fsname, volume) != 0;
	    fstab_record = getmntent(fstab))
		/* skip fstab entries until a match is found */;

	if (fstab_record == NULL) {
		l0g("could not get %dth fstab field for %s\n", field, volume);
		return 0;
	}

	switch (field) {
		case FSTAB_VOLUME:
			val = fstab_record->mnt_fsname;
			break;
		case FSTAB_MNTPT:
			val = fstab_record->mnt_dir;
			break;
		case FSTAB_FSTYPE:
			val = fstab_record->mnt_type;
			break;
		case FSTAB_OPTS:
			val = fstab_record->mnt_opts;
			break;
		default:
			l0g("field of %d invalid\n", field);
			return 0;
	}
#elif defined (__FreeBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	struct fstab *fstab_record;

	if (!setfsent()) {
		l0g("could not open fstab\n");
		return 0;
	}
	if ((fstab_record = getfsspec(volume)) == NULL) {
		l0g("could not get %dth fstab field for %s\n", field, volume);
		return 0;
	}

	switch (field) {
		case FSTAB_VOLUME:
			val = fstab_record->fs_spec;
			break;
		case FSTAB_MNTPT:
			val = fstab_record->fs_file;
			break;
		case FSTAB_FSTYPE:
			val = fstab_record->fs_vfstype;
			break;
		case FSTAB_OPTS:
			val = fstab_record->fs_mntops;
			break;
		default:
			l0g("field of %d invalid\n", field);
			return 0;
	}
#else
	l0g("reading fstab not implemented on arch.\n");
	return 0;
#endif

	strncpy(dest, val, size);
	dest[size-1] = '\0';
#if defined(__linux__)
	endmntent(fstab);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	endfsent();
#endif
	return 1;
}

/*
 * get_next_argument -
 * @sptr:	pointer to pointer to writable string
 *
 * Unescapes the next argument from @*sptr and writes it into @*sptr,
 * which is returned. (In-place unescape)
 */
static inline char *get_next_argument(char **sptr)
{
	char *i = *sptr, *o = i, *ret = i;
	char quot = '\0';

	if (*i == '\0')
		return NULL;
	while (isspace(*i))
		++i;

	while (*i != '\0') {
		if (quot == '\0') {
			if (isspace(*i)) {
				++i;
				break;
			}
			switch (*i) {
				case '"':
				case '\'':
					quot = *i++;
					continue;
				case '\\':
					if (*++i != '\0')
						*o++ = *i;
					continue;
				default:
					*o++ = *i++;
					continue;
			}
			break;
		}
		if (*i == quot) {
			quot = 0;
			++i;
			continue;
		} else if (*i == '\\') {
			*o++ = *++i;
			++i;
			continue;
		}
		*o++ = *i++;
	}
	*o++  = '\0';
	*sptr = i;
	return ret;
}

static inline bool parse_bool(const char *s)
{
	return strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0||
	       strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0;
}

static inline int strcmp_1u(const xmlChar *a, const char *b)
{
	return strcmp(reinterpret_cast(const char *, a), b);
}

/*
 * user_in_sgrp -
 * @user:	user to check
 * @grp:	group name
 *
 * Checks whether @user has @grp as one its _secondary_ groups. Returns 0 if
 * no match was found, positive non-zero on success or negative non-zero on
 * failure.
 */
static bool user_in_sgrp(const char *user, const char *grp)
{
	struct group *gent;
	const char **wp;

	if ((gent = getgrnam(grp)) == NULL) {
		w4rn("getgrnam(\"%s\") failed: %s\n", grp, strerror(errno));
		return false;
	}

	wp = const_cast(const char **, gent->gr_mem);
	while (wp != NULL && *wp != NULL) {
		if (strcmp(*wp, user) == 0)
			return true;
		++wp;
	}

	return false;
}

static inline char *xmlGetProp_2s(xmlNode *node, const char *attr)
{
	return reinterpret_cast(char *, xmlGetProp(node,
	       reinterpret_cast(const xmlChar *, attr)));
}

//-----------------------------------------------------------------------------
static const char *rc_command(xmlNode *node, struct config *config,
    unsigned int command)
{
	unsigned int n = 0;
	char *arg, *wp;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set command from user config\n";
	if ((node = node->children) == NULL)
		return NULL;
	for (; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;

		wp = xstrdup(signed_cast(const char *, node->content));
		while ((arg = get_next_argument(&wp)) != NULL)
			/*
			 * The copy taken with strdup() is not freed in this
			 * function, because it is used soon. 
			 * @config->command[command][0] will be the pointer to
			 * the block to free later.
			 */
			config->command[command][n++] = arg;

		/* No hassle to support comment-split tags. */
		break;
	}
	return NULL;
}

static const char *rc_debug(xmlNode *node, struct config *config,
    unsigned int cmd)
{
	char *s;
	if ((s = xmlGetProp_2s(node, "enable")) != NULL)
		Debug = config->debug = strtol(s, NULL, 0);
	free(s);
	return NULL;
}

static const char *rc_fsckloop(xmlNode *node, struct config *config,
    unsigned int cmd)
{
	char *dev;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set <fsckloop> from user config";
	if ((dev = xmlGetProp_2s(node, "device")) != NULL) {
		if (strlen(dev) > PATH_MAX) {
			free(dev);
			return "fsckloop device path too long";
		}
		strncpy(config->fsckloop, dev, PATH_MAX);
		free(dev);
	}

	return NULL;
}

static const char *rc_luserconf(xmlNode *node, struct config *config,
    unsigned int command)
{
	struct passwd *pent;
	char *s;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set <luserconf> from user config";
	if ((pent = getpwnam(config->user)) == NULL)
		return "Could not get password entry";
	if ((s = xmlGetProp_2s(node, "name")) == NULL)
		return "<luserconf> is missing name= attribute";
	if (strlen(pent->pw_dir) + 1 + strlen(s) > sizeof_z(config->luserconf)) {
		free(s);
		return "expanded luserconf path too long";
	}
	HX_strlcpy(config->luserconf, pent->pw_dir, sizeof(config->luserconf));
	HX_strlcat(config->luserconf, "/", sizeof(config->luserconf));
	HX_strlcat(config->luserconf, s, sizeof(config->luserconf));
	w4rn("path to luserconf set to %s\n", config->luserconf),
	free(s);
	return NULL;
}

static const char *rc_mkmountpoint(xmlNode *node, struct config *config,
    unsigned int command)
{
	char *s;
	if ((s = xmlGetProp_2s(node, "enable")) != NULL)
		config->mkmntpoint = strtol(s, NULL, 0);
	free(s);
	if ((s = xmlGetProp_2s(node, "remove")) != NULL)
		config->rmdir_mntpt = parse_bool(s);
	free(s);
	return NULL;
}

/*
 * str_to_optlist -
 * @optlist:	destination list
 * @str:	string to parse
 *
 * Break down @str into its option. This function modifies @str in-place.
 * This is ok, since it is already an allocated string (i.e. does not
 * belong to libxml but to pam_mount). Caller frees it anyway right away.
 */
static bool str_to_optlist(struct HXbtree *optlist, char *str)
{
	char *value, *ptr;

	if (str == NULL || strlen(str) == 0)
		/*
		 * So what, ignore it.
		 */
		return true;

	while ((ptr = HX_strsep(&str, ",")) != NULL) {
		value = strchr(ptr, '=');
		if (value != NULL) {
			*value++ = '\0';
			HXbtree_add(optlist, ptr, value);
		} else {
			HXbtree_add(optlist, ptr, NULL);
		}
	}

	return true;
}

static const char *rc_mntoptions(xmlNode *node, struct config *config,
    unsigned int command)
{
	char *options;
	int ret;

	if (config->level != CONTEXT_GLOBAL)
		return "Tried to set <mntoptions allow=...> from user config";

	if ((options = xmlGetProp_2s(node, "allow")) != NULL) {
		ret = str_to_optlist(config->options_allow, options);
		free(options);
		if (!ret)
			return "Error parsing allowed options";
	}

	if ((options = xmlGetProp_2s(node, "deny")) != NULL) {
		ret = str_to_optlist(config->options_deny, options);
		free(options);
		if (!ret)
			return "Error parsing denied options";
	}

	if ((options = xmlGetProp_2s(node, "require")) != NULL) {
		ret = str_to_optlist(config->options_require, options);
		free(options);
		if (!ret)
			return "Error parsing required options";
	}	

	return NULL;
}

static const char *rc_string(xmlNode *node, struct config *config,
    unsigned int command)
{
	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		switch (command) {
			case CMDA_AUTHPW:
				config->msg_authpw = xstrdup(signed_cast(const char *, node->content));
				break;
			case CMDA_SESSIONPW:
				config->msg_sessionpw = xstrdup(signed_cast(const char *, node->content));
				break;
		}
		break;
	}
	return NULL;
}

static const char *rc_volume_inter(struct config *config,
    const struct volume_attrs *attr)
{
	enum wildcard_type wildcard = WC_NONE;
	struct passwd *pent;
	struct vol *vpt;
	unsigned int i;

	if (strlen(attr->user) > sizeof_z(vpt->user) ||
	    strlen(attr->fstype) > sizeof_z(vpt->fstype) ||
	    strlen(attr->server) > sizeof_z(vpt->server) ||
	    strlen(attr->path) > sizeof_z(vpt->volume) ||
	    strlen(attr->mntpt) > sizeof_z(vpt->mountpoint) ||
	    strlen(attr->fskeycipher) > sizeof_z(vpt->fs_key_cipher) ||
	    strlen(attr->fskeypath) > sizeof_z(vpt->fs_key_path))
		return "command too long";

	if ((pent = getpwnam(config->user)) == NULL) {
		w4rn("getpwnam(\"%s\") failed: %s\n",
		     Config.user, strerror(errno));
		return NULL;
	}

	if (strcmp(attr->user, "*") == 0)
		wildcard = WC_ANYUSER;
	else if (*attr->pgrp != '\0')
		wildcard = WC_PGRP;
	else if (*attr->sgrp != '\0')
		wildcard = WC_SGRP;
	else if (*attr->user == '\0')
		wildcard = WC_ANYUSER;

	if (wildcard != WC_NONE && (strcmp(config->user, "root") == 0 ||
	    pent->pw_uid == 0)) {
		/* One day, when SELinux becomes a daily thing, remove this. */
		w4rn("volume wildcards ignored for \"root\" and uid0\n");
		return NULL;
	}

	if (wildcard == WC_NONE && (strcmp(config->user, attr->user) != 0) ^
	    attr->invert)
		goto notforme;

	if (wildcard == WC_PGRP) {
		const char *grp_name = attr->pgrp;
		struct group *gent;

		if ((gent = getgrgid(pent->pw_gid)) == NULL) {
			w4rn("getgrgid(%ld) failed: %s\n",
			     static_cast(long, pent->pw_gid), strerror(errno));
			return NULL;
		}
		if ((strcmp(grp_name, gent->gr_name) != 0) ^ attr->invert)
			goto notforme;
	} else if (wildcard == WC_SGRP) {
		const char *grp_name = attr->sgrp;
		struct group *gent;

		if ((gent = getgrgid(pent->pw_gid)) == NULL) {
			w4rn("getgrgid(%ld) failed: %s\n",
			     static_cast(long, pent->pw_gid), strerror(errno));
			return NULL;
		}
		if (!user_in_sgrp(config->user, grp_name) ^ attr->invert)
			goto notforme;
	}

	/* realloc */
	config->volume = xrealloc(config->volume,
	                 sizeof(struct vol) * (config->volcount + 1));
	vpt = &config->volume[config->volcount++];
	memset(vpt, 0, sizeof(*vpt));

	vpt->globalconf = config->level == CONTEXT_GLOBAL;
	strncpy(vpt->user, config->user, sizeof(vpt->user));
	vpt->type = CMD_LCLMOUNT;
	vpt->options = HXbtree_init(HXBT_MAP | HXBT_CKEY | HXBT_CDATA |
	               HXBT_SCMP | HXBT_CID);

	/* [1] */
	strncpy(vpt->fstype, attr->fstype, sizeof(vpt->fstype));

	for (i = 0; default_command[i].type != -1; ++i) {
		const struct pmt_command *c = &default_command[i];
		if (c->fs != NULL && strcasecmp(attr->fstype, c->fs) == 0) {
			vpt->type = c->type;
			break;
		}
	}

	/* [2] */
	if (*attr->server != '\0')
		strncpy(vpt->server, attr->server, sizeof(vpt->server));

	/* [3] */
	strncpy(vpt->volume, attr->path, sizeof(vpt->volume));

	/* [4] */
	if (*attr->mntpt == '\0') {
		if (!fstab_value(vpt->volume, FSTAB_MNTPT, vpt->mountpoint,
		    sizeof(vpt->mountpoint)))
				return "could not determine mountpoint";
		vpt->use_fstab = 1;
	} else {
		strncpy(vpt->mountpoint, attr->mntpt, sizeof(vpt->mountpoint));
	}

	if (*attr->options == '\0') {
		/*
		 * Three options: field defined, field is '-' and fstab should
		 * be used (when no mount point was provided either) or field
		 * is '-' and this means no options.
		 */
		if (vpt->use_fstab) {
			char options[MAX_PAR + 1];
			if (!fstab_value(vpt->volume, FSTAB_OPTS, options,
			    sizeof(options)))
				return "could not determine options";
			if (!str_to_optlist(vpt->options, options))
				return "error parsing mount options";
		} else {
			vpt->options = NULL;
		}
	} else if (!str_to_optlist(vpt->options, attr->options)) {
		return "error parsing mount options";
	}

	if (*attr->fskeycipher != '\0')
		strncpy(vpt->fs_key_cipher, attr->fskeycipher,
		        sizeof(vpt->fs_key_cipher));
	if (*attr->fskeypath != '\0')
		strncpy(vpt->fs_key_path, attr->fskeypath,
		        sizeof(vpt->fs_key_path));

	/* expandconfig() will set this later */
	vpt->used_wildcard = 0;
	return NULL;

 notforme:
	w4rn("ignoring volume record... (not for me)\n");
	return NULL;
}

static const char *rc_volume(xmlNode *node, struct config *config,
    unsigned int command)
{
	struct volume_attrs norm, orig = {
		.user        = xmlGetProp_2s(node, "user"),
		.pgrp        = xmlGetProp_2s(node, "pgrp"),
		.sgrp        = xmlGetProp_2s(node, "sgrp"),
		.fstype      = xmlGetProp_2s(node, "fstype"),
		.server      = xmlGetProp_2s(node, "server"),
		.path        = xmlGetProp_2s(node, "path"),
		.mntpt       = xmlGetProp_2s(node, "mountpoint"),
		.options     = xmlGetProp_2s(node, "options"),
		.fskeycipher = xmlGetProp_2s(node, "fskeycipher"),
		.fskeypath   = xmlGetProp_2s(node, "fskeypath"),
	};
	const char *ret;
	char *invert;

	if ((invert = xmlGetProp_2s(node, "invert")) != NULL) {
		orig.invert = strtoul(invert, NULL, 0);
		free(invert);
	}

	memcpy(&norm, &orig, sizeof(norm));
	if (norm.user        == NULL) norm.user        = "";
	if (norm.pgrp        == NULL) norm.pgrp        = "";
	if (norm.sgrp        == NULL) norm.sgrp        = "";
	if (norm.fstype      == NULL) norm.fstype      = "auto";
	if (norm.server      == NULL) norm.server      = "";
	if (norm.path        == NULL) norm.path        = "";
	if (norm.mntpt       == NULL) norm.mntpt       = "";
	if (norm.options     == NULL) norm.options     = "";
	if (norm.fskeycipher == NULL) norm.fskeycipher = "";
	if (norm.fskeypath   == NULL) norm.fskeypath   = "";
	ret = rc_volume_inter(config, &norm);
	free(orig.user);
	free(orig.fstype);
	free(orig.server);
	free(orig.path);
	free(orig.mntpt);
	free(orig.options);
	free(orig.fskeycipher);
	free(orig.fskeypath);
	return ret;
}

//-----------------------------------------------------------------------------
static const struct pmt_command default_command[] = {
	{CMD_SMBMOUNT,   "smbfs", "smbmount",   {"smbmount", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER),uid=%(USERUID),gid=%(USERGID)%(before=\",\" OPTIONS)", NULL}},
	{CMD_SMBUMOUNT,  "smbfs", "smbumount",  {"smbumount", "%(MNTPT)", NULL}},
	{CMD_CIFSMOUNT,  "cifs",  "cifsmount",  {"mount", "-t", "cifs", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER),uid=%(USERUID),gid=%(USERGID)%(before=\",\" OPTIONS)", NULL}},
	{CMD_DAVMOUNT,   "davfs", "davmount",   {"mount", "-t", "davfs", "%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER),uid=%(USERUID),gid=%(USERGID)%(before=\",\" OPTIONS)", NULL}},
	{CMD_NCPMOUNT,   "ncpfs", "ncpmount",   {"ncpmount", "%(SERVER)/%(USER)", "%(MNTPT)", "-o", "pass-fd=0,volume=%(VOLUME)%(before=\",\" OPTIONS)", NULL}},
	{CMD_NCPUMOUNT,  "ncpfs", "ncpumount",  {"ncpumount", "%(MNTPT)", NULL}},
	{CMD_FUSEMOUNT,  "fuse",  "fusemount",  {"mount.fuse", "%(VOLUME)", "%(MNTPT)", "%(before=\"-o \" OPTIONS)", NULL}},
	{CMD_FUSEUMOUNT, "fuse",  "fuseumount", {"fusermount", "-u", "%(MNTPT)", NULL}},
	/* Do not use LCLMOUNT to avoid calling fsck */
	{CMD_NFSMOUNT,   "nfs",   "nfsmount",   {"mount", "%(SERVER):%(VOLUME)", "%(MNTPT)%(before=\"-o\" OPTIONS)", NULL}},
	{CMD_LCLMOUNT,   NULL,    "lclmount",   {"mount", "-p0", "-t", "%(FSTYPE)", "%(VOLUME)", "%(MNTPT)", "%(before=\"-o\" OPTIONS)", NULL}},
	/* Hope to have this in util-linux (LCLMOUNT) some day: */
	{CMD_CRYPTMOUNT, "crypt", "cryptmount", {"mount", "-t", "crypt", "%(before=\"-o \" OPTIONS)", "%(VOLUME)", "%(MNTPT)", NULL}},
	{CMD_UMOUNT,     NULL,    "umount",     {"umount", "%(MNTPT)", NULL}},
	{CMD_LSOF,       NULL,    "lsof",       {"lsof", "%(MNTPT)", NULL}},
	{CMD_MNTAGAIN,   NULL,    "mntagain",   {"mount", "--bind", "%(PREVMNTPT)", "%(MNTPT)", NULL}},
	/*
	 *  Leave mntcheck available on GNU/Linux so I can ship one
	 *  config file example
	 */
	{CMD_MNTCHECK,   NULL,    "mntcheck",   {"mount", NULL}},
	{CMD_FSCK,       NULL,    "fsck",       {"fsck", "-p", "%(FSCKTARGET)", NULL}},
	{CMD_LOSETUP,    NULL,    "losetup",    {"losetup", "-p0", "%(before=\"-e\" CIPHER)", "%(before=\"-k\" KEYBITS)", "%(FSCKLOOP)", "%(VOLUME)", NULL}},
	{CMD_UNLOSETUP,  NULL,    "unlosetup",  {"losetup", "-d", "%(FSCKLOOP)", NULL}},
	{CMD_PMVARRUN,   NULL,    "pmvarrun",   {"pmvarrun", "-u", "%(USER)", "-o", "%(OPERATION)", NULL}},

	{CMD_TRUECRYPTMOUNT,  "truecrypt", "truecrypt", {"truecryptmount", "%(VOLUME)", "%(MNTPT)", NULL}},
	{CMD_TRUECRYPTUMOUNT, "truecrypt", "truecrypt", {"truecryptumount", "-d", "%(MNTPT)", NULL}},

	{-1},
};

static const struct callbackmap cf_tags[] = {
	{"cifsmount",       rc_command,             CMD_CIFSMOUNT},
	{"cryptmount",      rc_command,             CMD_CRYPTMOUNT},
	{"davmount",        rc_command,             CMD_DAVMOUNT},
	{"debug",           rc_debug,               CMD_NONE},
	{"fsckloop",        rc_fsckloop,            CMD_NONE},
	{"fsck",            rc_command,             CMD_FSCK},
	{"fusemount",       rc_command,             CMD_FUSEMOUNT},
	{"fuseumount",      rc_command,             CMD_FUSEUMOUNT},
	{"lclmount",        rc_command,             CMD_LCLMOUNT},
	{"losetup",         rc_command,             CMD_LOSETUP},
	{"lsof",            rc_command,             CMD_LSOF},
	{"luserconf",       rc_luserconf,           CMD_NONE},
	{"mkmountpoint",    rc_mkmountpoint,        CMD_NONE},
	{"mntagain",        rc_command,             CMD_MNTAGAIN},
	{"mntcheck",        rc_command,             CMD_MNTCHECK},
	{"mntoptions",      rc_mntoptions,          CMD_NONE},
	{"msg-authpw",      rc_string,              CMDA_AUTHPW},
	{"msg-sessionpw",   rc_string,              CMDA_SESSIONPW},
	{"nfsmount",        rc_command,             CMD_NFSMOUNT},
	{"ncpmount",        rc_command,             CMD_NCPMOUNT},
	{"ncpumount",       rc_command,             CMD_NCPUMOUNT},
	{"pmvarrun",        rc_command,             CMD_PMVARRUN},
	{"smbmount",        rc_command,             CMD_SMBMOUNT},
	{"smbumount",       rc_command,             CMD_SMBUMOUNT},
	{"truecryptmount",  rc_command,             CMD_TRUECRYPTMOUNT},
	{"truecryptumount", rc_command,             CMD_TRUECRYPTUMOUNT},
	{"umount",          rc_command,             CMD_UMOUNT},
	{"unlosetup",       rc_command,             CMD_UNLOSETUP},
	{"volume",          rc_volume,              CMD_NONE},
	{NULL},
};

//=============================================================================
