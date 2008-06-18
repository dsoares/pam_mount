/*
 *	Copyright © Jan Engelhardt, 2006 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
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
#include <libHX/arbtree.h>
#include <libHX/option.h>
#include <libHX/string.h>
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

enum {
	CMDA_AUTHPW,
	CMDA_SESSIONPW,
	CMDA_PATH,
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

/* Functions */
static char *expand_home(const char *, char *, size_t);
static char *expand_user(const char *, char *, size_t);
static inline int strcmp_1u(const xmlChar *, const char *);
static int rc_volume_cond_ext(const struct passwd *, xmlNode *);

/* Variables */
static const struct callbackmap cf_tags[];
static const struct pmt_command default_command[];

//-----------------------------------------------------------------------------
/**
 * expandconfig -
 * @config:	configuration structure
 *
 * Expands all wildcards in the structure.
 */
bool expandconfig(const struct config *config)
{
	const char *u = config->user;
	struct vol *vpt;

	HXlist_for_each_entry(vpt, &config->volume_list, list) {
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

/**
 * freeconfig -
 * @config:	config struct
 *
 * All dynamically allocated memory in the structure is freed.
 */
void freeconfig(struct config *config)
{
	struct vol *vol, *next;
	unsigned int i, j;

	for (i = 0; i < _CMD_MAX; ++i) {
		free(config->command[i][0]);
		for (j = 0; config->command[i][j] != NULL; ++j)
			config->command[i][j] = NULL;
	}

	HXlist_for_each_entry_safe(vol, next, &config->volume_list, list) {
		kvplist_genocide(&vol->options);
		free(vol);
	}

	HXbtree_free(config->options_allow);
	HXbtree_free(config->options_require);
	HXbtree_free(config->options_deny);
	free(config->user);
	free(config->msg_authpw);
	free(config->msg_sessionpw);
	free(config->path);
}

void initconfig(struct config *config)
{
	unsigned int i, j;
	static const unsigned int flags =
		HXBT_MAP | HXBT_CKEY | HXBT_SCMP | HXBT_CID;

	memset(config, 0, sizeof(*config));
	config->debug      = true;
	config->mkmntpoint = true;
	strcpy(config->fsckloop, "/dev/loop7");

	config->msg_authpw    = xstrdup("pam_mount password:");
	config->msg_sessionpw = xstrdup("reenter password for pam_mount:");

	config->path = xstrdup("/sbin:/bin:/usr/sbin:/usr/bin:"
	               "/usr/local/sbin:/usr/local/bin");

	for (i = 0; default_command[i].type != -1; ++i)
		for (j = 0; default_command[i].def[j] != NULL; ++j)
			config->command[default_command[i].type][j] =
				xstrdup(default_command[i].def[j]);

	config->options_allow   = HXbtree_init(flags);
	config->options_require = HXbtree_init(flags);
	config->options_deny    = HXbtree_init(flags);

	HXclist_init(&config->volume_list);
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
/**
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

/**
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

	if ((vinfo = HXformat_init()) == NULL)
		return NULL;
	HXformat_add(vinfo, "USER", user, HXTYPE_STRING);
	misc_add_ntdom(vinfo, user);
	HXformat_sprintf(vinfo, dest, size, dest);
	HXformat_free(vinfo);
	return dest;
}

/**
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

/**
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
	return strcasecmp(s, "yes") == 0 || strcasecmp(s, "on") == 0 ||
	       strcasecmp(s, "true") == 0 || strcmp(s, "1") == 0;
}

static inline bool parse_bool_f(char *s)
{
	bool ret;
	if (s == NULL)
		return false;
	ret = parse_bool(s);
	free(s);
	return ret;
}

static inline int strcmp_1u(const xmlChar *a, const char *b)
{
	return strcmp(reinterpret_cast(const char *, a), b);
}

/**
 * user_in_sgrp -
 * @user:	user to check
 * @grp:	group name
 *
 * Checks whether @user has @grp as one its _secondary_ groups. Returns 0 if
 * no match was found, positive non-zero on success or negative non-zero on
 * failure.
 */
static bool user_in_sgrp(const char *user, const char *grp, bool icase)
{
	struct group *gent;
	const char **wp;

	if ((gent = getgrnam(grp)) == NULL) {
		w4rn("getgrnam(\"%s\") failed: %s\n", grp, strerror(errno));
		return false;
	}

	wp = const_cast(const char **, gent->gr_mem);
	while (wp != NULL && *wp != NULL) {
		if (strcmp(*wp, user) ||
		    (icase && strcasecmp(*wp, user)) == 0)
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
		Debug = config->debug = strtoul(s, NULL, 0);
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
	w4rn("path to luserconf set to %s\n", config->luserconf);
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

/**
 * str_to_optlist -
 * @optlist:	destination list
 * @str:	string to parse
 *
 * Break down @str into its option. This function modifies @str in-place.
 * This is ok, since it is already an allocated string (i.e. does not
 * belong to libxml but to pam_mount). Caller frees it anyway right away.
 */
static bool str_to_optkv(struct HXclist_head *optlist, char *str)
{
	char *value, *ptr;
	struct kvp *kvp;

	if (str == NULL || *str == '\0')
		return true;

	while ((ptr = HX_strsep(&str, ",")) != NULL) {
		kvp = xmalloc(sizeof(struct kvp));
		if (kvp == NULL)
			return false;
		HXlist_init(&kvp->list);
		value = strchr(ptr, '=');
		if (value != NULL) {
			*value++ = '\0';
			kvp->key   = xstrdup(ptr);
			kvp->value = xstrdup(value);
			if (kvp->key == NULL || kvp->value == NULL)
				goto out;
			HXclist_push(optlist, &kvp->list);
		} else {
			kvp->key = xstrdup(ptr);
			if (kvp->key == NULL)
				goto out;
			kvp->value = NULL;
			HXclist_push(optlist, &kvp->list);
		}
	}

	return true;
 out:
	free(kvp->key);
	free(kvp->value);
	free(kvp);
	return false;
}

static bool str_to_optlist(struct HXbtree *optlist, char *str)
{
	char *value, *ptr;

	if (str == NULL || *str == '\0')
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
				free(config->msg_authpw);
				config->msg_authpw = xstrdup(signed_cast(const char *, node->content));
				break;
			case CMDA_SESSIONPW:
				free(config->msg_sessionpw);
				config->msg_sessionpw = xstrdup(signed_cast(const char *, node->content));
				break;
			case CMDA_PATH:
				free(config->path);
				config->path = xstrdup(signed_cast(const char *, node->content));
				break;
		}
		break;
	}
	return NULL;
}

/**
 * rc_volume_cond_and - handle <and> element
 * @pwd:	user logging in
 * @node: 	XML <and> node
 *
 * Handle an <and> XML node, by processing all elements within it and ANDing
 * them together. Returns negative on error.
 */
static int rc_volume_cond_and(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		ret = rc_volume_cond_ext(pwd, node);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			return false;
		++count;
	}

	if (count > 0)
		/*
		 * If there was any non-matching element, we would have
		 * already returned above.
		 */
		return true;

	l0g("config: <and> does not have any child elements\n");
	return -1;
}

/**
 * rc_volume_cond_or - handle <or> element
 * @pwd:	user logging in
 * @node:	XML <or> node
 *
 * Handle an <or> XML node, by processing all elements within it and ORing
 * them together. On error, returns -1.
 */
static int rc_volume_cond_or(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		ret = rc_volume_cond_ext(pwd, node);
		if (ret < 0)
			return ret;
		else if (ret > 0)
			return true;
		++count;
	}

	if (count > 0)
		return false;

	l0g("config: <and> does not have any child elements\n");
	return -1;
}

/**
 * rc_volume_cond_xor - handle <xor> element
 * @pwd:	user logging in
 * @node:	XML <xor> node
 *
 * Handle an <xor> XML node, by processing the two elements within it and
 * XORin them together. Exactly two elements must be provided, otherwise
 * the function fails with -1.
 */
static int rc_volume_cond_xor(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	int ret[2];

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (count >= 2)
			goto out;
		ret[count] = rc_volume_cond_ext(pwd, node);
		if (ret[count] < 0)
			return ret[count];
		++count;
	}

	if (count == 2)
		return ret[0] ^ ret[1];
 out:
	l0g("config: <xor> must have exactly two child elements\n");
	return -1;
}

/**
 * rc_volume_cond_not - handle <not> element
 * @pwd:	user logging in
 * @node:	XML <not> node
 *
 * Handle an <not> XML node, by processing the single elements within it and
 * negating it. Exactly one elements must be provided, otherwise the
 * function fails with -1.
 */
static int rc_volume_cond_not(const struct passwd *pwd, xmlNode *node)
{
	unsigned int count = 0;
	bool ret = true;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (count++ > 0)
			goto out;
		ret = rc_volume_cond_ext(pwd, node);
		if (ret < 0)
			return ret;
		ret = !ret;
	}

	if (count == 1)
		return ret;
 out:
	l0g("config: <not> may only have one child element\n");
	return -1;
}

/**
 * rc_volume_cond_user - handle <user> element
 * @pwd:	user logging in
 * @node:	XML <user> node
 */
static int rc_volume_cond_user(const struct passwd *pwd, xmlNode *node)
{
	xmlNode *parent = node;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		if (parse_bool_f(xmlGetProp_2s(parent, "icase")))
			return strcasecmp(signed_cast(const char *,
			       node->content), pwd->pw_name) == 0;
		else
			return strcmp_1u(node->content, pwd->pw_name) == 0;
	}

	return false;
}

static int __rc_volume_cond_id(const char *s, unsigned int id)
{
	unsigned int id_start, id_end;
	char *delim;

	id_start = id_end = strtoul(s, &delim, 0);
	if (*delim == '\0')
		return id_start == id;
	if (*delim != '-' || *++delim == '\0')
		return -1;
	id_end = strtoul(delim, &delim, 0);
	if (*delim != '\0')
		return -1;
	return id_start <= id && id <= id_end;
}

/**
 * rc_volume_cond_uid - handle <uid> element
 * @pwd:	user logging in
 * @node:	XML <uid> node
 */
static int rc_volume_cond_uid(const struct passwd *pwd, xmlNode *node)
{
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		ret = __rc_volume_cond_id(signed_cast(const char *,
		      node->content), pwd->pw_uid);
		if (ret < 0)
			return ret;
	}

	l0g("config: empty or invalid content for <%s>\n", "uid");
	return -1;
}

/**
 * rc_volume_cond_gid - handle <gid> element
 * @pwd:	user logging in
 * @node:	XML <uid> node
 */
static int rc_volume_cond_gid(const struct passwd *pwd, xmlNode *node)
{
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;
		ret = __rc_volume_cond_id(signed_cast(const char *,
		      node->content), pwd->pw_gid);
		if (ret < 0)
			return ret;
	}

	l0g("config: empty or invalid content for <%s>\n", "gid");
	return -1;
}

static int __rc_volume_cond_pgrp(const char *group, unsigned int gid,
    bool icase)
{
	const struct group *grp;

	errno = 0;
	grp   = getgrgid(gid);
	if (grp == NULL) {
		if (errno == 0)
			return 0; /* just not found */

		w4rn("getgrgid(%u) failed: %s\n", gid, strerror(errno));
		return -1;
	}

	if (icase)
		return strcasecmp(group, grp->gr_name) == 0;
	else
		return strcmp(group, grp->gr_name) == 0;
}

/**
 * rc_volume_cond_pgrp - handle <pgrp> element
 * @pwd:	user logging in
 * @node:	XML <pgrp> node (actually also <sgrp>)
 */
static int rc_volume_cond_pgrp(const struct passwd *pwd, xmlNode *node)
{
	xmlNode *parent = node;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;

		return __rc_volume_cond_pgrp(
		       signed_cast(const char *, node->content), pwd->pw_gid,
		       parse_bool_f(xmlGetProp_2s(parent, "icase")));
	}

	l0g("config: empty or invalid content for <%s>\n", "pgrp");
	return -1;
}

/**
 * rc_volume_cond_sgrp - handle <sgrp> element
 * @pwd:	user logging in
 * @node:	XML <sgrp> node
 */
static int rc_volume_cond_sgrp(const struct passwd *pwd, xmlNode *node)
{
	const struct group *grp;
	xmlNode *parent = node;
	int ret;

	for (node = node->children; node != NULL; node = node->next) {
		if (node->type != XML_TEXT_NODE)
			continue;

		if ((grp = getgrgid(pwd->pw_gid)) == NULL) {
			w4rn("getgrgid(%ld) failed: %s\n",
			     static_cast(long, pwd->pw_gid), strerror(errno));
			return -1;
		}

		ret = rc_volume_cond_pgrp(pwd, parent);
		if (ret < 0 || ret > 0)
			return ret;
		return user_in_sgrp(pwd->pw_name,
		       signed_cast(const char *, node->content),
		       parse_bool_f(xmlGetProp_2s(parent, "icase")));
	}

	l0g("config: empty or invalid content for <%s>\n", "sgrp");
	return -1;
}

/**
 * rc_volume_cond_ext - interpret extended user control elements
 * @pwd:	user logging in
 * @node:	XML node to operate on
 */
static int rc_volume_cond_ext(const struct passwd *pwd, xmlNode *node)
{
	if (strcmp_1u(node->name, "and") == 0)
		return rc_volume_cond_and(pwd, node);
	else if (strcmp_1u(node->name, "or") == 0)
		return rc_volume_cond_or(pwd, node);
	else if (strcmp_1u(node->name, "xor") == 0)
		return rc_volume_cond_xor(pwd, node);
	else if (strcmp_1u(node->name, "not") == 0)
		return rc_volume_cond_not(pwd, node);
	else if (strcmp_1u(node->name, "user") == 0)
		return rc_volume_cond_user(pwd, node);
	else if (strcmp_1u(node->name, "uid") == 0)
		return rc_volume_cond_uid(pwd, node);
	else if (strcmp_1u(node->name, "gid") == 0)
		return rc_volume_cond_gid(pwd, node);
	else if (strcmp_1u(node->name, "pgrp") == 0)
		return rc_volume_cond_pgrp(pwd, node);
	else if (strcmp_1u(node->name, "sgrp") == 0)
		return rc_volume_cond_sgrp(pwd, node);

	l0g("config: unknown element <%s>\n", node->name);
	return -1;
}

/**
 * rc_volume_cond_simple - interpret simple user control elements
 * @pwd:	user logging in
 * @node:	XML <volume> node
 */
static int rc_volume_cond_simple(const struct passwd *pwd, xmlNode *node)
{
	char *user   = xmlGetProp_2s(node, "user");
	char *invert = xmlGetProp_2s(node, "invert");
	char *uid    = xmlGetProp_2s(node, "uid");
	char *gid    = xmlGetProp_2s(node, "gid");
	char *pgrp   = xmlGetProp_2s(node, "pgrp");
	char *sgrp   = xmlGetProp_2s(node, "sgrp");
	bool for_me  = true;
	int ret      = true;

	if (user == NULL && invert == NULL && uid == NULL && gid == NULL &&
	    pgrp == NULL && sgrp == NULL)
		return -1;

	if (user != NULL) {
		if (strcmp(user, "*") != 0)
			for_me &= strcmp(pwd->pw_name, user) == 0;
		else if (pwd->pw_uid == 0 || strcmp(pwd->pw_name, "root") == 0)
			/* The wildcard never matches root */
			for_me &= false;
	}
	if (uid != NULL) {
		ret = __rc_volume_cond_id(uid, pwd->pw_uid);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (gid != NULL) {
		ret = __rc_volume_cond_id(gid, pwd->pw_gid);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (pgrp != NULL) {
		ret = __rc_volume_cond_pgrp(pgrp, pwd->pw_gid, false);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (sgrp != NULL) {
		ret = __rc_volume_cond_pgrp(sgrp, pwd->pw_gid, false);
		if (ret < 0)
			goto out;
		for_me &= ret;
		ret = user_in_sgrp(pwd->pw_name, sgrp, false);
		if (ret < 0)
			goto out;
		for_me &= ret;
	}
	if (invert != NULL) {
		l0g("The \"invert\" attribute is deprecated, support will "
		    "be removed in next version.\n");
		if (strtoul(invert, NULL, 0))
			for_me = !for_me;
	}

 out:
	free(user);
	free(invert);
	free(uid);
	free(gid);
	free(pgrp);
	free(sgrp);
	if (ret < 0)
		return ret;
	return for_me;
}

/**
 * rc_volume_cond - check if volume applies to user
 * @node:	XML <volume> node
 */
static int rc_volume_cond(const char *user, xmlNode *node)
{
	struct passwd *pwd_ent;
	int ret;

	if ((pwd_ent = getpwnam(user)) == NULL) {
		l0g("getpwnam: %s\n", strerror(errno));
		return -1;
	}

	ret = rc_volume_cond_simple(pwd_ent, node);
	if (ret < 0 && node->children != NULL) {
		/* When no attributes, but elements... */
		ret = rc_volume_cond_and(pwd_ent, node);
		if (ret < 0)
			return -1;
		else if (ret == 0)
			return false;
	} else if (ret == 0) {
		/* Attributes but (hopefully) no elements. */
		if (node->children != NULL) {
			l0g("You cannot have both simple and extended user control\n");
			return -1;
		}
		return false;
	}

	return true;
}

static const char *rc_volume(xmlNode *node, struct config *config,
    unsigned int command)
{
	struct vol *vpt;
	unsigned int i;
	char *tmp;

	if (strlen(config->user) > sizeof_z(vpt->user))
		return "config: <volume> components too long\n";
	if (rc_volume_cond(config->user, node) <= 0)
		return NULL;

	vpt = calloc(1, sizeof(struct vol));
	if (vpt == NULL)
		return strerror(errno);

	HXlist_init(&vpt->list);
	HXclist_push(&config->volume_list, &vpt->list);

	vpt->globalconf = config->level == CONTEXT_GLOBAL;
	strncpy(vpt->user, config->user, sizeof(vpt->user));
	vpt->type = CMD_LCLMOUNT;
	HXclist_init(&vpt->options);

	/* Eyeball ssh setting */
	if ((tmp = xmlGetProp_2s(node, "ssh")) != NULL) {
		vpt->uses_ssh = parse_bool(tmp);
		free(tmp);
	}

	/* Filesystem type */
	if ((tmp = xmlGetProp_2s(node, "fstype")) != NULL) {
		if (strlen(tmp) > sizeof_z(vpt->fstype))
			l0g("config: %s \"%s\" truncated\n", "fstype", tmp);
		strncpy(vpt->fstype, tmp, sizeof(vpt->fstype));

		for (i = 0; default_command[i].type != -1; ++i) {
			const struct pmt_command *c = &default_command[i];
			if (c->fs != NULL && strcasecmp(tmp, c->fs) == 0) {
				vpt->type = c->type;
				break;
			}
		}
		free(tmp);
	} else {
		strncpy(vpt->fstype, "auto", sizeof(vpt->fstype));
	}

	/* Source location */
	if ((tmp = xmlGetProp_2s(node, "server")) != NULL) {
		if (strlen(tmp) > sizeof_z(vpt->server))
			l0g("config: %s \"%s\" truncated\n", "server", tmp);
		strncpy(vpt->server, tmp, sizeof(vpt->server));
		free(tmp);
	}
	if ((tmp = xmlGetProp_2s(node, "path")) != NULL) {
		if (strlen(tmp) > sizeof_z(vpt->volume))
			l0g("config: %s \"%s\" truncated\n", "path", tmp);
		strncpy(vpt->volume, tmp, sizeof(vpt->volume));
		free(tmp);
	}

	/* Destination */
	if ((tmp = xmlGetProp_2s(node, "mountpoint")) != NULL) {
		if (strlen(tmp) > sizeof_z(vpt->mountpoint))
			l0g("config: %s \"%s\" truncated\n", "mountpoint", tmp);
		strncpy(vpt->mountpoint, tmp, sizeof(vpt->mountpoint));
		free(tmp);
	} else {
		if (!fstab_value(vpt->volume, FSTAB_MNTPT, vpt->mountpoint,
		    sizeof(vpt->mountpoint)))
			return "could not determine mountpoint";
		vpt->use_fstab = 1;
	}

	/* Options */
	if ((tmp = xmlGetProp_2s(node, "options")) == NULL) {
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
			if (!str_to_optkv(&vpt->options, options))
				return "error parsing mount options";
		}
	} else if (!str_to_optkv(&vpt->options, tmp)) {
		free(tmp);
		return "error parsing mount options";
	} else {
		free(tmp);
	}

	/* Filesystem key */
	if ((tmp = xmlGetProp_2s(node, "fskeycipher")) != NULL) {
		if (strlen(tmp) > sizeof_z(vpt->fs_key_cipher))
			l0g("config: %s \"%s\" truncated\n", "fskeycipher", tmp);
		strncpy(vpt->fs_key_cipher, tmp, sizeof(vpt->fs_key_cipher));
		free(tmp);
	}
	if ((tmp = xmlGetProp_2s(node, "fskeypath")) != NULL) {
		if (strlen(tmp) > sizeof_z(vpt->fs_key_path))
			l0g("config: %s \"%s\" truncated\n", "fskeypath", tmp);
		strncpy(vpt->fs_key_path, tmp, sizeof(vpt->fs_key_path));
		free(tmp);
	}

	/* expandconfig() will set this later */
	vpt->used_wildcard = false;
	return NULL;
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
	{CMD_CRYPTMOUNT, "crypt", "cryptmount", {"mount.crypt", "%(before=\"-o \" OPTIONS)", "%(VOLUME)", "%(MNTPT)", NULL}},
	{CMD_CRYPTUMOUNT, "crypt", "cryptumount", {"umount.crypt", "%(MNTPT)", NULL}},
	{CMD_UMOUNT,     NULL,    "umount",     {"umount", "%(MNTPT)", NULL}},
	{CMD_LSOF,       NULL,    "lsof",       {"lsof", "%(MNTPT)", NULL}},
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
	{"fd0ssh",          rc_command,             CMD_FD0SSH},
	{"fsckloop",        rc_fsckloop,            CMD_NONE},
	{"fsck",            rc_command,             CMD_FSCK},
	{"fusemount",       rc_command,             CMD_FUSEMOUNT},
	{"fuseumount",      rc_command,             CMD_FUSEUMOUNT},
	{"lclmount",        rc_command,             CMD_LCLMOUNT},
	{"losetup",         rc_command,             CMD_LOSETUP},
	{"lsof",            rc_command,             CMD_LSOF},
	{"luserconf",       rc_luserconf,           CMD_NONE},
	{"mkmountpoint",    rc_mkmountpoint,        CMD_NONE},
	{"mntcheck",        rc_command,             CMD_MNTCHECK},
	{"mntoptions",      rc_mntoptions,          CMD_NONE},
	{"msg-authpw",      rc_string,              CMDA_AUTHPW},
	{"msg-sessionpw",   rc_string,              CMDA_SESSIONPW},
	{"nfsmount",        rc_command,             CMD_NFSMOUNT},
	{"ncpmount",        rc_command,             CMD_NCPMOUNT},
	{"ncpumount",       rc_command,             CMD_NCPUMOUNT},
	{"path",            rc_string,              CMDA_PATH},
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
