/*   FILE: readconfig.c
 * AUTHOR: Elvis Pf?tzenreuter <epx@conectiva.com>
 *   DATE: 2000
 *
 * Copyright (C) 2000 Elvis Pf?tzenreuter <epx@conectiva.com>
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

#include <config.h>
#include <assert.h>
#include <glib.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dotconf.h>
#include <libgen.h>
#include <pwd.h>
#include <pam_mount.h>
#include <optlist.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <fstab.h>
#elif defined(__linux__)
#include <mntent.h>
#endif

typedef enum fstab_field_t {
	FSTAB_VOLUME,
	FSTAB_MNTPT,
	FSTAB_FSTYPE,
	FSTAB_OPTS
} fstab_field_t;

extern config_t config;
extern gboolean debug;

/* defaults are included here but these are overridden by pam_mount.conf */
static pm_command_t command[] = {
	{SMBMOUNT, "smb", "smbmount", {"/bin/mount", "-t", "smbfs", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER)%(before=\",\" OPTIONS)", NULL}},
	{SMBMOUNT, "smbfs", "smbmount", {"/bin/mount", "-t", "smbfs", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER)%(before=\",\" OPTIONS)", NULL}},
	{CIFSMOUNT, "cifs", "cifsmount", {"/bin/mount", "-t", "cifs", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER)%(before=\",\" OPTIONS)", NULL}},
	{NCPMOUNT, "ncp", "ncpmount", {"/bin/mount", "-t", "ncpfs", "%(SERVER)/%(USER)", "%(MNTPT)", "-o", "pass-fd=0,volume=%(VOLUME)%(before=\",\" OPTIONS)", NULL}},
	{NCPMOUNT, "ncpfs", "ncpmount", {"/bin/mount", "-t", "ncpfs", "%(SERVER)/%(USER)", "%(MNTPT)", "-o", "pass-fd=0,volume=%(VOLUME)%(before=\",\" OPTIONS)", NULL}},
	{NFSMOUNT, "nfs", "nfsmount", {"/bin/mount", "%(SERVER):%(VOLUME)", "%(MNTPT)%(before=\"-o \" OPTIONS)", NULL}},	/* Don't use LCLMOUNT to avoid fsck */
	{LCLMOUNT, "local", "lclmount", {"/bin/mount", "-p0", "%(VOLUME)", "%(MNTPT)", "%(before=\"-o \" OPTIONS)", NULL}},
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	{CRYPTMOUNT, "crypt", "cryptmount", {"/bin/mount", "-t", "crypt", "%(before=\"-o \" OPTIONS)", "%(VOLUME)", "%(MNTPT)", NULL}},
	{UMOUNT, NULL, "umount", {"/bin/umount", "%(MNTPT)", NULL}},
	{LSOF, NULL, "lsof", {"/usr/sbin/lsof", "%(MNTPT)", NULL}},
	{MNTAGAIN, NULL, "mntagain", {"/bin/mount", "--bind", "%(PREVMNTPT)", "%(MNTPT)", NULL}},
	/*
	 * Leave mntcheck available on GNU/Linux so I can ship one config file
	 * example
	 */
	{MNTCHECK, NULL, "mntcheck", {"/bin/mount", NULL}},
	{FSCK, NULL, "fsck", {"/sbin/fsck", "-p", "%(FSCKLOOP)", NULL}},
	{LOSETUP, NULL, "losetup", {"/sbin/losetup", "-p0", "%(before=\"-e \" CIPHER)", "%(before=\"-k \" KEYBITS)", "%(FSCKLOOP)", "%(VOLUME)", NULL}},
	{UNLOSETUP, NULL, "unlosetup", {"/sbin/losetup", "-d", "%(FSCKLOOP)", NULL}},
	{PMVARRUN, NULL, "pmvarrun", {"/usr/sbin/pmvarrun", "-u", "%(USER)", "-d", "-o", "%(OPERATION)", NULL}},
	{-1, NULL, NULL, NULL}
};

static DOTCONF_CB(read_int_param);
static DOTCONF_CB(read_debug);
static DOTCONF_CB(read_luserconf);
static DOTCONF_CB(read_command);
static DOTCONF_CB(read_options_require);
static DOTCONF_CB(read_options_allow);
static DOTCONF_CB(read_options_deny);
static DOTCONF_CB(read_volume);
static DOTCONF_CB(read_fsckloop);

static const configoption_t legal_config[] = {
	{"debug", ARG_TOGGLE, read_debug, &config.debug, CTX_ALL},
	{"mkmountpoint", ARG_TOGGLE, read_int_param, &config.mkmountpoint,
	 CTX_ALL},
	{"luserconf", ARG_STR, read_luserconf, &config, CTX_ALL},
	{"fsckloop", ARG_STR, read_fsckloop, &config, CTX_ALL},
	{"smbmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"cifsmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"ncpmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"umount", ARG_LIST, read_command, &config, CTX_ALL},
	{"lclmount", ARG_LIST, read_command, &config, CTX_ALL},
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	{"cryptmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"nfsmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"lsof", ARG_LIST, read_command, &config, CTX_ALL},
	{"mntagain", ARG_LIST, read_command, &config, CTX_ALL},
	{"mntcheck", ARG_LIST, read_command, &config, CTX_ALL},
	{"fsck", ARG_LIST, read_command, &config, CTX_ALL},
	{"losetup", ARG_LIST, read_command, &config, CTX_ALL},
	{"unlosetup", ARG_LIST, read_command, &config, CTX_ALL},
	{"pmvarrun", ARG_LIST, read_command, &config, CTX_ALL},
	{"options_require", ARG_STR, read_options_require, &config,
	 CTX_ALL},
	{"options_allow", ARG_STR, read_options_allow, &config, CTX_ALL},
	{"options_deny", ARG_STR, read_options_deny, &config, CTX_ALL},
	{"volume", ARG_LIST, read_volume, &config, CTX_ALL},
	LAST_OPTION
};

/* ============================ log_error () =============================== */
/* NOTE: callback helper function for handling errors
 *       frees msg after logging it! */
static FUNC_ERRORHANDLER(log_error)
{
	l0g("pam_mount: %s\n", msg);
	/* FIXME: This free is broken.
	 * If an invalid command definition (ie: foomount) exists in 
	 * pam_mount.conf then su, loging, gdm, etc. segfault with:
	 * pam_mount: Unknown Config-Option: 'fsck'
	 * Segmentation fault
	 * Other circumstances will also cause this segfault.  For example.
	 * some functions do a return "foo."
	 free((char *) msg);
	 */
	return 0;
}

/* ============================ read_options_require () ==================== */
/* NOTE: callback function for reading required options */
static DOTCONF_CB(read_options_require)
{
	assert(cmd != NULL);
	assert(cmd->data.str != NULL);
	assert(cmd->option != NULL);
	assert(cmd->option->info != NULL);

	if (!*((int *) cmd->context))
		return "tried to set options_require from user config";
	w4rn("pam_mount: %s\n", "reading options_require...");
	if (!str_to_optlist(&((config_t *) cmd->option->info)->
			    options_require, cmd->data.str))
		return "error parsing required options";
	return NULL;
}

/* ============================ read_options_allow () ====================== */
/* NOTE: callback function for reading required options */
static DOTCONF_CB(read_options_allow)
{
	assert(cmd != NULL);
	assert(cmd->data.str != NULL);
	assert(cmd->option != NULL);
	assert(cmd->option->info != NULL);

	if (!*((int *) cmd->context))
		return "tried to set options_allow from user config";
	w4rn("pam_mount: %s\n", "reading options_allow...");
	if (!str_to_optlist(&((config_t *) cmd->option->info)->
			    options_allow, cmd->data.str))
		return "error parsing allowed options";
	return NULL;
}

/* ============================ read_options_deny () ======================= */
/* NOTE: callback function for reading required options */
static DOTCONF_CB(read_options_deny)
{
	assert(cmd != NULL);
	assert(cmd->data.str != NULL);
	assert(cmd->option != NULL);
	assert(cmd->option->info != NULL);

	if (!*((int *) cmd->context))
		return "tried to set options_deny from user config";
	w4rn("pam_mount: %s\n", "reading options_deny...");
	if (!str_to_optlist(&((config_t *) cmd->option->info)->
			    options_deny, cmd->data.str))
		return "error parsing denied options";
	return NULL;
}

/* ============================ get_command_index () ======================= */
/* INPUT:  command, a pm_command_t array full of commands
 *         name, the name of the command that is being looked for
 * OUTPUT: the index into the pm_command_t cooresponding to name
 */
static command_type_t
get_command_index(const pm_command_t command[], const char *name)
{
	int i;

	/* FIXME: need to assert(command[i])? */
	for (i = 0; command[i].type != -1; i++) {
		assert(command[i].command_name != NULL);
	}
	assert(name);

	for (i = 0; command[i].type != -1; i++)
		if (strcmp(command[i].command_name, name) == 0)
			return command[i].type;
	return -1;
}

/* ============================ read_command () ============================ */
/* NOTE: callback function for reading command configurations
 *       command array must be initialized to [ 0x00, ..., 0x00 ]
 *       (see initconfig)
 *       mount.c's functions do checks on command array before it tries to 
 *       execv anything so don't worry about missing configurations */
static DOTCONF_CB(read_command)
{
#define COMMAND(n) ((config_t *) cmd->option->info)->command[(n)][command_index]
	int i;
	command_type_t command_index;

	assert(cmd);
	assert(cmd->name);
	assert(cmd->context);
	assert(cmd->data.list);
	assert(cmd->option);
	assert(cmd->option->info);
	assert(((config_t *) cmd->option->info)->command);
	for (i = 0; i < cmd->arg_count; i++) {
		/* FIXME: causes seg. fault, command_index not set: assert(COMMAND(i) == NULL); */
		assert(cmd->data.list[i]);
	}
	/* FIXME: causes seg. fault, command_index not set: assert(COMMAND(i) == NULL); */

	if (!*((int *) cmd->context))
		return "tried to set command from user config";
	if ((command_index = get_command_index(command, cmd->name)) == -1)
		return "pam_mount: bad command in config";
	if (cmd->arg_count <= 0)
		return "command type specified without definition";
	for (i = 0; i < cmd->arg_count; i++)
		if (strlen(cmd->data.list[i]) > MAX_PAR)
			return "command too long";
	COMMAND(0) = g_strdup(cmd->data.list[0]);
	COMMAND(1) = g_strdup(g_basename(cmd->data.list[0]));
	for (i = 1; i < cmd->arg_count; i++) {
		if (i > MAX_PAR)
			return
			    "pam_mount: command line configured to be too long";
		COMMAND(i + 1) = g_strdup(cmd->data.list[i]);
	}
	return NULL;
}

/* ============================ _option_in_list () ========================= */
/* INPUT:  haystack, an optlist_t to search
 *         needle, a key to look for
 * OUTPUT: 1 if haystack[needle] exists, else 0
 */
static int _option_in_list(optlist_t * haystack, const char *needle)
{
	assert(needle);

	/* FIXME: this fn. is not needed, just call the following directly: */
	return optlist_exists(haystack, needle);
}

/* ============================ options_allow_ok () ======================== */
/* INPUT:  allowed, an optlist of allowed options
 *         options, a list of options
 * OUTPUT: if options acceptable 1 else 0
 * SIDE AFFECTS: error logged 
 */
static options_allow_ok(optlist_t * allowed, optlist_t * options)
{
	optlist_t *e;

	if (optlist_exists(allowed, "*") || !optlist_len(options))
		return 1;
	for (e = options; e; e = optlist_next(e))
		if (!_option_in_list(allowed, optlist_key(e))) {
			l0g("pam_mount: option %s not allowed\n",
			    optlist_key(e));
			return 0;
		}
	return 1;
}

/* ============================ options_required_ok () ===================== */
/* INPUT:  required, an optlist of required options
 *         options, a list of options
 * OUTPUT: if options acceptable 1 else 0
 * SIDE AFFECTS: error logged
 */
static options_required_ok(optlist_t * required, optlist_t * options)
{
	optlist_t *e;
	for (e = required; e; e = optlist_next(e))
		if (!_option_in_list(options, optlist_key(e))) {
			l0g("pam_mount: option %s required\n",
			    optlist_key(e));
			return 0;
		}
	return 1;
}

/* ============================ options_deny_ok () ========================= */
/* INPUT:  denied, an optlist of denied options
 *         options, a list of options
 * OUTPUT: if options acceptable 1 else 0
 * SIDE AFFECTS: error logged
 */
static options_deny_ok(optlist_t * denied, optlist_t * options)
{
	optlist_t *e;
	if (!optlist_len(denied)) {
		w4rn("pam_mount: %s\n", "no denied options");
		return 1;
	} else if (optlist_exists(denied, "*") && optlist_len(options)) {
		l0g("pam_mount: %s\n",
		    "all mount options denied, user tried to specify one");
		return 0;
	}
	for (e = denied; e; e = optlist_next(e))
		if (_option_in_list(options, optlist_key(e))) {
			l0g("pam_mount: option %s denied\n",
			    optlist_key(e));
			return 0;
		}
	return 1;
}

/* ============================ _options_ok () ============================= */
/* INPUT:  config, the configuration to use as a basis for checking
 *         volume, a volume to check
 * OUTPUT: if volume checks okay 1, else 0
 * SIDE AFFECTS: error logged
 */
static int _options_ok(config_t * config, vol_t * volume)
{

	assert(config);
	assert(volume);

	if (optlist_len(config->options_allow)
	    && optlist_len(config->options_deny)) {
		l0g("pam_mount: %s\n",
		    "possible conflicting option settings (use allow OR deny)");
		return 0;
	}
	if (volume->use_fstab == FALSE)
		if (!options_required_ok
		    (config->options_require, volume->options))
			return 0;
		else if (optlist_len(config->options_allow)) {
			if (!options_allow_ok(config->
					      options_allow,
					      volume->options))
				return 0;
		} else if (optlist_len(config->options_deny)) {
			if (!options_deny_ok(config->
					     options_deny,
					     volume->options))
				return 0;
		} else if (optlist_len(volume->options)) {
			l0g("pam_mount: %s\n",
			    "user specified options denied by default");
			return 0;
		}
	return 1;
}

/* ============================ luserconf_volume_record_sane () ============ */
/* PRE:    config points to a valid config_t structure
		vol...
*/
/* FIXME: check to ensure input is legal and reject all else instead of rejecting everyhing that is illegal */
gboolean luserconf_volume_record_sane(config_t * config, int vol)
{
	/* FIXME: assertions not done */
	assert(config != NULL);
	assert(config->volume != NULL);

	if (config->volume[vol].used_wildcard == TRUE) {
		l0g("pam_mount: wildcard used in user-defined volume\n");
		return FALSE;
	}
	if (config->volume[vol].type == LCLMOUNT
	    && owns(config->user, config->volume[vol].volume) == FALSE) {
		l0g("pam_mount: user-defined volume, volume not owned by user\n");
		return FALSE;
	}
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	if (config->volume[vol].type == CRYPTMOUNT
	    && owns(config->user, config->volume[vol].volume) == FALSE) {
		l0g("pam_mount: user-defined volume, volume not owned by user\n");
		return FALSE;
	}
	/*
	 * If it does not already exist then its okay, pam_mount will mkdir
	 * it (if configured to do so)
	 */
	if (config->volume[vol].type == LCLMOUNT
	    && exists(config->volume[vol].mountpoint)
	    && owns(config->user, config->volume[vol].mountpoint) == FALSE) {
		l0g("pam_mount: user-defined volume, mountpoint not owned by user\n");
		return FALSE;
	}
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	if (config->volume[vol].type == CRYPTMOUNT
	    && exists(config->volume[vol].mountpoint)
	    && owns(config->user, config->volume[vol].mountpoint) == FALSE) {
		l0g("pam_mount: user-defined volume, mountpoint not owned by user\n");
		return FALSE;
	}
	if (!_options_ok(config, &config->volume[vol])) {
		l0g("pam_mount: illegal option specified by user\n");
		return FALSE;
	}
	return TRUE;
}

/* ============================ volume_record_sane () ====================== */
/* PRE:    config points to a valid config_t structure
 * FN VAL: if error string error message else NULL */
/* FIXME: check to ensure input is legal and reject all else instead of rejecting everyhing that is illegal */
gboolean volume_record_sane(config_t * config, int vol)
{
	w4rn("pam_mount: %s\n", "checking sanity of volume record");
	if (!config->command[0][config->volume[vol].type]) {
		l0g("mount command not defined for this type\n");
		return FALSE;
	}
	if ((config->volume[vol].type == SMBMOUNT
	     || config->volume[vol].type == NCPMOUNT
	     || config->volume[vol].type == CIFSMOUNT
	     || config->volume[vol].type == NFSMOUNT)
	    && !strlen(config->volume[vol].server)) {
		l0g("remote mount type specified without server\n");
		return FALSE;
	}
	if (config->volume[vol].type == NCPMOUNT && ! optlist_exists(config->volume[vol].options, "user")) {
		l0g("NCP volume definition missing user option\n");
		return FALSE;
	}
	if (!config->command[0][UMOUNT]) {
		l0g("umount command not defined\n");
		return FALSE;
	}
	if (strlen(config->volume[vol].fs_key_cipher)
	    && !strlen(config->volume[vol].fs_key_path)) {
		l0g("fs_key_cipher defined without fs_key_path\n");
		return FALSE;
	}
	if (!strlen(config->volume[vol].fs_key_cipher)
	    && strlen(config->volume[vol].fs_key_path)) {
		l0g("fs_key_path defined without fs_key_cipher\n");
		return FALSE;
	}
	return TRUE;
}

/* ============================ read_luserconf () ========================== */
/* NOTE: callback function for reading configuration parameters */
static DOTCONF_CB(read_luserconf)
{
	char *home_dir;
	struct passwd *passwd_ent;
	if (!*((int *) cmd->context))
		return "tried to set luserconf from user config";
	passwd_ent = getpwnam(((config_t *) cmd->option->info)->user);
	if (!passwd_ent) {
		home_dir = "~";
	} else {
		home_dir = passwd_ent->pw_dir;
	}
	if (strlen(home_dir) + strlen("/") + strlen(cmd->data.str) >
	    PATH_MAX)
		return "expanded luserconf path too long";
	strcpy(((config_t *) cmd->option->info)->luserconf, home_dir);
	strcat(((config_t *) cmd->option->info)->luserconf, "/");
	strcat(((config_t *) cmd->option->info)->luserconf, cmd->data.str);
	w4rn("pam_mount: path to luserconf set to %s\n",
	     ((config_t *) cmd->option->info)->luserconf);
	return NULL;
}

/* ============================ read_fsckloop () =========================== */
/* NOTE: callback function for reading configuration parameters */
static DOTCONF_CB(read_fsckloop)
{
	if (!*((int *) cmd->context))
		return "tried to set fsckloop from user config";
	if (strlen(cmd->data.str) > PATH_MAX)
		return "fsckloop path too long";
	strncpy(((config_t *) cmd->option->info)->fsckloop, cmd->data.str,
		PATH_MAX);
	((config_t *) cmd->option->info)->fsckloop[PATH_MAX] = 0x00;
	return NULL;
}

/* ============================ read_int_param () ========================== */
/* NOTE: callback function for reading configuration parameters */
static DOTCONF_CB(read_int_param)
{
	if (!*((int *) cmd->context))
		return "tried to set int param from user config";
	*((int *) cmd->option->info) = cmd->data.value;
	return NULL;
}

/* ============================ read_debug () ============================== */
/* NOTE: callback function for reading debug parameter */
static DOTCONF_CB(read_debug)
{
	/* debug is handled as a special case so global debug can be set ASAP */
	debug = (cmd->data.value != 0);
	return read_int_param(cmd, ctx);
}

/* ============================ fstab_value () ============================= */
static int
fstab_value(const char *volume, const fstab_field_t field, char *value,
	    const int size)
/* PRE:    volume points to a valid string != NULL
 *         0 <= field < 4 (last two fields are integers) 
 *         value points to a valid string of size size
 * POST:   value points to the volume's field'th field from /etc/fstab
 * FN VAL: if error 0 else 1, errors are logged
 */
{
#if defined(__linux__)
	char *val;
	FILE *fstab;
	struct mntent *fstab_record;
	if (!(fstab = setmntent("/etc/fstab", "r"))) {
		l0g("pam_mount: could not open fstab\n");
		return 0;
	}
	fstab_record = getmntent(fstab);
	while (fstab_record && strcmp(fstab_record->mnt_fsname, volume))
		fstab_record = getmntent(fstab);
	if (!fstab_record) {
		l0g("pam_mount: could not get %dth fstab field for %s\n",
		    field, volume);
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
		l0g("pam_mount: field of %d invalid\n", field);
		return 0;
	}
	if (strlen(val) > size - 1) {
		l0g("pam_mount: %dth fstab field for %s too long", field,
		    volume);
		return 0;
	}
	strncpy(value, val, size - 1);
	value[size - 1] = 0x00;
	endmntent(fstab);
	return 1;
#elif defined (__FreeBSD__) || defined (__OpenBSD__)
	FIXME ! this code was torn out of another function and needs to be
	    modified.struct fstab *fstab_record;
	if (!setfsent()) {
		l0g("pam_mount: could not open fstab to determine mount point for %s\n", volume);
		return 0;
	}
	if (!(fstab_record = getfsspec(volume))) {
		l0g("pam_mount: could not determine mount point for %s\n",
		    volume);
		return 0;
	}
	if (strlen(fstab_record->fs_file) > FIXME MAX_PAR) {
		l0g("pam_mount: mnt point listed in /etc/fstab for %s too long", volume);
		return 0;
	}
	strncpy(mountpoint, fstab_record->fs_file, FIXME MAX_PAR);
	mountpoint[FIXME MAX_PAR] = 0x00;
	return 1;
#else
	/* FIXME */
	l0g("pam_mount: %s\n", "reading fstab not implemented on arch.");
	return 0;
#endif
}

/* ============================ read_volume () ============================= */
/* NOTE: callback function for reading volume parameters */
static DOTCONF_CB(read_volume)
{
#define VOL ((config_t *)cmd->option->info)->volume
#define VOLCOUNT ((config_t *)cmd->option->info)->volcount
	int i;
	char *errmsg;
	if (cmd->arg_count != 8)
		return "bad number of args for volume";
	else if (*((int *) cmd->context) && strcmp
		 (cmd->data.list[0],
		  ((config_t *) cmd->option->info)->user)
		 && strcmp(cmd->data.list[0], "*")) {
		/*
		 * user may use other usernames to mount volumes using
		 * luserconf
		 */
		w4rn("pam_mount: ignoring volume record (not for me)\n");
		return NULL;
	} else if (!strcmp(cmd->data.list[0], "*")
		   && !strcmp(config.user, "root")) {
		/* FIXME: should use uid == 0, not "root" */
		w4rn("pam_mount: volume wildcard ignored for root");
		return NULL;
	}
	for (i = 0; i < cmd->arg_count; i++)
		if (strlen(cmd->data.list[i]) > MAX_PAR)
			return "command too long";
	VOL = g_realloc(VOL, sizeof(vol_t) * (VOLCOUNT + 1));
	memset(&VOL[VOLCOUNT], 0x00, sizeof(vol_t));
	VOL[VOLCOUNT].globalconf = *((int *) cmd->context) ? TRUE : FALSE;
	strncpy(VOL[VOLCOUNT].user, cmd->data.list[0], MAX_PAR);
	VOL[VOLCOUNT].type = -1;
	for (i = 0; command[i].type != -1; i++)
		if (command[i].fs
		    && !strcasecmp(cmd->data.list[1], command[i].fs)) {
			VOL[VOLCOUNT].type = command[i].type;
			break;
		}
	if (VOL[VOLCOUNT].type == -1)
		return "filesystem not supported";
	if (*cmd->data.list[2] == '-')
		*VOL[VOLCOUNT].server = 0x00;
	else
		strncpy(VOL[VOLCOUNT].server, cmd->data.list[2], MAX_PAR);
	strncpy(VOL[VOLCOUNT].volume, cmd->data.list[3], MAX_PAR);
	if (*cmd->data.list[4] == '-') {
		if (!fstab_value
		    (VOL[VOLCOUNT].volume, FSTAB_MNTPT,
		     VOL[VOLCOUNT].mountpoint, PATH_MAX + 1))
			return "could not determine mount point";
		VOL[VOLCOUNT].use_fstab = TRUE;
	} else
		strncpy(VOL[VOLCOUNT].mountpoint, cmd->data.list[4],
			MAX_PAR);
	if (*cmd->data.list[5] == '-') {
		/* three options: field defined, field is '-' and fstab 
		 * should be used (when no mount point was provided either) 
		 * or field is '-' and this means no options */
		if (VOL[VOLCOUNT].use_fstab) {
			char options[MAX_PAR + 1];
			if (!fstab_value
			    (VOL[VOLCOUNT].volume, FSTAB_OPTS, options,
			     MAX_PAR + 1))
				return "could not determine options";
			if (!str_to_optlist
			    (&VOL[VOLCOUNT].options, options))
				return "error parsing mount options";
		} else
			VOL[VOLCOUNT].options = NULL;
	} else
	    if (!str_to_optlist(&VOL[VOLCOUNT].options, cmd->data.list[5]))
		return "error parsing mount options";
	if (*cmd->data.list[6] == '-')
		*VOL[VOLCOUNT].fs_key_cipher = 0x00;
	else
		strncpy(VOL[VOLCOUNT].fs_key_cipher, cmd->data.list[6],
			MAX_PAR);
	if (*cmd->data.list[7] == '-')
		*VOL[VOLCOUNT].fs_key_path = 0x00;
	else
		strncpy(VOL[VOLCOUNT].fs_key_path, cmd->data.list[7],
			MAX_PAR);
	VOL[VOLCOUNT].used_wildcard = FALSE; /* expandconfig() sets this */
	/* FIXME: these should l0g an error and return NULL so other volumes can continue */
	VOLCOUNT++;
	return NULL;
#undef VOL
#undef VOLCOUNT
}

/* ============================ readconfig () ============================== */
/* PRE:    user is a valid string != NULL
 *         file is the path of config file to read
 *         globalconf == TRUE if file is a global config, else FALSE
 *         config points to a valid config_t structure
 * POST:   command is an array containing configured mount command lines
 *         config points to a config_t structure containing configuration read
 * FN VAL: if error 0 else 1, errors are logged */
int
readconfig(const char *user, char *file, int globalconf, config_t * config)
{
	configfile_t *configfile;
	if (!
	    (configfile =
	     dotconf_create(file, legal_config, &globalconf, NONE))) {
		l0g("pam_mount: error opening %s\n", file);
		return 0;
	}
	configfile->errorhandler = (dotconf_errorhandler_t) log_error;
	if (!dotconf_command_loop(configfile))
		l0g("pam_mount: error reading %s\n", file);	/* may not be fatal */
	dotconf_cleanup(configfile);
	return 1;
}

/* ============================ initconfig () ============================== */
/* PRE:  config points to a valid config_t structure
 * POST: config is initialized (ie: config.volcount == 0) */
int initconfig(config_t * config)
{
	int i, j;
	config->user = NULL;
	config->volcount = 0;
	config->debug = DEBUG_DEFAULT;
	config->mkmountpoint = MKMOUNTPOINT_DEFAULT;
	strcpy(config->fsckloop, FSCKLOOP_DEFAULT);

	/* set commands to defaults */
	for (i = 0; command[i].type != -1; i++) {
		config->command[0][command[i].type] = g_strdup(command[i].def[0]);
		config->command[1][command[i].type] = g_strdup(g_basename(command[i].def[0]));
		for (j = 1; command[i].def[j]; j++) {
			config->command[j + 1][command[i].type] = g_strdup(command[i].def[j]);
		}
		config->command[j + 1][command[i].type] = 0x00;
	}
	/* FIXME: post condition assert all commands not NULL and NULL terminated */
	return 1;
}

/* ============================ freeconfig () ============================== */
/* PRE:  config is a valid, initialized config_t structure
 * POST: all dynamically allocated memory in config is freed */
void freeconfig(config_t config)
{
	int i = 0, j = 0;
	/* FIXME: not implemented:
	   optlist_free(&config.options_require);
	   optlist_free(&config.options_allow);
	   optlist_free(&config.options_deny);
	   for (i = 0; i < config.volcount; i++)
	   optlist_free(&config.volume[i].options); FIXME: May be NULL!!
	 */
	if (config.user != NULL)
		g_free(config.user);
	for (i = 0; i < COMMAND_MAX; i++)
		for (j = 0; config.command[j][i]; j++)
			g_free(config.command[j][i]);
}

/* ============================ expand_home () ============================= */
/* PRE:    path points to the path to expand (ie: ~/foo)
 *         path_size = sizeof(path)
 *         user points to a valid string != NULL
 * FN VAL: expanded path (ie: /home/usr/foo) or NULL on error */
static char *expand_home(char *path, size_t path_size, const char *user)
{
	size_t seg_len;
	struct passwd *p = getpwnam(user);
	char *src;
	src = g_strdup(path);
	if (p) {
		/* - 1 because ~ is dropped from str */
		if ((seg_len =
		     strlen(p->pw_dir) + strlen(src) - 1) < path_size) {
			strcpy(path, p->pw_dir);
			strcat(path, src + 1);	/* skip leading '~' */
		} else {
			l0g("pam_mount: destination string to short\n");
			g_free(src);
			return NULL;
		}
	} else {
		l0g("pam_mount: could not look up account information for %s", user);
		g_free(src);
		return NULL;
	}
	g_free(src);
	return path;
}

/* ============================ expand_wildcard () ========================= */
/* PRE:    dest points to a valid string
 *         dest_size = sizeof(dest)
 *         str points to the string to expand (must contain at least one &)
 *         user is the username to expand to
 * FN VAL: str with any &s expanded into user or NULL on error */
static char *expand_wildcard(char *dest, size_t dest_size, const char *str,
			     const char *user)
/* FIXME: this strdup/free is silly; req. dest and str point to diff. arrays? */
{
	char *pos, *src;
	w4rn("pam_mount: expand_wildcard for %s\n", str);
	if (str == NULL) {
		l0g("pam_mount %s\n", "tried to expand a NULL");
		return NULL;
	}
	src = g_strdup(str);
	pos = strchr(src, '&');
	if (pos) {
		size_t seg_len;
		/* - 1 because & is dropped from str */
		if (strlen(src) + strlen(user) - 1 < dest_size) {
			seg_len = pos - src;
			strcpy(dest, src);
			strcpy(dest + seg_len, user);
			if (!expand_wildcard
			    (dest + seg_len + strlen(user),
			     dest_size - seg_len - strlen(user),
			     src + seg_len + 1, user)) {
				g_free(src);
				return NULL;
			}
		} else {
			l0g("pam_mount %s\n",
			    "destination string to short");
			g_free(src);
			return NULL;
		}
	} else {
		strncpy(dest, src, dest_size);
		dest[dest_size - 1] = 0x00;
	}
	g_free(src);
	return (dest);
}

/* ============================ expandconfig () ============================ */
/* PRE:  config points to a valid config_t structure that has been filled
 * POST: any wildcards in config->data are expanded
 * FN VAL: if error 0 else 1, errors are logged */
int expandconfig(config_t * config)
{
	int i;
	for (i = 0; i < config->volcount; i++) {
		char tmp[MAX_PAR + 1];
		if (*config->volume[i].mountpoint == '~')
			if (!expand_home(config->volume[i].
					 mountpoint,
					 sizeof(config->volume[i].
						mountpoint), config->user))
				return 0;
		if (*config->volume[i].volume == '~')
			if (!expand_home(config->volume[i].
					 volume,
					 sizeof(config->volume[i].
						volume), config->user))
				return 0;
		if (*config->volume[i].fs_key_path == '~')
			if (!expand_home(config->volume[i].
					 fs_key_path,
					 sizeof(config->volume[i].
						fs_key_path),
					 config->user))
				return 0;
		if (!strcmp(config->volume[i].user, "*")) {
			optlist_t *e;
			config->volume[i].used_wildcard = TRUE;
			strcpy(config->volume[i].user, config->user);
			if (!expand_wildcard
			    (config->volume[i].volume,
			     sizeof(config->volume[i].volume),
			     config->volume[i].volume, config->user))
				return 0;
			if (!expand_wildcard(config->volume[i].
					     mountpoint,
					     sizeof(config->volume[i].
						    mountpoint),
					     config->volume[i].mountpoint,
					     config->user))
				return 0;
			for (e = config->volume[i].options;
			     e; e = optlist_next(e)) {
				if (!expand_wildcard
				    (tmp, sizeof(tmp), optlist_key(e),
				     config->user))
					return 0;
				optlist_key(e) = g_strdup(tmp);
				if (!expand_wildcard
				    (tmp, sizeof(tmp), optlist_val(e),
				     config->user))
					return 0;
				optlist_val(e) = g_strdup(tmp);
			}
			if (!expand_wildcard(config->volume[i].
					     fs_key_path,
					     sizeof(config->volume[i].
						    fs_key_path),
					     config->volume[i].fs_key_path,
					     config->user))
				return 0;
		}
	}
	return 1;
}
