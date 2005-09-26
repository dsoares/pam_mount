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

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>

#include "dotconf.h"
#include "misc.h"
#include "optlist.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#    include <fstab.h>
#elif defined(__linux__)
#    include <mntent.h>
#endif

#define DEBUG_DEFAULT           FALSE
#define MKMOUNTPOINT_DEFAULT    FALSE
#define FSCKLOOP_DEFAULT        "/dev/loop7"
#define PMPREFIX                "pam_mount: "

#define ICONTEXT (*(int *)cmd->context)
#define ICONFIG ((config_t *)cmd->option->info)

typedef enum fstab_field_t {
	FSTAB_VOLUME,
	FSTAB_MNTPT,
	FSTAB_FSTYPE,
	FSTAB_OPTS
} fstab_field_t;

/* defaults are included here but these are overridden by pam_mount.conf */
static pm_command_t Command[] = {
        {SMBMOUNT, "smb", "smbmount", {"/usr/bin/smbmount", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER)%(before=\",\" OPTIONS)", NULL}},
        {SMBMOUNT, "smbfs", "smbmount", {"/usr/bin/smbmount", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER)%(before=\",\" OPTIONS)", NULL}},
        {SMBUMOUNT, "smbfs", "smbumount", {"/usr/bin/smbumount", "%(MNTPT)", NULL}},
	{CIFSMOUNT, "cifs", "cifsmount", {"/bin/mount", "-t", "cifs", "//%(SERVER)/%(VOLUME)", "%(MNTPT)", "-o", "username=%(USER)%(before=\",\" OPTIONS)", NULL}},
        {NCPMOUNT, "ncp", "ncpmount", {"/usr/bin/ncpmount", "%(SERVER)/%(USER)", "%(MNTPT)", "-o", "pass-fd=0,volume=%(VOLUME)%(before=\",\" OPTIONS)", NULL}},
        {NCPMOUNT, "ncpfs", "ncpmount", {"/usr/bin/ncpmount", "%(SERVER)/%(USER)", "%(MNTPT)", "-o", "pass-fd=0,volume=%(VOLUME)%(before=\",\" OPTIONS)", NULL}},
        {NCPUMOUNT, "ncpfs", "ncpumount", {"/usr/bin/ncpumount", "%(MNTPT)", NULL}},
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
	{FSCK, NULL, "fsck", {"/sbin/fsck", "-p", "%(FSCKTARGET)", NULL}},
	{LOSETUP, NULL, "losetup", {"/sbin/losetup", "-p0", "%(before=\"-e \" CIPHER)", "%(before=\"-k \" KEYBITS)", "%(FSCKLOOP)", "%(VOLUME)", NULL}},
	{UNLOSETUP, NULL, "unlosetup", {"/sbin/losetup", "-d", "%(FSCKLOOP)", NULL}},
	{PMVARRUN, NULL, "pmvarrun", {"/usr/sbin/pmvarrun", "-u", "%(USER)", "-d", "-o", "%(OPERATION)", NULL}},
	{-1, NULL, NULL, {NULL}}
};

static char *expand_home(char *, size_t, const char *);
static char *expand_wildcard(char *, size_t, const char *, const char *);
static int fstab_value(const char *, const fstab_field_t, char *, const int);
static command_type_t get_command_index(const pm_command_t *, const char *);
static FUNC_ERRORHANDLER(log_error);
static DOTCONF_CB(read_command);
static DOTCONF_CB(read_debug);
static DOTCONF_CB(read_fsckloop);
static DOTCONF_CB(read_int_param);
static DOTCONF_CB(read_luserconf);
static DOTCONF_CB(read_options_allow);
static DOTCONF_CB(read_options_deny);
static DOTCONF_CB(read_options_require);
static int _options_ok(const config_t *, const vol_t *);
static int options_allow_ok(optlist_t *, optlist_t *);
static int options_deny_ok(optlist_t *, optlist_t *);
static int option_in_list(optlist_t *, const char *);
static int options_required_ok(optlist_t *, optlist_t *);

static const configoption_t legal_config[] = {
	{"debug", ARG_TOGGLE, read_debug, &Config.debug, CTX_ALL},
	{"mkmountpoint", ARG_TOGGLE, read_int_param, &Config.mkmntpoint,
	 CTX_ALL},
	{"luserconf", ARG_STR, read_luserconf, &Config, CTX_ALL},
	{"fsckloop", ARG_STR, read_fsckloop, &Config, CTX_ALL},
	{"smbmount", ARG_LIST, read_command, &Config, CTX_ALL},
        {"smbumount", ARG_LIST, read_command, &Config, CTX_ALL},
	{"cifsmount", ARG_LIST, read_command, &Config, CTX_ALL},
	{"ncpmount", ARG_LIST, read_command, &Config, CTX_ALL},
        {"ncpumount", ARG_LIST, read_command, &Config, CTX_ALL},
	{"umount", ARG_LIST, read_command, &Config, CTX_ALL},
	{"lclmount", ARG_LIST, read_command, &Config, CTX_ALL},
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	{"cryptmount", ARG_LIST, read_command, &Config, CTX_ALL},
	{"nfsmount", ARG_LIST, read_command, &Config, CTX_ALL},
	{"lsof", ARG_LIST, read_command, &Config, CTX_ALL},
	{"mntagain", ARG_LIST, read_command, &Config, CTX_ALL},
	{"mntcheck", ARG_LIST, read_command, &Config, CTX_ALL},
	{"fsck", ARG_LIST, read_command, &Config, CTX_ALL},
	{"losetup", ARG_LIST, read_command, &Config, CTX_ALL},
	{"unlosetup", ARG_LIST, read_command, &Config, CTX_ALL},
	{"pmvarrun", ARG_LIST, read_command, &Config, CTX_ALL},
	{"options_require", ARG_STR, read_options_require, &Config,
	 CTX_ALL},
	{"options_allow", ARG_STR, read_options_allow, &Config, CTX_ALL},
	{"options_deny", ARG_STR, read_options_deny, &Config, CTX_ALL},
	{"volume", ARG_LIST, read_volume, &Config, CTX_ALL},
	LAST_OPTION
};

/* ============================ log_error () =============================== */
/* NOTE: callback helper function for handling errors
 *       frees msg after logging it! */
static FUNC_ERRORHANDLER(log_error)
{
	l0g(PMPREFIX "%s\n", msg);
	/* FIXME: This free is broken.
	 * If an invalid command definition (ie: foomount) exists in 
	 * pam_mount.conf then su, loging, gdm, etc. segfault with:
	 * pam_mount: Unknown Config-Option: 'fsck'
	 * Segmentation fault
	 * Other circumstances will also cause this segfault.  For example.
	 * some functions do a return "foo."
	 free(msg);
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


	if(!ICONTEXT)
		return "tried to set options_require from user config";
	w4rn(PMPREFIX "reading options_require...\n");
	if(!str_to_optlist(&ICONFIG->options_require, cmd->data.str))
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

	if(!ICONTEXT)
		return "tried to set options_allow from user config";
	w4rn(PMPREFIX "reading options_allow...\n");
	if(!str_to_optlist(&ICONFIG->options_allow, cmd->data.str))
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

	if(!ICONTEXT)
		return "tried to set options_deny from user config";
	w4rn(PMPREFIX "reading options_deny...\n");
	if(!str_to_optlist(&ICONFIG->options_deny, cmd->data.str))
		return "error parsing denied options";
	return NULL;
}

/* ============================ get_command_index () ======================= */
/* INPUT:  command, a pm_command_t array full of commands
 *         name, the name of the command that is being looked for
 * OUTPUT: the index into the pm_command_t cooresponding to name
 */
static command_type_t
get_command_index(const pm_command_t *command, const char *name)
{
	int i;

	/* FIXME: need to assert(command[i])? */
	for (i = 0; command[i].type != -1; i++) {
		assert(command[i].command_name != NULL);
	}
	assert(name != NULL);

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
#define COMMAND(n) ICONFIG->command[(n)][command_index]
	int i;
	command_type_t command_index;

	assert(cmd != NULL);
	assert(cmd->name != NULL);
	assert(cmd->context != NULL);
	assert(cmd->data.list != NULL);
	assert(cmd->option != NULL);
	assert(ICONFIG != NULL);
	assert(ICONFIG->command != NULL);
	for (i = 0; i < cmd->arg_count; i++) {
		/* FIXME: causes seg. fault, command_index not set: assert(COMMAND(i) == NULL); */
		assert(cmd->data.list[i] != NULL);
	}
	/* FIXME: causes seg. fault, command_index not set: assert(COMMAND(i) == NULL); */

	if(!ICONTEXT)
		return "tried to set command from user config";
	if((command_index = get_command_index(Command, cmd->name)) == -1)
		return PMPREFIX "bad command in config";
	if (cmd->arg_count <= 0)
		return "command type specified without definition";
	for (i = 0; i < cmd->arg_count; i++)
		if (strlen(cmd->data.list[i]) > MAX_PAR)
			return "command too long";
	COMMAND(0) = g_strdup(cmd->data.list[0]);
	for (i = 1; i < cmd->arg_count; i++) {
		if (i > MAX_PAR)
                    return PMPREFIX "command line configured to be too long";
		COMMAND(i) = g_strdup(cmd->data.list[i]);
	}
	return NULL;
}

/* ============================ option_in_list () ========================== */
/* INPUT:  haystack, an optlist_t to search
 *         needle, a key to look for
 * OUTPUT: 1 if haystack[needle] exists, else 0
 */
static int option_in_list(optlist_t *haystack, const char *needle) {
	assert(needle != NULL);

	/* FIXME: this fn. is not needed, just call the following directly: */
	return optlist_exists(haystack, needle);
}

/* ============================ options_allow_ok () ======================== */
/* INPUT:  allowed, an optlist of allowed options
 *         options, a list of options
 * OUTPUT: if options acceptable 1 else 0
 * SIDE EFFECTS: error logged 
 */
static int options_allow_ok(optlist_t * allowed, optlist_t * options)
{
	optlist_t *e;

	if (optlist_exists(allowed, "*") || !optlist_len(options))
		return 1;
	for(e = options; e != NULL; e = optlist_next(e))
		if (!option_in_list(allowed, optlist_key(e))) {
                    l0g(PMPREFIX "option %s not allowed\n", optlist_key(e));
                    return 0;
		}
	return 1;
}

/* ============================ options_required_ok () ===================== */
/* INPUT:  required, an optlist of required options
 *         options, a list of options
 * OUTPUT: if options acceptable 1 else 0
 * SIDE EFFECTS: error logged
 */
static int options_required_ok(optlist_t * required, optlist_t * options)
{
	optlist_t *e;
	for(e = required; e != NULL; e = optlist_next(e))
		if (!option_in_list(options, optlist_key(e))) {
                    l0g(PMPREFIX "option %s required\n", optlist_key(e));
                    return 0;
		}
	return 1;
}

/* ============================ options_deny_ok () ========================= */
/* INPUT:  denied, an optlist of denied options
 *         options, a list of options
 * OUTPUT: if options acceptable 1 else 0
 * SIDE EFFECTS: error logged
 */
static int options_deny_ok(optlist_t * denied, optlist_t * options)
{
	optlist_t *e;
	if (!optlist_len(denied)) {
		w4rn(PMPREFIX "no denied options\n");
		return 1;
	} else if(optlist_exists(denied, "*") && optlist_len(options) > 0) {
		l0g(PMPREFIX "all mount options denied, user tried to specify one\n");
		return 0;
	}
	for(e = denied; e != NULL; e = optlist_next(e))
		if (option_in_list(options, optlist_key(e))) {
			l0g(PMPREFIX "option %s denied\n", optlist_key(e));
			return 0;
		}
	return 1;
}

/* ============================ _options_ok () ============================= */
/* INPUT:  config, the configuration to use as a basis for checking
 *         volume, a volume to check
 * OUTPUT: if volume checks okay 1, else 0
 * SIDE EFFECTS: error logged
 */
static int _options_ok(const config_t *config, const vol_t *volume) {

	assert(config != NULL);
	assert(volume != NULL);

	if(optlist_len(config->options_allow) > 0 &&
	    optlist_len(config->options_deny) > 0) {
		l0g(PMPREFIX "possible conflicting option settings (use allow OR deny)\n");
		return 0;
	}
	if (volume->use_fstab == FALSE) {
		if (!options_required_ok
		    (config->options_require, volume->options))
			return 0;
		else if(optlist_len(config->options_allow) > 0) {
			if (!options_allow_ok(config->
					      options_allow,
					      volume->options))
				return 0;
		} else if(optlist_len(config->options_deny) > 0) {
			if (!options_deny_ok(config->
					     options_deny,
					     volume->options))
				return 0;
		} else if(optlist_len(volume->options) > 0) {
			l0g(PMPREFIX "user specified options denied by default\n");
			return 0;
		}
	}
	return 1;
}

/* ============================ luserconf_volume_record_sane () ============ */
/* PRE:    config points to a valid config_t structure
		vol...
*/
/* FIXME: check to ensure input is legal and reject all else instead of rejecting everyhing that is illegal */
gboolean luserconf_volume_record_sane(const config_t * config, int vol) {
	/* FIXME: assertions not done */
	assert(config != NULL);
	assert(config->volume != NULL);

	if (config->volume[vol].used_wildcard == TRUE) {
		l0g(PMPREFIX "wildcard used in user-defined volume\n");
		return FALSE;
	}
	if (!_options_ok(config, &config->volume[vol])) {
		l0g(PMPREFIX "illegal option specified by user\n");
		return FALSE;
	}
	return TRUE;
}

/* ============================ volume_record_sane () ====================== */
/* PRE:    config points to a valid config_t structure
 * FN VAL: if error string error message else NULL */
/* FIXME: check to ensure input is legal and reject all else instead of rejecting everyhing that is illegal */
gboolean volume_record_sane(const config_t *config, int vol) {
	w4rn(PMPREFIX "checking sanity of volume record (%s)\n", config->volume[vol].volume);
	if (!config->command[0][config->volume[vol].type]) {
		l0g("mount command not defined for this type\n");
		return FALSE;
	}
	if ((config->volume[vol].type == SMBMOUNT
	     || config->volume[vol].type == NCPMOUNT
	     || config->volume[vol].type == CIFSMOUNT
	     || config->volume[vol].type == NFSMOUNT)
	    && strlen(config->volume[vol].server) == 0) {
		l0g("remote mount type specified without server\n");
		return FALSE;
	}
	if (config->volume[vol].type == NCPMOUNT && ! optlist_exists(config->volume[vol].options, "user")) {
		l0g("NCP volume definition missing user option\n");
		return FALSE;
	}
	if(config->command[0][UMOUNT] == NULL) {
		l0g("umount command not defined\n");
		return FALSE;
	}
	if(strlen(config->volume[vol].fs_key_cipher) > 0 &&
	    strlen(config->volume[vol].fs_key_path) == 0) {
		l0g("fs_key_cipher defined without fs_key_path\n");
		return FALSE;
	}
	if(strlen(config->volume[vol].fs_key_cipher) == 0 &&
	    strlen(config->volume[vol].fs_key_path) > 0) {
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
	if(!ICONTEXT)
		return "tried to set luserconf from user config";
	passwd_ent = getpwnam(ICONFIG->user);
	if(passwd_ent == NULL) {
		home_dir = "~";
	} else {
		home_dir = passwd_ent->pw_dir;
	}
	if (strlen(home_dir) + strlen("/") + strlen(cmd->data.str) >
	    PATH_MAX)
		return "expanded luserconf path too long";
	strcpy(ICONFIG->luserconf, home_dir);
	strcat(ICONFIG->luserconf, "/");
	strcat(ICONFIG->luserconf, cmd->data.str);
	w4rn(PMPREFIX "path to luserconf set to %s\n", ICONFIG->luserconf);
	return NULL;
}

/* ============================ read_fsckloop () =========================== */
/* NOTE: callback function for reading configuration parameters */
static DOTCONF_CB(read_fsckloop)
{
	if(!ICONTEXT)
		return "tried to set fsckloop from user config";
	if (strlen(cmd->data.str) > PATH_MAX)
		return "fsckloop path too long";
	strncpy(ICONFIG->fsckloop, cmd->data.str, PATH_MAX);
	ICONFIG->fsckloop[PATH_MAX] = '\0';
	return NULL;
}

/* ============================ read_int_param () ========================== */
/* NOTE: callback function for reading configuration parameters */
static DOTCONF_CB(read_int_param)
{
	if(!ICONTEXT)
		return "tried to set int param from user config";
	*((int *) cmd->option->info) = cmd->data.value;
	return NULL;
}

/* ============================ read_debug () ============================== */
/* NOTE: callback function for reading debug parameter */
static DOTCONF_CB(read_debug)
{
	/* debug is handled as a special case so global debug can be set ASAP */
	Debug = cmd->data.value != 0;
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
	char *val;
#if defined(__linux__)
	FILE *fstab;
	struct mntent *fstab_record;
	if((fstab = setmntent("/etc/fstab", "r")) == NULL) {
		l0g(PMPREFIX "could not open fstab\n");
		return 0;
	}
	fstab_record = getmntent(fstab);
	while(fstab_record != NULL && strcmp(fstab_record->mnt_fsname, volume) != 0)
		fstab_record = getmntent(fstab);
	if(fstab_record == NULL) {
		l0g(PMPREFIX "could not get %dth fstab field for %s\n",
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
		l0g(PMPREFIX "field of %d invalid\n", field);
		return 0;
	}
#elif defined (__FreeBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	struct fstab *fstab_record;
	if (!setfsent()) {
		l0g(PMPREFIX "could not open fstab to determine mount point for %s\n", volume);
		return 0;
	}
	if((fstab_record = getfsspec(volume)) == NULL) {
		l0g(PMPREFIX "could not get %dth fstab field for %s\n",
		    field, volume);
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
		l0g(PMPREFIX "field of %d invalid\n", field);
		return 0;
	}
#else
	/* FIXME */
	l0g(PMPREFIX "reading fstab not implemented on arch.\n");
	return 0;
#endif
	strncpy(value, val, size - 1);
	value[size - 1] = '\0';
#if defined(__linux__)
	endmntent(fstab);
#elif defined (__FreeBSD__) || defined (__OpenBSD__) || defined(__APPLE__)
	endfsent();
#endif
	return 1;
}

/* ============================ read_volume () ============================= */
/* NOTE: callback function for reading volume parameters */
DOTCONF_CB(read_volume)
{
#define VOL ICONFIG->volume
#define VOLCOUNT ICONFIG->volcount
	int i;
	if (cmd->arg_count != 8)
		return "bad number of args for volume";
	else if(ICONTEXT && strcmp(cmd->data.list[0], ICONFIG->user) != 0 &&
	    strcmp(cmd->data.list[0], "*") != 0) {
		/*
		 * user may use other usernames to mount volumes using
		 * luserconf
		 */
		w4rn(PMPREFIX "ignoring volume record (not for me)\n");
		return NULL;
	} else if(strcmp(cmd->data.list[0], "*") == 0 &&
            strcmp(Config.user, "root") == 0) {
		/* FIXME: should use uid == 0, not "root" */
		w4rn(PMPREFIX "volume wildcard ignored for root\n");
		return NULL;
	}
	for (i = 0; i < cmd->arg_count; i++)
		if (strlen(cmd->data.list[i]) > MAX_PAR)
			return "command too long";
	VOL = g_realloc(VOL, sizeof(vol_t) * (VOLCOUNT + 1));
	memset(&VOL[VOLCOUNT], 0, sizeof(vol_t));
	VOL[VOLCOUNT].globalconf = ICONTEXT ? TRUE : FALSE;
	strncpy(VOL[VOLCOUNT].user, cmd->data.list[0], MAX_PAR);
	VOL[VOLCOUNT].type = -1;
	for(i = 0; Command[i].type != -1; ++i)
		if(Command[i].fs != NULL &&
		    strcasecmp(cmd->data.list[1], Command[i].fs) == 0) {
			VOL[VOLCOUNT].type = Command[i].type;
			break;
		}
	if (VOL[VOLCOUNT].type == -1)
		return "filesystem not supported";
	if (*cmd->data.list[2] == '-')
		*VOL[VOLCOUNT].server = '\0';
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
			     sizeof(options)))
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
		*VOL[VOLCOUNT].fs_key_cipher = '\0';
	else
		strncpy(VOL[VOLCOUNT].fs_key_cipher, cmd->data.list[6],
			MAX_PAR);
	if (*cmd->data.list[7] == '-')
		*VOL[VOLCOUNT].fs_key_path = '\0';
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
int readconfig(const char *user, const char *file, int globalconf,
 config_t *config)
{
	configfile_t *configfile;
	if(
	    (configfile =
	     dotconf_create(file, legal_config, &globalconf, 0)) == NULL) {
		l0g(PMPREFIX "error opening %s: %s\n", file, strerror(errno));
		return 0;
	}
	configfile->errorhandler = (dotconf_errorhandler_t) log_error;
        if(!dotconf_command_loop(configfile)) {
            // may not be fatal
            l0g(PMPREFIX "error reading %s: %s\n", file, strerror(errno));
        }
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
	config->debug = DEBUG_DEFAULT;
	config->mkmntpoint = MKMOUNTPOINT_DEFAULT;
	config->volcount = 0;
	/* FIXME: initialize luserconf */
	strcpy(config->fsckloop, FSCKLOOP_DEFAULT);

	/* set commands to defaults */
	for(i = 0; Command[i].type != -1; i++) {
		config->command[0][Command[i].type] = g_strdup(Command[i].def[0]);
		for(j = 1; Command[i].def[j] != NULL; j++) {
			config->command[j][Command[i].type] = g_strdup(Command[i].def[j]);
		}
		config->command[j + 1][Command[i].type] = NULL;
	}

	/* FIXME: initialize options_require, _allow and _deny */

	config->volume = NULL;
	/* FIXME: post condition assert all commands not NULL and NULL terminated */
	return 1;
}

/* ============================ freeconfig () ============================== */
/* PRE:  config is a valid, initialized config_t structure
 * POST: all dynamically allocated memory in config is freed */
void freeconfig(config_t *config)
{
	int i = 0, j = 0;
	/* FIXME: not implemented:
	   optlist_free(&config.options_require);
	   optlist_free(&config.options_allow);
	   optlist_free(&config.options_deny);
	   for (i = 0; i < config.volcount; i++)
	   optlist_free(&config.volume[i].options); FIXME: May be NULL!!
	 */
        if(config->user != NULL)
		g_free(config->user);
	for (i = 0; i < COMMAND_MAX; i++)
		for(j = 0; config->command[j][i]; j++)
			g_free(config->command[j][i]);
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
	if(p != NULL) {
		/* - 1 because ~ is dropped from str */
		if ((seg_len =
		     strlen(p->pw_dir) + strlen(src) - 1) < path_size) {
			strcpy(path, p->pw_dir);
			strcat(path, src + 1);	/* skip leading '~' */
		} else {
			l0g(PMPREFIX "destination string to short\n");
			g_free(src);
			return NULL;
		}
	} else {
            l0g(PMPREFIX "could not look up account information for %s\n", user);
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
	w4rn(PMPREFIX "expand_wildcard for %s\n", str);
	if (str == NULL) {
		l0g(PMPREFIX "tried to expand a NULL\n");
		return NULL;
	}
	src = g_strdup(str);
	pos = strchr(src, '&');
	if(pos != NULL) {
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
		dest[dest_size - 1] = '\0';
	}
	g_free(src);
	return dest;
}

/* ============================ expandconfig () ============================ */
/* PRE:  config points to a valid config_t structure that has been filled
 * POST: any wildcards in config->data are expanded
 * FN VAL: if error 0 else 1, errors are logged */
int expandconfig(const config_t *config) {
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
		if(strcmp(config->volume[i].user, "*") == 0) {
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
			     e != NULL; e = optlist_next(e)) {
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
