/*   FILE: misc.c
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
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <assert.h>
#include <glib.h>
#include <stdlib.h>
#include <security/pam_modules.h>
#include <pam_mount.h>

#ifdef HAVE_SETFSUID
#include <sys/fsuid.h>
#endif

extern int debug;

/* ============================ l0g () ===================================== */
/* INPUT: similar to printf; all args are valid strings != NULL
 * SIDE AFFECTS: format + args are logged and displayed */
void l0g(const char *format, ...)
{
	/* Used to log issues that cause pam_mount to fail. */
	va_list args;

	assert(format != NULL);

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	va_start(args, format);
/* This code needs root priv? */
	vsyslog(LOG_AUTHPRIV | LOG_ERR, format, args);
/* end root priv. */
	va_end(args);
}

/* ============================ w4rn () ==================================== */
/* INPUT: similar to printf; all args are valid string != NULL
 * SIDE AFFECTS: format + args are logged and displayed iff debug == 1
 * NOTE: Used to log informational messages and issues that should not cause
 *       pam_mount to fail. */
void w4rn(const char *format, ...)
{
	assert(format != NULL);

	if (debug != 0) {
		va_list args;
		va_start(args, format);
		vfprintf(stderr, format, args);
		va_end(args);
		va_start(args, format);
/* This code needs root priv? */
		vsyslog(LOG_AUTHPRIV | LOG_ERR, format, args);
/* end root priv. */
		va_end(args);
	}
}

/* ============================ exists () ================================== */
/* INPUT: file, a file path
 * OUTPUT: 0 if file does not exist, -1 if file is a symlink, or 1 if file 
 *         is normal and exists */
int exists(const char *file)
{
	struct stat filestat;

	assert(file != NULL);

	if (stat(file, &filestat) != 0) {
		return 0;
	}
	if (S_ISLNK(filestat.st_mode)) {
		return -1;
	}
	return 1;
}

/* ============================ owns () ==================================== */
/* INPUT: user, a username; file, a file path
 * OUTPUT: FALSE if user does not own file or TRUE if user owns file */
gboolean owns(const char *user, const char *file)
{
	struct stat filestat;
	struct passwd *userinfo;

	assert(user != NULL);
	assert(file != NULL);

	userinfo = getpwnam(user);
	if (!userinfo) {
		l0g("pam_mount: user %s could not be translated to UID\n",
		    user);
		return FALSE;
	}

	if (stat(file, &filestat) != 0) {
		w4rn("pam_mount: file %s could not be stat'ed\n", file);
		return FALSE;
	}

	if ((filestat.st_uid == userinfo->pw_uid)
	    && !S_ISLNK(filestat.st_mode))
		return TRUE;
	return FALSE;
}

/* ============================ str_to_long () ============================= */
long str_to_long(char *n)
/* INPUT: n, a string
 * SIDE AFFECT: errors are logged
 * OUTPUT: if error LONG_MAX or LONG_MIN else long value of n
 * NOTE:   this is needed because users own /var/run/pam_mount/<user> 
 *         and they could try something sneaky
 *         FIXME: the above NOTE may no longer be true
 */
{
	long val;
	char *endptr = NULL;
	if (!n) {
		l0g("pam_mount: %s\n", "count string is NULL");
		return LONG_MAX;
	}
	val = strtol(n, &endptr, 10);
	if (*endptr) {
		l0g("pam_mount: count string is not valid\n");
		return LONG_MAX;
	}
	return val;
}

/* ============================ string_valid () ============================ */
static gboolean static_string_valid(const char *s, const int len)
{
	int i;
	if (s == NULL)
		return FALSE;
	/* make sure there is a terminating NULL */
	for (i = 0; i < len; i++)
		if (s[i] == 0x00)
			return TRUE;
	return FALSE;
}

/* ============================ pm_command_t_valid () ====================== */
gboolean pm_command_t_valid(const pm_command_t * c)
{
	/* FIXME */
	return TRUE;
}

/* ============================ vol_t_valid () ============================= */
gboolean vol_t_valid(const vol_t * v)
{
	if (v == NULL)
		return FALSE;
	if (!(0 <= v->type && v->type < COMMAND_MAX))
		return FALSE;
	/* should be guaranteed by volume_record_sane() */
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	if (!((v->type == LCLMOUNT || v->type == CRYPTMOUNT)
	      || strlen(v->server) > 0))
		return FALSE;
	/* gboolean globalconf; */
	/* gboolean created_mntpt; */
	if (static_string_valid(v->fs_key_cipher, MAX_PAR + 1) == FALSE)
		return FALSE;
	if (static_string_valid(v->fs_key_path, PATH_MAX + 1) == FALSE)
		return FALSE;
	/* should be guaranteed by volume_record_sane(): */
	if (!(strlen(v->fs_key_cipher) == 0 || strlen(v->fs_key_path) > 0))
		return FALSE;
	if (static_string_valid(v->server, MAX_PAR + 1) == FALSE)
		return FALSE;
	if (static_string_valid(v->user, MAX_PAR + 1) == FALSE)
		return FALSE;
	if (static_string_valid(v->volume, MAX_PAR + 1) == FALSE)
		return FALSE;
	/* optlist_t * options */
	if (static_string_valid(v->mountpoint, PATH_MAX + 1) == FALSE)
		return FALSE;
	/* gboolean use_fstab */
	return TRUE;
}

/* ============================ config_t_valid () ========================== */
gboolean config_t_valid(const config_t * c)
{
	int i;
	if (c == NULL)
		return FALSE;
	if (c->user == NULL)
		return FALSE;
	/* gboolean debug */
	/* gboolean mkmountpoint */
	/* unsigned int volcount */
	if (static_string_valid(c->luserconf, PATH_MAX + 1) == FALSE)
		return FALSE;
	if (static_string_valid(c->fsckloop, PATH_MAX + 1) == FALSE)
		return FALSE;
	/* FIXME: test char *command[MAX_PAR + 1][COMMAND_MAX]; */
	/* optlist_t *options_require; */
	/* optlist_t *options_allow; */
	/* optlist_t *options_deny; */
	for (i = 0; i < c->volcount; i++) {
		if (vol_t_valid(c->volume) == FALSE)
			return FALSE;
	}
	return TRUE;
}

/* ============================ log_argv () ================================ */
void log_argv(char *const argv[])
/* PRE:  argv[0...n] point to valid strings != NULL
 *       argv[n + 1] is NULL
 * POST: argv[0...n] is logged in a nice manner
 */
{
	/* FIXME: UGLY! */
	int i;
	char str[MAX_PAR + 1];
	if (debug == FALSE)
		return;
	strncpy(str, argv[0], MAX_PAR - 1);	/* -1 for ' ' */
	strcat(str, " ");
	str[MAX_PAR] = (char) 0x00;
	for (i = 1; argv[i] != NULL && strlen(str) < MAX_PAR - 1; i++) {
		strncat(str, argv[i], MAX_PAR - strlen(str) - 1);
		strcat(str, " ");
		str[MAX_PAR] = (char) 0x00;
		if (strlen(str) >= MAX_PAR)	/* Should never be greater */
			break;
	}
	w4rn("pam_mount: command: %s\n", str);
}

/* ============================ add_to_argv () ============================= */
/* POST: arg has been added to end of argv, which is NULL * terminated
 *       argc++
 * NOTE: this function exits on an error as an error means a buffer
 *       overflow would otherwise have occured
 */
void add_to_argv(char *argv[], int *const argc, char *const arg,
		 fmt_ptrn_t * vinfo)
{
	char *filled, *ptr;

	assert(argv != NULL);
	/* need room for one more + terminating NULL for execv */
	assert(argc != NULL && 0 <= *argc && *argc <= MAX_PAR - 1);
	assert(arg != NULL);
	assert(vinfo != NULL);

	if (*argc == MAX_PAR) { /* FIXME: this is protected by assert above */
		l0g("pam_mount: %s\n",
		    "too many arguments to mount command");
		return;
	}
	if ((filled = fmt_ptrn_filled(vinfo, arg)) == NULL) {
		l0g("pam_mount: could not fill %s\n", arg);
		while (fmt_ptrn_parse_err(vinfo) != 0)
			l0g("pam_mount: %s\n",
			    fmt_ptrn_parse_strerror(vinfo));
		/* hopefully "key has no value" -- for example:
		 *  %(before=\"-k \" KEYBITS) */
		return;
	}
	while (fmt_ptrn_parse_err(vinfo) != 0)
		l0g("pam_mount: %s\n", fmt_ptrn_parse_strerror(vinfo));
	/* FIXME: this is NOT robust enough (handles only single spaces) */
	/* FIXME: this is silly, how can I avoid parsing this again after
	 * dotfile did?
	 */
	while (filled && (ptr = strchr(filled, ' '))) {
		*ptr = (char) 0x00;
		argv[(*argc)++] = filled;
		filled = ptr + 1;
	}
	argv[(*argc)++] = filled;
	argv[*argc] = NULL;
}

/* ============================ setrootid () =============================== */ 
/* SIDE AFFECTS: sets uid to 0 */
void setrootid(void *ignored)
{
	if (setuid(0) == -1)
		w4rn("pam_mount: %s\n", "error setting uid to 0");
#ifdef HAVE_SETFSUID
	/* Red Hat's su changes fsuid to the processes' uid instead of euid */
	setfsuid(0);
#endif				/* HAVE_SETFSUID */
}
