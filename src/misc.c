/*=============================================================================
misc.c
  Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2006
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
#include <config.h>
#ifdef HAVE_SETFSUID
#    include <sys/fsuid.h>
#endif
#include <sys/stat.h>
#include <assert.h>
#include <glib.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include "misc.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"

/* ============================ l0g () ===================================== */
/* INPUT: similar to printf; all args are valid strings != NULL
 * SIDE EFFECTS: format + args are logged and displayed */
void l0g(const char *format, ...)
{
	/* Used to log issues that cause pam_mount to fail. */
	va_list args;

	assert(format != NULL);

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	va_start(args, format);
	vsyslog(LOG_AUTHPRIV | LOG_ERR, format, args);
	va_end(args);
}

/* ============================ w4rn () ==================================== */
/* INPUT: similar to printf; all args are valid string != NULL
 * SIDE EFFECTS: format + args are logged and displayed iff debug == 1
 * NOTE: Used to log informational messages and issues that should not cause
 *       pam_mount to fail. */
void w4rn(const char *format, ...) {
    va_list args;

    assert(format != NULL);

    if(Debug == 0) return;

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    va_start(args, format);
    vsyslog(LOG_AUTHPRIV | LOG_ERR, format, args);
    va_end(args);
    return;
}

/* ============================ exists () ================================== */
/* INPUT: file, a file path
 * OUTPUT: 0 if file does not exist or 1 if file exists */
int exists(const char *file) {
    struct stat sb;
    assert(file != NULL);
    return stat(file, &sb) == 0;
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
	if(userinfo == NULL) {
		l0g(PMPREFIX "user %s could not be translated to UID\n",
		    user);
		return FALSE;
	}

	if (stat(file, &filestat) != 0) {
		w4rn(PMPREFIX "file %s could not be stat'ed\n", file);
		return FALSE;
	}

    return (filestat.st_uid == userinfo->pw_uid && !S_ISLNK(filestat.st_mode))
           ? TRUE : FALSE;
}

/* ============================ str_to_long () ============================= */
long str_to_long(const char *n) {
/* INPUT: n, a string
 * SIDE EFFECT: errors are logged
 * OUTPUT: if error LONG_MAX or LONG_MIN else long value of n
 * NOTE:   this is needed because users own /var/run/pam_mount/<user> 
 *         and they could try something sneaky
 *         FIXME: the above NOTE may no longer be true
 */
	long val;
	char *endptr = NULL;
	if(n == NULL) {
		l0g(PMPREFIX "count string is NULL\n");
		return LONG_MAX;
	}
	val = strtol(n, &endptr, 10);
	if(*endptr != '\0') {
		l0g(PMPREFIX "count string is not valid\n");
		return LONG_MAX;
	}
	return val;
}

/* ============================ static_string_valid () ===================== */
gboolean static_string_valid(const char *s, const size_t len)
{
	size_t i;
	if (s == NULL)
		return FALSE;
	/* make sure there is a terminating NULL */
	for (i = 0; i < len; i++)
		if(s[i] == '\0')
			return TRUE;
	return FALSE;
}

/* ============================ vol_t_valid () ============================= */
gboolean vol_t_valid(const vol_t * v)
{
	if (v == NULL)
		return FALSE;
	if (!(v->type >= 0 && v->type < COMMAND_MAX))
		return FALSE;
	/* should be guaranteed by volume_record_sane() */
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	if (!((v->type == LCLMOUNT || v->type == CRYPTMOUNT)
	      || strlen(v->server) > 0))
		return FALSE;
	/* gboolean globalconf; */
	/* gboolean created_mntpt; */
	if(!static_string_valid(v->fs_key_cipher, MAX_PAR + 1) ||
	 !static_string_valid(v->fs_key_path, PATH_MAX + 1))
		return FALSE;
	/* should be guaranteed by volume_record_sane(): */
	if (!(strlen(v->fs_key_cipher) == 0 || strlen(v->fs_key_path) > 0))
		return FALSE;
        if(!static_string_valid(v->server, MAX_PAR + 1) ||
         !static_string_valid(v->user, MAX_PAR + 1) ||
         !static_string_valid(v->volume, MAX_PAR + 1))
		return FALSE;
	/* optlist_t * options */
        if(!static_string_valid(v->mountpoint, PATH_MAX + 1))
		return FALSE;
	/* gboolean use_fstab */
	return TRUE;
}

/* ============================ config_t_valid () ========================== */
gboolean config_t_valid(const config_t * c)
{
	int i;
        if(c == NULL || c->user == NULL)
		return FALSE;
	/* gboolean debug */
	/* gboolean mkmountpoint */
	/* unsigned int volcount */
        if(!static_string_valid(c->luserconf, PATH_MAX + 1) ||
         !static_string_valid(c->fsckloop, PATH_MAX + 1))
		return FALSE;
	/* FIXME: test char *command[MAX_PAR + 1][COMMAND_MAX]; */
	/* optlist_t *options_require; */
	/* optlist_t *options_allow; */
	/* optlist_t *options_deny; */
	for (i = 0; i < c->volcount; i++) {
                if(!vol_t_valid(c->volume))
			return FALSE;
	}
	return TRUE;
}

/* ============================ log_argv () ================================ */
void log_argv(const char *const *argv) {
/* PRE:  argv[0...n] point to valid strings != NULL
 *       argv[n + 1] is NULL
 * POST: argv[0...n] is logged in a nice manner
 */
	/* FIXME: UGLY! */
	int i;
	char str[MAX_PAR + 1];
        if(!Debug)
		return;
	g_strlcpy(str, argv[0], sizeof(str));
	g_strlcat(str, " ", sizeof(str));
	str[sizeof(str)-1] = '\0';
	for (i = 1; argv[i] != NULL && strlen(str) < sizeof(str) - 2; i++) {
		g_strlcat(str, "[", sizeof(str));
		g_strlcat(str, argv[i], sizeof(str));
		g_strlcat(str, "] ", sizeof(str));
		str[sizeof(str)-1] = '\0';
		if(strlen(str) >= sizeof(str) - 1) /* Should never be greater */
			break;
	}
	w4rn(PMPREFIX "command: %s\n", str);
}

/* ============================ add_to_argv () ============================= */
/* POST: arg has been added to end of argv, which is NULL * terminated
 *       argc++
 * NOTE: this function exits on an error as an error means a buffer
 *       overflow would otherwise have occured
 */
void add_to_argv(const char **argv, int *const argc, const char *const arg,
 fmt_ptrn_t *vinfo)
{
	char *filled;

	assert(argv != NULL);
	/* need room for one more + terminating NULL for execv */
	assert(argc != NULL && *argc >= 0 && *argc <= MAX_PAR - 1);
	assert(arg != NULL);
	assert(vinfo != NULL);

	if (*argc == MAX_PAR) { /* FIXME: this is protected by assert above */
		l0g(PMPREFIX "too many arguments to mount command\n");
		return;
	}
	if ((filled = fmt_ptrn_filled(vinfo, arg)) == NULL) {
		l0g(PMPREFIX "could not fill %s\n", arg);
		while (fmt_ptrn_parse_err(vinfo) != 0)
			l0g(PMPREFIX "%s\n",
			    fmt_ptrn_parse_strerror(vinfo));
		/* [??] hopefully "key has no value" -- for example:
		 *  %(before=\"-k\" KEYBITS) */
		return;
	}
	while (fmt_ptrn_parse_err(vinfo) != 0)
		l0g(PMPREFIX "%s\n", fmt_ptrn_parse_strerror(vinfo));

	argv[*argc] = filled;
	argv[++*argc] = NULL;
}

void set_myuid(void *data) {
    /* INPUT: user, the username or NULL to setuid(0)
     * SIDE EFFECTS: sets process uid (and gid if user!=NULL)
     * OUTPUT: -1 on error, 0 else
     */
    const char *user = data;

    if(user == NULL) {
        w4rn(PMPREFIX "setting uid to 0\n");
        if(setuid(0) == -1) {
            l0g(PMPREFIX "error setting uid to 0\n");
            return;
        }
#ifdef HAVE_SETFSUID
        if(setfsuid(0) == -1) {
            l0g(PMPREFIX "error setting fsuid to 0\n");
            return;
        }
#endif
    } else {
        // Set UID and GID to the user's one.
        struct passwd *real_user;
        w4rn(PMPREFIX "setting uid to user %s\n", user);
        if((real_user = getpwnam(user)) == NULL) {
            l0g(PMPREFIX "could not get passwd entry for user %s\n", user);
            return;
        }
        if(setgid(real_user->pw_gid) == -1) {
            l0g(PMPREFIX "could not set gid to %u\n", real_user->pw_gid);
            return;
        }
        if(setuid(real_user->pw_uid) == -1) {
            l0g(PMPREFIX "could not set uid to %u\n", real_user->pw_uid);
            return;
        }
    }
    w4rn(PMPREFIX "real user/group IDs are %d/%d, effective is %d/%d\n",
      getuid(), getgid(), geteuid(), getegid());
    return;
}

/*  relookup_user
    @user:      The user to retrieve

    Relookup the user. This is done to account for case-insensitivity of
    usernames with LDAP. Returns a copy of the real username (as stored in
    the user database).
*/
char *relookup_user(const char *user) {
    struct passwd *pe;
    if((pe = getpwnam(user)) == NULL)
        return strdup(user);
    else
        return strdup(pe->pw_name);
}

//=============================================================================
