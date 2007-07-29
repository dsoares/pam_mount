/*=============================================================================
pam_mount - misc.c
  Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2007
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
#include <sys/stat.h>
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libHX.h>
#include <pwd.h>
#include "misc.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"
#include "xstdlib.h"

/* Functions */
static int static_string_valid(const char *, const size_t);

//-----------------------------------------------------------------------------
/*
 * misc_log - log to syslog
 * @format:	printf(3)-style format specifier
 *
 * Message is logged to syslog, and, if debugging is turned on, printed to
 * %stderr. Use this for critical messages or issues that cause(d) pam_mount
 * to fail.
 */
void misc_log(const char *format, ...)
{
	va_list args, arg2;

	assert(format != NULL);

	va_start(args, format);
	va_copy(arg2, args);
	if (Debug)
		vfprintf(stderr, format, args);
	vsyslog(LOG_AUTHPRIV | LOG_ERR, format, arg2);
	va_end(args);
	va_end(arg2);
	return;
}

/*
 * misc_warn - debug logger
 * @format:	printf(3)-style format specifier
 *
 * If debugging is turned on, the message is logged to syslog and %stderr.
 * Use this for debugging messages.
 */
void misc_warn(const char *format, ...)
{
	va_list args, arg2;

	assert(format != NULL);
	if (Debug == 0)
		return;

	va_start(args, format);
	va_copy(arg2, args);
	vfprintf(stderr, format, args);
	vsyslog(LOG_AUTHPRIV | LOG_ERR, format, arg2);
	va_end(args);
	va_end(arg2);
	return;
}

/*
 * exists -
 * @file:	file to check
 *
 * Check if a file exists (if it can be stat()'ed) and return positive
 * non-zero if that was successful. Returns 0 for error. %errno will be set
 * in case of error.
 */
int exists(const char *file)
{
	struct stat sb;
	assert(file != NULL);
	return stat(file, &sb) == 0;
}


/* owns -
 * @user:	user to check for
 * @file:	file to check
 *
 * Checks whether @user owns @file. Returns positive non-zero if this is the
 * case, otherwise zero. If an error occurred, zero is returned and %errno
 * is set. (For the success case, %errno is undefined.)
 */
int owns(const char *user, const char *file)
{
	struct stat filestat;
	struct passwd *userinfo;

	assert(user != NULL);
	assert(file != NULL);

	if ((userinfo = getpwnam(user)) == NULL) {
		l0g("user %s could not be translated to UID\n",
		    user);
		return 0;
	}

	if (stat(file, &filestat) != 0) {
		w4rn("file %s could not be stat'ed\n", file);
		return 0;
	}

	return filestat.st_uid == userinfo->pw_uid &&
	       !S_ISLNK(filestat.st_mode);
}

/*
 * str_to_long -
 * @n:	string to analyze
 *
 * Calls @strtol on @n using base 10 and makes sure there were no invalid
 * characters in @n. Returns the value, or %LONG_MAX in case of an
 * over-/underflow.
 * NOTE: This function is only referenced from pmvarrun.c.
 */
long str_to_long(const char *n)
{
	long val;
	char *endptr = NULL;
	if (n == NULL) {
		l0g("count string is NULL\n");
		return LONG_MAX;
	}
	val = strtol(n, &endptr, 10);
	if (*endptr != '\0') {
		l0g("count string is not valid\n");
		return LONG_MAX;
	}
	return val;
}

/*
 * static_string_valid -
 * @s:		string to analyze
 * @len:	maximum length of string
 *
 * Verifies that there is a '\0' byte within the first @len bytes of @s.
 */
static int static_string_valid(const char *s, const size_t len)
{
	size_t i;
	if (s == NULL)
		return 0;
	/* make sure there is a terminating NUL */
	for (i = 0; i < len; i++)
		if (s[i] == '\0')
			return 1;
	return 0;
}

/*
 * vol_valid -
 * @v:	volume to check
 *
 * Verifies that the volume structure is consistent.
 */
int vol_valid(const struct vol *v) {
	if (v == NULL)
		return 0;
	if (!(v->type >= 0 && v->type < _CMD_MAX))
		return 0;
	/* should be guaranteed by volume_record_sane() */
	/* FIXME: hope to have this in util-linux (LCLMOUNT) some day: */
	if (!(v->type == CMD_LCLMOUNT || v->type == CMD_CRYPTMOUNT ||
	    v->type == CMD_FUSEMOUNT || v->type == CMD_TRUECRYPTMOUNT ||
	    strlen(v->server) > 0))
		return 0;
	/* bool globalconf; */
	/* bool created_mntpt; */
	if (!static_string_valid(v->fs_key_cipher, MAX_PAR + 1) ||
	    !static_string_valid(v->fs_key_path, PATH_MAX + 1))
		return 0;
	/* should be guaranteed by volume_record_sane(): */
	if (!(strlen(v->fs_key_cipher) == 0 || strlen(v->fs_key_path) > 0))
		return 0;
	if (!static_string_valid(v->server, MAX_PAR + 1) ||
	    !static_string_valid(v->user, MAX_PAR + 1) ||
	    !static_string_valid(v->volume, MAX_PAR + 1))
		return 0;
	/* optlist_t * options */
	if (!static_string_valid(v->mountpoint, PATH_MAX + 1))
		return 0;
	/* bool use_fstab */
	return 1;
}

/*
 * config_valid -
 * @c:	config to check
 *
 * Verifies that the configuration structure is consistent.
 */
int config_valid(const struct config *c)
{
	int i;
	if (c == NULL || c->user == NULL)
		return 0;
	/* bool debug */
	/* bool mkmountpoint */
	/* unsigned int volcount */
	if (!static_string_valid(c->luserconf, PATH_MAX + 1) ||
	    !static_string_valid(c->fsckloop, PATH_MAX + 1))
		return 0;
	/* FIXME: test char *command[MAX_PAR + 1][COMMAND_MAX]; */
	/* optlist_t *options_require; */
	/* optlist_t *options_allow; */
	/* optlist_t *options_deny; */
	for (i = 0; i < c->volcount; ++i)
		if (!vol_valid(c->volume))
			return 0;
	return 1;
}

/*
 * log_argv -
 * @argv:	argument vector
 * Log @argv using w4rn() when debugging is turned on.
 */
void log_argv(const char *const *argv)
{
	/* FIXME: UGLY! */
	int i;
	char str[MAX_PAR + 1];
	if (!Debug)
		return;
	g_strlcpy(str, argv[0], sizeof(str));
	g_strlcat(str, " ", sizeof(str));
	str[sizeof_z(str)] = '\0';
	for (i = 1; argv[i] != NULL && strlen(str) < sizeof(str) - 2; i++) {
		g_strlcat(str, "[", sizeof(str));
		g_strlcat(str, argv[i], sizeof(str));
		g_strlcat(str, "] ", sizeof(str));
		str[sizeof_z(str)] = '\0';
		if (strlen(str) >= sizeof_z(str))
			/* Should never be greater */
			break;
	}
	w4rn("command: %s\n", str);
	return;
}

/* add_to_argv -
 * @argv:	argument vector to add to
 * @argc:	pointer to current argument count
 * @arg:	argument to add
 * @vinfo:
 *
 * Expands @arg according to @vinfo and adds it to the @argv vector which is
 * (and will be) %NULL-terminated. @argc is increased by one.
 *
 * There is a compile-time limit imposed: there can not be more than MAX_PAR-1
 * elements in the @argv vector.
 */
void add_to_argv(const char **argv, int *const argc, const char *const arg,
    struct HXbtree *vinfo)
{
	char *filled;

	assert(argv != NULL);
	/* need room for one more + terminating NULL for execv */
	assert(argc != NULL && *argc >= 0 && *argc <= MAX_PAR - 1);
	assert(arg != NULL);
	assert(vinfo != NULL);

	if (*argc == MAX_PAR) {
		/* FIXME: this is protected by assert above */
		l0g("too many arguments to mount command\n");
		return;
	}
	if (HXformat_aprintf(vinfo, &filled, arg) == 0) {
		/*
		 * This case may happen with e.g. %(before="-o" OPTIONS) where
		 * OPTIONS is empty. And empty options is certainly valid.
		 */
		w4rn("could not fill %s\n", arg);
		return;
	}

	argv[*argc]   = filled;
	argv[++*argc] = NULL;
	return;
}

/*
 * set_myuid -
 * @data:	username
 *
 * set_myuid() is called in the child process as a result of the spawn_ap0()
 * fork, before exec() will take place.
 *
 * If @user is %NULL, the UID is changed to root. (In most cases, we are
 * already root, though.)
 *
 * If @user is not %NULL, the UID of the current process is changed to
 * that of @user. Also, for FUSE daemons, we set the HOME and USER
 * environment variables. setsid() is called so that FUSE daemons (e.g.
 * sshfs) get a new session identifier and do not get killed by the
 * login program after PAM authentication is successful.
 *
 * chdir("/") is called so that fusermount does not get stuck in a
 * non-readable directory (by means of doing `su - unprivilegeduser`)
 */
void set_myuid(void *data)
{
	const char *user = data;

	setsid();
	chdir("/");
	if (user == NULL) {
		w4rn("%s(pre): (uid=%ld, euid=%ld, gid=%ld, egid=%ld)\n", __func__,
		     static_cast(long, getuid()), static_cast(long, geteuid()),
		     static_cast(long, getgid()), static_cast(long, getegid()));
		if (setuid(0) < 0) {
			l0g("error setting uid to 0\n");
			return;
		}
	} else {
		/* Set UID and GID to the user's one */
		const struct passwd *real_user;
		w4rn("setting uid to user %s\n", user);
		if ((real_user = getpwnam(user)) == NULL) {
			l0g("could not get passwd entry for user %s\n", user);
			return;
		}
		if (setgid(real_user->pw_gid) == -1) {
			l0g("could not set gid to %ld\n",
			    static_cast(long, real_user->pw_gid));
			return;
		}
		if (setuid(real_user->pw_uid) == -1) {
			l0g("could not set uid to %ld\n",
			    static_cast(long, real_user->pw_uid));
			return;
		}
		setenv("HOME", real_user->pw_dir, 1);
		setenv("USER", real_user->pw_name, 1);
	}
	w4rn("%s(pre): (uid=%ld, euid=%ld, gid=%ld, egid=%ld)\n", __func__,
	     static_cast(long, getuid()), static_cast(long, geteuid()),
	     static_cast(long, getgid()), static_cast(long, getegid()));
	return;
}

/*
 * relookup_user -
 * @user:	The user to retrieve
 *
 * Relookup the user. This is done to account for case-insensitivity of
 * usernames with LDAP. Returns a copy of the real username (as stored in
 * the user database).
 */
char *relookup_user(const char *user)
{
	struct passwd *pe;
	if ((pe = getpwnam(user)) == NULL)
		return xstrdup(user);
	else
		return xstrdup(pe->pw_name);
}

/*
 * misc_add_ntdom -
 * @v:		substitution data
 * @user:	username to add
 *
 * Splits up @user into domain and user parts (if applicable) and adds
 * %(DOMAIN_NAME) and %(DOMAIN_USER) to @v. If @user is not of the form
 * "domain\user", %(DOMAIN_NAME) will be added as an empty tag, and
 * %(DOMAIN_USER) will be the same as @v. It is assumed that @user is also
 * part of @v, and hence, will not go out of scope as long as %(DOMAIN_*) is
 * in @v.
 */
void misc_add_ntdom(struct HXbtree *v, const char *user)
{
	const char *domain_user, *ptr;
	char domain[32];
	*domain = '\0';

	if ((ptr = strchr(user, '\\')) != NULL) {
		snprintf(domain, sizeof(domain), "%.*s", ptr - user - 1, user);
		domain_user = ptr + 1;
	} else {
		domain_user = user;
	}

	HXformat_add(v, "DOMAIN_NAME", domain, HXTYPE_STRING | HXFORMAT_IMMED);
	HXformat_add(v, "DOMAIN_USER", domain_user, HXTYPE_STRING);
	return;
}
