/*
 *	Copyright (C) Elvis Pfützenreuter, 2000
 *	Copyright © Jan Engelhardt, 2005 - 2008
 *	Copyright © Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libHX/arbtree.h>
#include <libHX/clist.h>
#include <libHX/defs.h>
#include <libHX/deque.h>
#include <libHX/list.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <pwd.h>
#include "misc.h"
#include "pam_mount.h"
#include "readconfig.h"
#include "pam_mount.h"
#include "misc.h"

//-----------------------------------------------------------------------------
/**
 * misc_dump_id - print user IDs
 */
void misc_dump_id(const char *where)
{
	w4rn("%s: (uid=%u, euid=%u, gid=%u, egid=%u)\n", where,
	     static_cast(unsigned int, getuid()),
	     static_cast(unsigned int, geteuid()),
	     static_cast(unsigned int, getgid()),
	     static_cast(unsigned int, getegid()));
}

/**
 * misc_log - log to syslog
 * @format:	printf(3)-style format specifier
 *
 * Message is logged to syslog, and, if debugging is turned on, printed to
 * %stderr. Use this for critical messages or issues that cause(d) pam_mount
 * to fail.
 *
 * Do not call this function directly; use the l0g() macro instead, so that
 * file name and line number show up.
 */
int misc_log(const char *format, ...)
{
	va_list args, arg2;
	int ret = 0;

	assert(format != NULL);

	va_start(args, format);
	va_copy(arg2, args);
	if (Debug)
		ret = vfprintf(stderr, format, args);
	vsyslog(LOG_AUTH | LOG_ERR, format, arg2);
	va_end(args);
	va_end(arg2);
	return ret;
}

/**
 * misc_warn - debug logger
 * @format:	printf(3)-style format specifier
 *
 * If debugging is turned on, the message is logged to syslog and %stderr.
 * Use this for debugging messages.
 *
 * Do not call this function directly; use the w4rn() macro instead, so that
 * file name and line number show up.
 */
int misc_warn(const char *format, ...)
{
	va_list args, arg2;
	int ret;

	assert(format != NULL);
	if (Debug == 0)
		return 0;

	va_start(args, format);
	va_copy(arg2, args);
	ret = vfprintf(stderr, format, args);
	vsyslog(LOG_AUTH | LOG_ERR, format, arg2);
	va_end(args);
	va_end(arg2);
	return ret;
}

/**
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


/**
 * owns -
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

/**
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

/**
 * arglist_log - dump command
 * @argq:	argument list
 *
 * Log @argq using misc_warn() when debugging is turned on.
 */
void arglist_log(const struct HXdeque *argq)
{
	const struct HXdeque_node *n;
	hxmc_t *str = NULL;

	if (!Debug)
		return;

	str = HXmc_meminit(NULL, 80);
	for (n = argq->first; n != NULL; n = n->next) {
		HXmc_strcat(&str, "[");
		HXmc_strcat(&str, n->ptr);
		HXmc_strcat(&str, "] ");
	}

	misc_warn("command: %s\n", str);
	HXmc_free(str);
}

/**
 * arglist_add -
 * @argq:	argument list to add to
 * @arg:	raw argument
 * @vinfo:	substitution map
 *
 * Expands @arg according to @vinfo and adds it to the @argq list.
 */
void arglist_add(struct HXdeque *argq, const char *arg,
    const struct HXbtree *vinfo)
{
	char *filled;

	if (HXformat_aprintf(vinfo, &filled, arg) == 0)
		/*
		 * This case may happen with e.g. %(before="-o" OPTIONS) where
		 * OPTIONS is empty. And options expanding to nothing are
		 * certainly valid.
		 */
		return;

	if (filled == NULL || HXdeque_push(argq, filled) == NULL)
		misc_log("malloc: %s\n", strerror(errno));
}

/**
 * arglist_build - build argument list
 * @cmd:	raw unsubstituted command
 * @vinfo:	substitution map
 *
 * Substitutes %() placeholders in the commands (@cmd) with values from @vinfo
 * and returns the result, suitable for spawn_qstart().
 */
struct HXdeque *arglist_build(const struct HXdeque *cmd,
    const struct HXbtree *vinfo)
{
	const struct HXdeque_node *n;
	struct HXdeque *aq;

	if ((aq = HXdeque_init()) == NULL)
		misc_log("malloc: %s\n", strerror(errno));

	for (n = cmd->first; n != NULL; n = n->next)
		arglist_add(aq, n->ptr, vinfo);

	arglist_log(aq);
	return aq;
}

/**
 * set_myuid -
 * @user:	switch to specified user
 *
 * set_myuid() is called in the child process as a result of the 
 * spawn_start() fork, before exec() will take place.
 *
 * If @users is %NULL, the UID is changed to root. (In most cases, we are
 * already root, though.)
 *
 * If @user is not %NULL, the UID of the current process is changed to that of
 * @user. Also, as a bonus for FUSE daemons, we set the HOME and USER
 * environment variables. setsid() is called so that FUSE daemons (e.g. sshfs)
 * get a new session identifier and do not get killed by the login program
 * after PAM authentication is successful.
 *
 * chdir("/") is called so that fusermount does not get stuck in a
 * non-readable directory (by means of doing `su - unprivilegeduser`)
 */
void set_myuid(const char *user)
{
	setsid();
	if (chdir("/") < 0)
		;
	if (user == NULL) {
		misc_dump_id("set_myuid<pre>");
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
	misc_dump_id("set_myuid<post>");
}

/**
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

/**
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
		snprintf(domain, sizeof(domain), "%.*s",
		         static_cast(int, ptr - user - 1), user);
		domain_user = ptr + 1;
	} else {
		domain_user = user;
	}

	HXformat_add(v, "DOMAIN_NAME", domain, HXTYPE_STRING | HXFORMAT_IMMED);
	HXformat_add(v, "DOMAIN_USER", domain_user, HXTYPE_STRING);
}

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

/**
 * kvplist_to_str -
 * @optlist:	option list
 *
 * Transform the option list into a flat string. Allocates and returns the
 * string. Caller has to free it. Used for debugging.
 */
hxmc_t *kvplist_to_str(const struct HXclist_head *optlist)
{
	const struct kvp *kvp;
	hxmc_t *ret = HXmc_meminit(NULL, 0);

	if (optlist == NULL)
		return ret;

	HXlist_for_each_entry(kvp, optlist, list) {
		HXmc_strcat(&ret, kvp->key);
		if (kvp->value != NULL && *kvp->value != '\0') {
			HXmc_strcat(&ret, "=");
			HXmc_strcat(&ret, kvp->value);
		}
		HXmc_strcat(&ret, ",");
	}

	if (*ret != '\0')
		/*
		 * When string is not empty, there is always at least one
		 * comma -- nuke it.
		 */
		ret[HXmc_length(ret)-1] = '\0';

	return ret;
}

/**
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

/**
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

/**
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
