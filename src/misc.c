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
#include <security/pam_modules.h>

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
	vsyslog(LOG_USER | LOG_ERR, format, args);
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
		vsyslog(LOG_USER | LOG_ERR, format, args);
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
 * OUTPUT: 0 if user does not own file or 1 if user owns file */
int owns(const char *user, const char *file)
{
	struct stat filestat;
	struct passwd *userinfo;

	assert(user != NULL);
	assert(file != NULL);

	userinfo = getpwnam(user);
	if (!userinfo) {
		l0g("pam_mount: user %s could not be translated to UID\n",
		    user);
		return 0;
	}

	if (stat(file, &filestat) != 0) {
		w4rn("pam_mount: file %s could not be stat'ed\n", file);
		return 0;
	}

	if ((filestat.st_uid == userinfo->pw_uid)
	    && !S_ISLNK(filestat.st_mode))
		return 1;
	return 0;
}

/* ============================ converse () ================================ */
/* INPUT: pamh; nargs; message, a prompt message
 * SIDE AFFECTS: resp points to PAM's (user's) response to message
 * OUTPUT: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c */
static int
converse(pam_handle_t * pamh, int nargs,
	 const struct pam_message **message,
	 struct pam_response **resp)
{
	int retval;
	struct pam_conv *conv;
	
	assert(pamh != NULL);
	assert(nargs >= 0);
	assert(resp != NULL);

	*resp = NULL;
	retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (retval == PAM_SUCCESS)
		retval =
		    conv->conv(nargs, message, resp,
			       conv->appdata_ptr);
	if (! *resp)
		retval = PAM_AUTH_ERR;

	assert(retval != PAM_SUCCESS || (resp != NULL && *resp != NULL && (*resp)->resp != NULL));

	return retval;		/* propagate error status */
}

/* ============================ read_password () =========================== */
/* INPUT: pamh; prompt1, a prompt message
 * SIDE AFFECTS: pass points to PAM's (user's) response to prompt1 (malloc'ed)
 * OUTPUT: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c (_unix_read_password)
 */
int read_password(pam_handle_t * pamh, char *prompt1, char **pass)
{
	int retval;
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;

	assert(pamh != NULL);
	assert(prompt1 != NULL);
	assert(pass != NULL);

	w4rn("pam_mount: %s\n", "enter read_password");
	*pass = NULL;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt1;
	retval = converse(pamh, 1, &pmsg, &resp);
	if (retval == PAM_SUCCESS)
		*pass = strdup(resp->resp);

	assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));

	return retval;
}
