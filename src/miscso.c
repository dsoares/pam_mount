#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

extern int debug;

/* ============================ _log () ==================================== */ 
void _log(int priority, const char *mask, const char *arg)
{
    fprintf(stderr, mask, arg);
    syslog(priority, mask, arg);
}

/* ============================ log () ===================================== */ 
/* PRE:  mask points to a valid string != NULL
 *       arg points to a valid string != NULL
 * POST: mask + arg is logged and displayed */
void log(const char *mask, const char *arg)
{
    /* Used to log issues that cause pam_mount to fail. */
    _log(LOG_AUTHPRIV | LOG_ERR, mask, arg);
}

/* ============================ w4rn () ==================================== */ 
/* PRE:  mask points to a valid string != NULL
 *       arg points to a valid string != NULL
 * POST: mark + arg is logged and displayed iff debug == 0
 * NOTE: Used to log informational messages and issues that should not cause
 *       pam_mount to fail. */
void w4rn(const char *mask, const char *arg)
{
    if (debug) {
	_log(LOG_USER | LOG_ERR, mask, arg);
    }
}

/* ============================ exists () ================================== */ 
/* PRE:    file points to a valid string != NULL
 * FN VAL: 0 if file does not exist, -1 if file is a symlink, or 1 if file 
 *         is normal and exists */
int exists(const char *file)
{
    struct stat filestat;
    if (stat(file, &filestat)) {
	return 0;
    }
    if (S_ISLNK(filestat.st_mode)) {
	return -1;
    }
    return 1;
}

/* ============================ owns () ==================================== */ 
/* PRE:    user points to a valid string != NULL
 *         file points to a valid string != NULL
 * FN VAL: 0 if user does not own file or 1 if user owns file */
int owns(const char *user, const char *file)
{
    struct stat filestat;
    struct passwd *userinfo;

    userinfo = getpwnam(user);
    if (!userinfo) {
	log("pam_mount: user %s could not be translated to UID\n", user);
	return 0;
    }

    if (stat(file, &filestat)) {
	w4rn("pam_mount: file %s could not be stat'ed\n", file);
	return 0;
    }

    if ((filestat.st_uid == userinfo->pw_uid)) {
	if (!S_ISLNK(filestat.st_mode)) {
	    return 1;
	}
    }
    return 0;
}
