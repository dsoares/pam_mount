#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <pam_mount.h>

extern int debug;

void _log(int priority, const char *mask, const char *arg)
{
    fprintf(stderr, mask, arg);
    syslog(priority, mask, arg);
}

void log(const char *mask, const char *arg)
{
    /* Used to log issues that cause pam_mount to fail. */
    _log(LOG_AUTHPRIV | LOG_ERR, mask, arg);
}

void w4rn(const char *mask, const char *arg)
{
    /* Used to log informational messages and issues that should not cause
     * pam_mount to fail. */
    if (debug) {
	_log(LOG_USER | LOG_ERR, mask, arg);
    }
}

/* WARNING: exists() returns a 3-state result */
int exists(const char *file)
{
    struct stat filestat;

    if (stat(file, &filestat)) {
	log("pam_mount: file %s could not be stat'ed\n", file);
	return 0;
    }
    if (S_ISLNK(filestat.st_mode)) {
	log("pam_mount: file %s is a symlink, strange...\n", file);
	return -1;
    }
    return 1;
}

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
