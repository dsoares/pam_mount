#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <syslog.h>
#include "pam_mount.h"

extern int debug;

void log(const char *mask, const char *arg)
{
	char *maskprov = malloc( strlen(mask)+3 );
	strcpy(maskprov, mask);
	strcat(maskprov, "\n");
	fprintf(stderr, maskprov, arg);
	syslog(LOG_DEBUG, maskprov, arg);
	free(maskprov);
}

void w4rn(const char *mask, const char *arg)
{
	if (debug) {
		log(mask, arg);
	}
}

/* WARNING: exists() return a 3-state result */

int exists(const char *file)
{
	struct stat filestat;

	if (stat(file, &filestat)) {
		log("pam_mount: file %s could not be stat'ed", file);
		return 0;	
	}
	if (S_ISLNK(filestat.st_mode)) {
		log("pam_mount: file %s is a symlink, strange...", file);
		return -1;
	}
	return 1;
}

int owns(const char *user, const char *file)
{
	struct stat filestat;
	struct passwd *userinfo;

	userinfo = getpwnam(user);
	if (! userinfo) {
		log("pam_mount: user %s could not be translated to UID", user);
		return 0;
	}

	if (stat(file, &filestat)) {
		w4rn("pam_mount: file %s could not be stat'ed", file);
		return 0;	
	}

	if ((filestat.st_uid == userinfo->pw_uid)) {
		if (! S_ISLNK(filestat.st_mode)) {
			return 1;
		}
	} 
	return 0;
}

void debugsleep(int sec)
{
	if (debug) sleep(sec);
}
