#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "pam_mount.h"

extern int debug;

void w4rn(const char *mask, const char *arg)
{
	if (debug) {
		char *maskprov = malloc( strlen(mask)+3 );
		strcpy(maskprov, mask);
		strcat(maskprov, "\n");
	       	fprintf(stderr, maskprov, arg);
		free(maskprov);
		// usleep(333333);
	}
}

/* WARNING: exists() return a 3-state result */

int exists(const char *file)
{
	struct stat filestat;

	if (stat(file, &filestat)) {
		w4rn("File %s could not be stat'ed", file);
		return 0;	
	}
	if (S_ISLNK(filestat.st_mode)) {
		w4rn("File %s is a symlink, strange...", file);
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
		w4rn("User %s could not be translated to UID", user);
		return 0;
	}

	if (stat(file, &filestat)) {
		w4rn("File %s could not be stat'ed", file);
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
