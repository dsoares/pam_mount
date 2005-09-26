/*   FILE: pmvarrun.c -- Updates /var/run/pam_mount/<user>.  A seperate
 *         program is needed so that /var/run/pam_mount/<user> may be 
 *         created with a pam_mount-specific security context (otherwise 
 *         SELinux policy will conflict with gdm, which also creates file
 *         in /var/run).
 * AUTHOR: W. Michael Petullo <mike@flyn.org>
 *   DATE: 10 May 2004
 *
 * Copyright (C) 2004 W. Michael Petullo <mike@flyn.org>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "misc.h"

#define PREFIX "pmvarrun: "

int Debug;
static const char *usage_pmvarrun = "pmvarrun -u user [-o number] [-d]";

typedef struct settings_t {
	char user[MAX_PAR + 1];
	long operation;
} settings_t;

static int modify_pm_count(const char *, long);
static void parse_args(const int, const char **, settings_t *);
static void set_defaults(settings_t *);
static void usage(int, const char *, const char *);

/* ============================ usage () ==================================== */
static void usage(const int exitcode, const char *error, const char *more) {
	fprintf(stderr, "%s\n", usage_pmvarrun);
	if(error != NULL)
		fprintf(stderr, "%s: %s.\n\n", error, more);
	exit(exitcode);
}

/* ============================ set_defaults () ============================= */
static void set_defaults(settings_t *settings) {
	Debug = 0;
	*settings->user = '\0';
	settings->operation = 1;
}

/* ============================ parse_args () =============================== */
static void parse_args(int argc, const char **argv, settings_t *settings) {
	int c;
	int opt_index = 0;
	struct option opts[] = {
		{"help", 0, 0, 'h'},
		{"user", 1, 0, 'u'},
		{"operation", 1, 0, 'o'},
		{0, 0, 0, 0}
	};
        while((c = getopt_long(argc, (char * const *)argv,
         "hdo:u:", opts, &opt_index)) >= 0) {
	    switch (c) {
		case 'h':
			usage(EXIT_SUCCESS, NULL, NULL);
		case 'd':
			Debug = 1;
			break;
		case 'o':
                    if((settings->operation = str_to_long(optarg)) == LONG_MAX
                     || settings->operation == LONG_MIN)
                        usage(EXIT_FAILURE, PREFIX "%s\n",
                          "count string is not valid");
			break;
		case 'u':
			g_strlcpy(settings->user, optarg,
				  sizeof(settings->user));
			break;
		default:
			usage(EXIT_FAILURE, NULL, NULL);
	    }
	}
}

/* ============================ modify_pm_count () ========================= */
/* FIXME: use INPUT, SIDE EFFECTS and OUTPUT */
/* POST:   amount is added to /var/run/pam_mount/<user>'s value
 *         if value == 0, then file is removed. 
 * FN VAL: new value else -1 on error, errors are logged 
 * NOTE:   code is modified version of pam_console.c's use_count 
 * FIXME:  should this be replaced with utmp (man utmp) usage?  
 *         Is utmp portable?  This function is nasty and MAY BE INSECURE.
 */
static int modify_pm_count(const char *user, long amount) {
	char filename[PATH_MAX + 1];
	int tries = 0;
	int fd = 0, err;
	long val;
	struct stat st;
	struct flock lockinfo;
	char *buf = NULL;
        struct passwd *passwd_ent;

	assert(user != NULL);

        if((passwd_ent = getpwnam(user)) == NULL) {
            l0g(PREFIX "could not resolve uid for %s\n", user);
            err = -1;
            goto return_error;
        }

	if (stat("/var/run/pam_mount", &st) == -1) {
                w4rn(PREFIX "creating /var/run/pam_mount");
		if (mkdir("/var/run/pam_mount", 0000) == -1) {
                    l0g(PREFIX "unable to create /var/run/pam_mount: %s\n",
                      strerror(errno));
                    err = -1;
                    goto return_error;
		}
		if (chown("/var/run/pam_mount", 0, 0) == -1) {
                    l0g(PREFIX "unable to chown /var/run/pam_mount: %s\n",
                      strerror(errno));
                    err = -1;
                    goto return_error;
		}
		/*
		 * 0755: su creates file group owned by user and the releases
		 * root perms.  User needs to be able to access file on
		 * logout.
		 */
		/*
		 * FIXME: user can modify /var/.../<user> at will; security
		 * problem?  Note that this file's contents is checked by 
		 * str_to_long.
		 */
		if (chmod("/var/run/pam_mount", 0755) == -1) {
                    l0g(PREFIX "unable to chmod /var/run/pam_mount: %s\n",
                      strerror(errno));
                    err = -1;
                    goto return_error;
		}
	}
	g_snprintf(filename, sizeof(filename), "/var/run/pam_mount/%s", user);
      top:
	tries++;
	if (stat(filename, &st) == -1) {
		if ((fd = open(filename, O_RDWR | O_CREAT, 0000)) == -1) {
                    l0g(PREFIX "unable to open %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
		/*
		 * su creates file group owned by user and then releases root
		 * perms.  User needs to be able to access file on logout.
		 */
            if (fchown (fd, passwd_ent->pw_uid, passwd_ent->pw_gid) == -1)
		/* FIXME: permission denied */
		if (fchown(fd, 0, 0) == -1) {
                    l0g(PREFIX "unable to chown %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
		if (fchmod(fd, 0600) == -1) {
                    l0g(PREFIX "unable to chmod %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
		if (write(fd, "0", 1) == -1) {
                    l0g(PREFIX "write error on %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
		if (lseek(fd, SEEK_SET, 0) == -1) {
                    l0g(PREFIX "seek error on %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
	} else
		fd = open(filename, O_RDWR);

	if (stat(filename, &st) == -1) {
            l0g(PREFIX "unable to stat %s: %s\n", filename, strerror(errno));
            err = -1;
            goto return_error;
	}
	if (fd < 0) {
            l0g(PREFIX "could not open count file %s: %s\n",
              filename, strerror(errno));
            return 0;
	}
	lockinfo.l_type = F_WRLCK;
	lockinfo.l_whence = SEEK_SET;
	lockinfo.l_start = 0;
	lockinfo.l_len = 0;
	alarm(20);
	err = fcntl(fd, F_SETLKW, &lockinfo);
	alarm(0);
	if (err == EAGAIN) {
		/*
		 * if someone has locked the file and not written to it in at
		 * least 20 seconds, we assume they either forgot to unlock
		 * it or are catatonic -- chances are slim that they are in
		 * the middle of a read-write cycle and I don't want to make
		 * us lock users out.  Perhaps I should just return
		 * PAM_SUCCESS instead and log the event?  Kill the process
		 * holding the lock?  Options abound...  For now, we ignore
		 * it.
		 */
		fcntl(fd, F_GETLK, &lockinfo);
		/*
		 * now lockinfo.l_pid == 0 implies that the lock was released
		 * by the other process between returning from the 20 second
		 * wait and calling fcntl again, not likely to ever happen,
		 * and not a problem other than cosmetics even if it does.
		 */
                w4rn(PREFIX "ignoring stale lock on file %s\n", filename);
	}
	/*
	 * it is possible at this point that the file has been removed by a
	 * previous login; if this happens, we need to start over.
	 * Unfortunately, the only way to do this without potential stack
	 * trashing is a goto.
	 */
	if(access(filename, F_OK) == -1) {
		if (tries < 10) {
                    l0g(PREFIX "could not access %s: %s; trying again\n",
                      filename, strerror(errno));
                    /* Waiting too long might interfere with
                    /etc/login.defs:LOGIN_TIMEOUT and /bin/login itself may
                    prematurely kill the session. */
                    sleep(1);
                    CLOSE(fd);
                    goto top;
		} else {
                    l0g(PREFIX "could not access %s in 10s, quitting\n",
                      filename);
                    err = -1;
                    goto return_error;
		}
	}
	buf = g_malloc(st.st_size + 2);	/* size will never grow by
					 * more than one */
	if(st.st_size > 0) {
		if (read(fd, buf, st.st_size) == -1) {
                    w4rn(PREFIX "read error on %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
		if (lseek(fd, 0, SEEK_SET) == -1) {
                    w4rn(PREFIX "lseek error on %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
		buf[st.st_size] = '\0';
		if ((val = str_to_long(buf)) == LONG_MAX
		    || val == LONG_MIN) {
                        l0g(PREFIX "session count corrupt (overflow)\n");
			err = -1;
			goto return_error;
		}
	} else {
		val = 0;
	}
	if(amount != 0) {		/* amount == 0 implies query */
		val += amount;
                if(val <= 0 && unlink(filename) != 0) {
                    l0g(PREFIX "could not unlink %s: %s\n",
                      filename, strerror(errno));
		}
		g_snprintf(buf, st.st_size + 2, "%ld", val);
		if (write(fd, buf, strlen(buf)) == -1) {
                    l0g(PREFIX "write error on %s: %s\n",
                      filename, strerror(errno));
                    err = -1;
                    goto return_error;
		}
	}
	err = val;
      return_error:
	if (fd > 0)
		CLOSE(fd);
	if (buf)
		g_free(buf);
	return err;
}

/* ============================ main () ===================================== */
int main(int argc, const char **argv) {
	int pm_count;
	settings_t settings;

	set_defaults(&settings);
	parse_args(argc, argv, &settings);

	if (strlen(settings.user) == 0)
		usage(EXIT_FAILURE, NULL, NULL);

	if ((pm_count =
	     modify_pm_count(settings.user, settings.operation)) < 0)
		exit(EXIT_FAILURE);

	/* print current count so pam_mount module may read it */
	printf("%d\n", pm_count);

	exit(EXIT_SUCCESS);
}
