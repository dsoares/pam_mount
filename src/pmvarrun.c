/*=============================================================================
pmvarrun.c
  Copyright (C) W. Michael Putello <mike@flyn.org>, 2004
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
/*
pmvarrun.c -- Updates /var/run/pam_mount/<user>.
    A seperate program is needed so that /var/run/pam_mount/<user> may be
    created with a pam_mount-specific security context (otherwise SELinux
    policy will conflict with gdm, which also creates file in /var/run).
*/

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
#include "private.h"

// Definitions
#define ASCIIZ_LLX      sizeof("0xFFFFFFFF""FFFFFFFF")
#define PREFIX          "pmvarrun: "
#define VAR_RUN         "/var/run"
#define VAR_RUN_PMT     VAR_RUN "/pam_mount"

struct settings {
	char user[MAX_PAR + 1];
	long operation;
};

// Functions
static int create_var_run(void);
static int modify_pm_count(const char *, long);
static int open_and_lock(const char *, long);
static void parse_args(const int, const char **, struct settings *);
static long read_current_count(int, const char *);
static void set_defaults(struct settings *);
static void usage(int, const char *, const char *);

// Variables
int Debug;
static const char *usage_pmvarrun = "pmvarrun -u user [-o number] [-d]";

/* ============================ usage () ==================================== */
static void usage(const int exitcode, const char *error, const char *more) {
	fprintf(stderr, "%s\n", usage_pmvarrun);
	if(error != NULL)
		fprintf(stderr, "%s: %s.\n\n", error, more);
	exit(exitcode);
}

/* ============================ set_defaults () ============================= */
static void set_defaults(struct settings *settings) {
	Debug = 0;
	*settings->user = '\0';
	settings->operation = 1;
}

/* ============================ parse_args () =============================== */
static void parse_args(int argc, const char **argv,
 struct settings *settings)
{
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
	int fd = 0, err;
    long val;
    int ret;
	struct stat st;
	char *buf = NULL;
        struct passwd *passwd_ent;

	assert(user != NULL);

        if((passwd_ent = getpwnam(user)) == NULL) {
            ret = errno;
            l0g(PREFIX "could not resolve uid for %s\n", user);
            return ret;
        }

    if(stat(VAR_RUN_PMT, &st) != 0) {
        if(errno != ENOENT) {
            ret = errno;
            l0g(PREFIX "unable to stat" VAR_RUN_PMT ": %s\n", strerror(errno));
            return ret;
        }
        if((ret = create_var_run()) < 0)
            return ret;
    }

    snprintf(filename, sizeof(filename), VAR_RUN_PMT "/%s", user);
    while((ret = fd = open_and_lock(filename, passwd_ent->pw_uid)) == -EAGAIN)
        /* noop */;
    if(ret < 0)
        return ret;

    if((val = read_current_count(fd, filename)) < 0) {
        close(fd);
        return val;
    }

    w4rn(PREFIX "parsed count value %ld\n", val);
	if(amount != 0) {		/* amount == 0 implies query */
                int size;
		val += amount;
                if(val <= 0 && unlink(filename) != 0) {
                    l0g(PREFIX "could not unlink %s: %s\n",
                      filename, strerror(errno));
		}
		snprintf(buf, st.st_size + 2, "%ld", val);
		if (write(fd, buf, strlen(buf)) == -1) {
                    err = errno;
                    l0g(PREFIX "write error on %s: %s\n",
                      filename, strerror(errno));
                    goto return_error;
		}
                if((size = lseek(fd, 0, SEEK_CUR)) < 0) {
                    l0g(PREFIX "lseek: %s\n", strerror(errno));
                    err = errno;
                    goto return_error;
                }
                write(fd, " ", 1);
                ftruncate(fd, size);
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
    int ret;
	struct settings settings;

	set_defaults(&settings);
	parse_args(argc, argv, &settings);

	if (strlen(settings.user) == 0)
		usage(EXIT_FAILURE, NULL, NULL);

    ret = modify_pm_count(settings.user, settings.operation);
    if(ret == -ESTALE) {
        printf("0\n");
        return EXIT_SUCCESS;
    } else if(ret < 0) {
        return EXIT_FAILURE;
    }

    // print current count so pam_mount module may read it
    printf("%d\n", ret);
    return EXIT_SUCCESS;
}

//-----------------------------------------------------------------------------
/*  create_var_run

    Creates the /var/run/pam_mount directory required by pmvarrun and sets
    proper permissions on it.

    Returns >0 for success or <=0 to indicate errno.
*/
static int create_var_run(void) {
    int ret;

    w4rn(PREFIX "creating " VAR_RUN_PMT);
    if(mkdir(VAR_RUN_PMT, 0000) != 0) {
        ret = errno;
        l0g(PREFIX "unable to create " VAR_RUN_PMT ": %s\n", strerror(errno));
        return ret;
    }

    if(chown(VAR_RUN_PMT, 0, 0) != 0) {
        ret = errno;
        l0g(PREFIX "unable to chown " VAR_RUN_PMT ": %s\n", strerror(errno));
        return ret;
    }

    /* 0755: `su` creates file group owned by user and the releases root
    permissions. User needs to be able to access file on logout. */

    if(chmod(VAR_RUN_PMT, S_IRWXU | S_IRXG | S_IRXO) != 0) {
        ret = errno;
        l0g(PREFIX "unable to chmod " VAR_RUN_PMT ": %s\n", strerror(errno));
        return ret;
    }

    return 1;
}

/*  open_and_lock
    @filename:  file to open

    Creates if necessary, opens and chown()s @filename, and locks it.
    Returns the fd if all of that succeeded, -EAGAIN if the file was unlinked
    during operation (see below), -ESTALE if the lock could not be obtained,
    and <0 otherwise to indicate errno.
*/
static int open_and_lock(const char *filename, long uid) {
    struct flock lockinfo = {
        .l_type   = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start  = 0,
        .l_len    = 0,
    };
    struct stat sb;
    int fd, ret;

    if((fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
        ret = errno;
        l0g(PREFIX "unable to open %s: %s\n", filename, strerror(errno));
        return ret;
    }
    if((fchown(fd, uid, 0)) != 0) {
        ret = errno;
        l0g(PREFIX "unable to chown %s: %s\n", filename, strerror(errno));
        return ret;
    }

    /* Note: Waiting too long might interfere with LOGIN_TIMEOUT from
    /etc/login.defs, and /bin/login itself may prematurely kill the session. */
    alarm(20);
    ret = fcntl(fd, F_SETLKW, &lockinfo);
    alarm(0);
    if(ret == EAGAIN) {
        /* [Flyn] If someone has locked the file and not written to it in at
        least 20 seconds, we assume they either forgot to unlock it or are
        catatonic -- chances are slim that they are in the middle of a
        read-write cycle and I do not want to make us lock users out. Perhaps
        I should just return PAM_SUCCESS instead and log the event? Kill the
        process holding the lock? Options abound... For now, we ignore it. */

        /* [Jen] pmvarrun is the only one ever writing to that file, and we
        keep the lock as short as possible. So if there is no response within
        the time limit, something is fouled up (e.g. NFS server not
        responding - though /var/run should at best not be on an NFS mount).
        Continue, let user log in, do not change anything. */

        w4rn(PREFIX "stale lock on file %s - continuing without increasing"
             "pam_mount reference count\n", filename);
        close(fd);
        return -ESTALE;
    }

    /* It is possible at this point that the file has been removed by a
    previous login; if this happens, we need to start over. */
    if(stat(filename, &sb) != 0) {
        ret = errno;
        close(fd);
        if(ret == ENOENT)
            return -EAGAIN;
        return -ret;
    }

    return fd;
}

/*  read_current_count
    @fd:        file descriptor to read from

    Reads the current user's reference count from @fd and returns the value
    on success. Otherwise, returns -EOVERFLOW in case we suspect a problem or
    <0 to indicate errno.
*/
static long read_current_count(int fd, const char *filename) {
    char buf[ASCIIZ_LLX] = {};
    long ret;

    if((ret = read(fd, buf, sizeof(buf))) < 0) {
        ret = errno;
        l0g(PREFIX "read error on fd: %s\n", filename, strerror(errno));
        close(fd);
        return -ret;
    } else if(ret == 0) {
        /* File is empty, ret is already 0 -- we are set. */
    } else if(ret < sizeof(buf)) {
        char *p;
        if((ret = strtol(buf, &p, 0)) >= LONG_MAX || p == buf) {
            l0g(PREFIX "parse problem / session count corrupt (overflow), "
                "check your refcount file\n");
            return -EOVERFLOW;
        }
    } else if(ret >= sizeof(buf)) {
        l0g(PREFIX "session count corrupt (overflow)\n");
        return -EOVERFLOW;
    }

    return ret;
}

//=============================================================================
