/*=============================================================================
pam_mount - pmvarrun.c
  Copyright © W. Michael Petullo <mike@flyn.org>, 2004
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
/*
pmvarrun.c -- Updates /var/run/pam_mount/<user>.
    A seperate program is needed so that /var/run/pam_mount/<user> may be
    created with a pam_mount-specific security context (otherwise SELinux
    policy will conflict with gdm, which also creates files in /var/run).
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
#include "compiler.h"
#include "misc.h"
#include "pam_mount.h"
#include "private.h"

/* Definitions */
#undef PMPREFIX
#define PMPREFIX        "pmvarrun: "
#define ASCIIZ_LLX      sizeof("0xFFFFFFFF""FFFFFFFF")
#define VAR_RUN         "/var/run"
#define VAR_RUN_PMT     VAR_RUN "/pam_mount"

struct settings {
	char user[MAX_PAR + 1];
	long operation;
};

/* Functions */
static int create_var_run(void);
static int modify_pm_count(const char *, long);
static int open_and_lock(const char *, long);
static void parse_args(const int, const char **, struct settings *);
static long read_current_count(int, const char *);
static void set_defaults(struct settings *);
static void usage(int, const char *);
static int write_count(int, long, const char *);

/* Variables */
bool Debug = false;

//-----------------------------------------------------------------------------
/*
 * usage - display help
 * @exitcode:	numeric value we will be exiting with
 * @error:	descriptive error string
 *
 * Displays the help string and an optional extra error message.
 */
static void usage(const int exitcode, const char *error)
{
	fprintf(stderr, "Usage: pmvarrun -u USER [-o NUMBER] [-d]\n");
	if (error != NULL)
		fprintf(stderr, PMPREFIX ": %s\n\n", error);
	exit(exitcode);
}

/*
 * set_defaults -
 * @settings:	pointer to settings structure
 */
static void set_defaults(struct settings *settings)
{
	*settings->user     = '\0';
	settings->operation = 1;
	return;
}

/*
 * from https://vitalnix.svn.sourceforge.net/svnroot/vitalnix/
 * /trunk/src/libvxutil/util.c
 */
static int valid_username(const char *n)
{
	if (*n == '\0')
		return 0;
	if (!((*n >= 'A' && *n <= 'Z') || (*n >= 'a' && *n <= 'z') ||
	    *n == '_'))
		return 0;

	while (*n != '\0') {
		int valid;

		if (*n == '$' && *(n+1) == '\0') /* Samba accounts */
			return 1;

		valid = (*n >= 'A' && *n <= 'Z') || (*n >= 'a' && *n <= 'z') ||
		        (*n >= '0' && *n <= '9') || *n == '_' || *n == '.' ||
		        *n == '-';
		if (!valid)
			return 0;
		++n;
	}

	return 1;
}

/*
 * parse_args
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 * @settings:	pointer to settings structure
 *
 * Parse options from @argv and put it into @settings.
 */
static void parse_args(int argc, const char **argv, struct settings *settings)
{
	int c;

	while ((c = getopt(argc, reinterpret_cast(char * const *, argv),
	    "hdo:u:")) >= 0) {
		switch (c) {
		case 'h':
			usage(EXIT_SUCCESS, NULL);
			break;
		case 'd':
			Debug = 1;
			break;
		case 'o':
			settings->operation = str_to_long(optarg);
			if (settings->operation == LONG_MAX ||
			    settings->operation == LONG_MIN)
				usage(EXIT_FAILURE, "count string is not valid");
			break;
		case 'u':
			if (!valid_username(optarg)) {
				fprintf(stderr, "Invalid user name\n");
				exit(EXIT_FAILURE);
			}
			HX_strlcpy(settings->user, optarg,
			           sizeof(settings->user));
			break;
		default:
			usage(EXIT_FAILURE, NULL);
			break;
	    }
	}
	return;
}

/*
 * modify_pm_count -
 * @user:	user to poke on
 * @amount:	increment (usually -1, 0 or +1)
 *
 * Adjusts /var/run/pam_mount/@user by @amount, or deletes the file if the
 * resulting value (current + @amount) is <= 0. Returns >= 0 on success to
 * indicate the new login count, or negative to indicate errno. -ESTALE and
 * -EOVERFLOW are passed up from subfunctions and must be handled in the
 * caller.
 */
static int modify_pm_count(const char *user, long amount)
{
	char filename[PATH_MAX + 1];
	struct passwd *pent;
	struct stat sb;
	int fd, ret;
	long val;

	assert(user != NULL);

	if ((pent = getpwnam(user)) == NULL) {
		ret = -errno;
		l0g("could not resolve user %s\n", user);
		return ret;
	}

	if (stat(VAR_RUN_PMT, &sb) < 0) {
		if (errno != ENOENT) {
			ret = -errno;
			l0g("unable to stat " VAR_RUN_PMT ": %s\n",
			    strerror(errno));
			return ret;
		}
		if ((ret = create_var_run()) < 0)
			return ret;
	}

	snprintf(filename, sizeof(filename), VAR_RUN_PMT "/%s", user);
	while ((ret = fd = open_and_lock(filename, pent->pw_uid)) == -EAGAIN)
		/* noop */;
	if (ret < 0)
		return ret;

	if ((val = read_current_count(fd, filename)) < 0) {
		close(fd);
		return val;
	}

	w4rn("parsed count value %ld\n", val);
	/* amount == 0 implies query */
	ret = 1;
	if (amount != 0)
		ret = write_count(fd, val + amount, filename);

	close(fd);
	return (ret < 0) ? ret : val + amount;
}

int main(int argc, const char **argv)
{
	struct settings settings;
	int ret;

	set_defaults(&settings);
	parse_args(argc, argv, &settings);

	if (strlen(settings.user) == 0)
		usage(EXIT_FAILURE, NULL);

	ret = modify_pm_count(settings.user, settings.operation);
	if (ret == -ESTALE) {
		printf("0\n");
		return EXIT_SUCCESS;
	} else if (ret < 0) {
		return EXIT_FAILURE;
	}

	/* print current count so pam_mount module may read it */
	printf("%d\n", ret);
	return EXIT_SUCCESS;
}

//-----------------------------------------------------------------------------
/*
 * create_var_run
 *
 * Creates the /var/run/pam_mount directory required by pmvarrun and sets
 * proper permissions on it.
 *
 * Returns >0 for success or <=0 to indicate errno.
 */
static int create_var_run(void)
{
	int ret;

	w4rn("creating " VAR_RUN_PMT);
	if (mkdir(VAR_RUN_PMT, 0000) < 0) {
		ret = -errno;
		l0g("unable to create " VAR_RUN_PMT ": %s\n", strerror(errno));
		return ret;
	}
	if (chown(VAR_RUN_PMT, 0, 0) < 0) {
		ret = -errno;
		l0g("unable to chown " VAR_RUN_PMT ": %s\n", strerror(errno));
		return ret;
	}

	/*
	 * 0755: `su` creates file group owned by user and then releases root
	 * permissions. User needs to be able to access file on logout.
	 */
	if (chmod(VAR_RUN_PMT, S_IRWXU | S_IRXG | S_IRXO) < 0) {
		ret = -errno;
		l0g("unable to chmod " VAR_RUN_PMT ": %s\n", strerror(errno));
		return ret;
	}

	return 1;
}

/*
 * open_and_lock -
 * @filename:	file to open
 *
 * Creates if necessary, opens and chown()s @filename, and locks it.
 * Returns the fd if all of that succeeded, -EAGAIN if the file was unlinked
 * during operation (see below), -ESTALE if the lock could not be obtained,
 * and <0 otherwise to indicate errno.
 */
static int open_and_lock(const char *filename, long uid) {
	struct flock lockinfo = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len	= 0,
	};
	struct stat sb;
	int fd, ret;

	if ((fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR)) < 0) {
		ret = -errno;
		l0g("unable to open %s: %s\n", filename, strerror(errno));
		return ret;
	}
	if (fchown(fd, uid, 0) < 0) {
		ret = -errno;
		l0g("unable to chown %s: %s\n", filename, strerror(errno));
		return ret;
	}

	/*
	 * Note: Waiting too long might interfere with LOGIN_TIMEOUT from
	 * /etc/login.defs, and /bin/login itself may prematurely kill the
	 * /session.
	 */
	alarm(20);
	ret = fcntl(fd, F_SETLKW, &lockinfo);
	alarm(0);
	if (ret == EAGAIN) {
		/*
		 * [Flyn] If someone has locked the file and not written to it
		 * in at least 20 seconds, we assume they either forgot to
		 * unlock it or are catatonic -- chances are slim that they are
		 * in the middle of a read-write cycle and I do not want to
		 * make us lock users out. Perhaps I should just return
		 * %PAM_SUCCESS instead and log the event? Kill the process
		 * holding the lock? Options abound... For now, we ignore it.
		 *
		 * [CCJ] pmvarrun is the only one ever writing to that file,
		 * and we keep the lock as short as possible. So if there is no
		 * response within the time limit, something is fouled up (e.g. 
		 * NFS server not responding -- though /var/run should at best
		 * not be on an NFS mount).  Continue, let user log in, do not
		 * change anything.
		 */
		w4rn("stale lock on file %s - continuing without increasing"
		     "pam_mount reference count\n", filename);
		close(fd);
		return -ESTALE;
	}

	/*
	 * It is possible at this point that the file has been removed by a
	 * previous login; if this happens, we need to start over.
	 */
	if (stat(filename, &sb) < 0) {
		ret = -errno;
		close(fd);
		if (ret == -ENOENT)
			return -EAGAIN;
		return ret;
	}

	return fd;
}

/*
 * read_current_count -
 * @fd:	file descriptor to read from
 *
 * Reads the current user's reference count from @fd and returns the value
 * on success. Otherwise, returns -EOVERFLOW in case we suspect a problem or
 * <0 to indicate errno.
 */
static long read_current_count(int fd, const char *filename) {
	char buf[ASCIIZ_LLX] = {};
	long ret;

	if ((ret = read(fd, buf, sizeof(buf))) < 0) {
		ret = -errno;
		l0g("read error on %s: %s\n", filename, strerror(errno));
		close(fd);
		return ret;
	} else if (ret == 0) {
		/* File is empty, ret is already 0 -- we are set. */
	} else if (ret < sizeof(buf)) {
		char *p;
		if ((ret = strtol(buf, &p, 0)) >= LONG_MAX || p == buf) {
			l0g("parse problem / session count corrupt "
			    "(overflow), check your refcount file\n");
			return -EOVERFLOW;
		}
	} else if (ret >= sizeof(buf)) {
		l0g("session count corrupt (overflow)\n");
		return -EOVERFLOW;
	}

	return ret;
}

/*
 * write_count -
 * @fd:		file descriptor to write to
 * @nv:		new value to write
 * @filename:	filename, only used for l0g()
 *
 * Writes @nv as a number in hexadecimal to the start of the file @fd and
 * truncates the file to the written length.
 */
static int write_count(int fd, long nv, const char *filename) {
	char buf[ASCIIZ_LLX];
	int wrt, len, ret;

	if (nv <= 0 && unlink(filename) < 0) {
		l0g("could not unlink %s: %s\n", filename, strerror(errno));
		return 1; /* let user log in */
	}

	if ((ret = lseek(fd, 0, SEEK_SET)) != 0) {
		ret = -errno;
		l0g("failed to seek in %s: %s\n", filename, strerror(errno));
		return ret;
	}

	len = snprintf(buf, sizeof(buf), "0x%lX", nv);
	if ((wrt = write(fd, buf, len)) != len) {
		ret = -errno;
		l0g("wrote %d of %d bytes; write error on %s: %s\n",
		    (wrt < 0) ? 0 : wrt, len, filename, strerror(errno));
		close(fd);
		return ret;
	}

	ftruncate(fd, len);
	return 1;
}

//=============================================================================
