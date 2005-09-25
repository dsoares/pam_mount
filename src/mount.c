/*   FILE: mount.c
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "crypto.h"
#include "fmt_ptrn.h"
#include "misc.h"
#include "mount.h"
#include "optlist.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#    include <fstab.h>
#elif defined(__linux__)
#    include <mntent.h>
#    include <sys/ioctl.h>
#    include <sys/stat.h>
#    include <fcntl.h>
#    include <linux/loop.h>
#    include <linux/major.h>
#endif

#ifdef HAVE_LIBCRYPTO
#    ifndef EVP_MAX_BLOCK_LENGTH
#        define EVP_MAX_BLOCK_LENGTH 32 // some older openssl versions need this
#    endif
#else
#    define EVP_MAX_BLOCK_LENGTH 0 // FIXME: this is ugly, but needed
#endif

#define PMPREFIX "pam_mount: "

static int already_mounted(const config_t * const, const unsigned int,
    char * const, fmt_ptrn_t *);
static int check_filesystem(config_t *, const unsigned int, fmt_ptrn_t *,
    const unsigned char *, size_t);
static int do_losetup(config_t *, const unsigned int, fmt_ptrn_t *,
    const unsigned char *, size_t);
static int do_unlosetup(config_t *, fmt_ptrn_t *);
static void log_output(int);
static void log_pm_input(const config_t * const, const unsigned int);
static int mkmountpoint(vol_t * const, const char * const);
static int pipewrite(int, const void *, size_t);
static void run_lsof(const config_t *, fmt_ptrn_t *);
static inline const char *loop_bk(const char *, struct loop_info64 *);

/* ============================ log_output () ============================== */
/* INPUT: fd, a valid file descriptor
 * SIDE EFFECTS: contents of fd are logged, usually fd is connected by a 
 *               pipe to another process's stdout or stderr
 */
static void log_output(int fd)
{
	FILE *fp;
	char buf[BUFSIZ + 1];
	/* FIXME: check fdopen's retval */
	if ((fp = fdopen(fd, "r")) == NULL) {
		w4rn(PMPREFIX "error opening file: %s\n",
		     strerror(errno));
		return;
	}
	while(fgets(buf, sizeof(buf), fp) != NULL)
		w4rn(PMPREFIX "%s\n", buf);
}

/* ============================ run_lsof () ================================ */
/*
 * NOTE: this fn simply runs lsof on a directory and logs its output for
 * debugging purposes
 */
static void run_lsof(const config_t *config, fmt_ptrn_t *vinfo) {
	int i, _argc = 0, cstdout = -1, child_exit;
	char *_argv[MAX_PAR + 1];
	GError *err = NULL;
	pid_t pid;
	if(config->command[0][LSOF] == NULL)
		l0g(PMPREFIX "lsof not defined in pam_mount.conf\n");
	/* FIXME: NEW */
	for(i = 0; config->command[i][LSOF] != NULL; i++)
		add_to_argv(_argv, &_argc, config->command[i][LSOF],
			    vinfo);
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	     &pid, NULL, &cstdout, NULL, &err) == FALSE) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		return;
	}
	w4rn(PMPREFIX "lsof output (should be empty)...\n");
	log_output(cstdout);
	w4rn(PMPREFIX "waiting for lsof\n");
	if (waitpid(pid, &child_exit, 0) == -1)
		l0g(PMPREFIX "error waiting for child\n");
	CLOSE(cstdout);
}

/* ============================ already_mounted () ========================= */
/*
 * PRE:    config->volume[vol].type is a mount type (LCLMOUNT, SMBMOUNT, ...)
 *         sizeof(mntpt) >= PATH_MAX + 1
 *         vinfo is a valid struct fmt_ptrn_t
 * POST:   mntpt contains:
 *           config->volume[vol].mountpoint if config->volume[vol].volume is
 *             already mounted there
 *           some other path if config->volume[vol].volume is mounted elsewhere
 *           undefined if config->volume[vol].volume is not mounted
 * FN VAL: 1 if config->volume[vol].volume is mounted, 0 if not, -1 on error
 *         errors are logged
 */
static int already_mounted(const config_t *const config,
 const unsigned int vol, char *const mntpt, fmt_ptrn_t *vinfo)
{
	char match[PATH_MAX + 1];
	int mounted = 0;
#if defined(__linux__)
	FILE *mtab;
	struct mntent *mtab_record;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	int fds[2];
	pid_t pid;
#endif

	assert(config_t_valid(config));

	memset(match, 0, sizeof(match));
	if (config->volume[vol].type == SMBMOUNT
	    || config->volume[vol].type == CIFSMOUNT) {
		strcpy(match, "//");
		strncat(match, config->volume[vol].server,
			sizeof(match) - strlen(match) - 1);
		strncat(match, "/", sizeof(match) - strlen(match) - 1);
		strncat(match, config->volume[vol].volume,
			sizeof(match) - strlen(match) - 1);
	} else if (config->volume[vol].type == NCPMOUNT) {
		strncpy(match, config->volume[vol].server,
			sizeof(match) - strlen(match) - 1);
		strncat(match, "/", sizeof(match) - strlen(match) - 1);
		/* FIXME: volume sanity check in readconfig.c ensures optlist_value() will not return NULL for user */
		strncat(match,
			optlist_value(config->volume[vol].options, "user"),
			sizeof(match) - strlen(match) - 1);
	} else if (config->volume[vol].type == NFSMOUNT) {
		strncpy(match, config->volume[vol].server,
			sizeof(match) - strlen(match) - 1);
		strncat(match, ":", sizeof(match) - strlen(match) - 1);
		strncat(match, config->volume[vol].volume,
			sizeof(match) - strlen(match) - 1);
		/* FIXME: ugly hack to support umount.crypt script.  I hope that
		 * util-linux will have native dm_crypt support some day */
	} else if (config->volume[vol].type == CRYPTMOUNT) {
		int i;
		char escaped_vol[PATH_MAX + 1];
		strncpy(match, "/dev/mapper/", sizeof(match) - strlen(match) - 1);
		/* isn't there a function to do this in libc or glib? */
		for (i = 0; config->volume[vol].volume && i < sizeof(escaped_vol) - 1;
		     i++) {
			if (config->volume[vol].volume[i] == '/')
				escaped_vol[i] = '_';
			else
				escaped_vol[i] =
				    config->volume[vol].volume[i];
		}
		strncat(match, escaped_vol, sizeof(match) - strlen(match) - 1);
	} else {
		strncpy(match, config->volume[vol].volume, sizeof(match) - 1);
	}
#if defined(__linux__)
	if((mtab = fopen("/etc/mtab", "r")) == NULL) {
		l0g(PMPREFIX "could not open /etc/mtab\n");
		return -1;
	}
	w4rn(PMPREFIX "checking to see if %s is already mounted at %s\n",
	     match, config->volume[vol].mountpoint);

	while ((mtab_record = getmntent(mtab)) != NULL) {
            char const *mnt_fsname = mtab_record->mnt_fsname;
            struct loop_info64 loopdev;
            struct stat statbuf;

            if(stat(mnt_fsname, &statbuf) == 0 && S_ISBLK(statbuf.st_mode) &&
             major(statbuf.st_rdev) == LOOP_MAJOR) {
                /* If /etc/mtab is a link to /proc/mounts then the loop device
                instead of the real device will be listed -- resolve it. */
                mnt_fsname = loop_bk(mnt_fsname, &loopdev);
            }

		/* FIXME: okay to always ignore case (needed for NCP)? */
		if(strcasecmp(mnt_fsname, match) == 0) {
			strncpy(mntpt, mtab_record->mnt_dir, PATH_MAX);
			mntpt[PATH_MAX] = '\0';
			mounted = 1;
			if(strcmp(mtab_record->mnt_dir,
				    config->volume[vol].mountpoint) == 0) {
				strncpy(mntpt, mtab_record->mnt_dir,
					PATH_MAX);
				mntpt[PATH_MAX] = '\0';
				break;
			}
		}
	}
	fclose(mtab);
	return mounted;
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
	{
		FILE *fp;
		GError *err = NULL;
		int i, _argc = 0, cstdout = -1;
		char *_argv[MAX_PAR + 1], dev[BUFSIZ + 1];
		/*
		 * FIXME: I'm not overly fond of using mount, but BSD has no
		 * /etc/mtab?
		 */
		if(config->command[0][MNTCHECK] == NULL) {
			l0g(PMPREFIX "mntcheck not defined in pam_mount.conf\n");
			return -1;
		}
		/* FIXME: NEW */
		for(i = 0; config->command[i][MNTCHECK] != NULL; i++)
			add_to_argv(_argv, &_argc,
				    config->command[i][MNTCHECK], vinfo);
		log_argv(_argv);
		if (g_spawn_async_with_pipes
		    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL,
		     NULL, &pid, NULL, &cstdout, NULL, &err) == FALSE) {
			l0g(PMPREFIX "%s\n", err->message);
			g_error_free(err);
			return -1;
		}
		fp = fdopen(cstdout, "r");
		while(fgets(dev, BUFSIZ, fp) != NULL) {
			/*
			 * FIXME: A bit ugly but
			 * works.
			 */
			char *mp, *trash;
			w4rn(PMPREFIX "mounted filesystem: %s", dev);	/* dev includes '\n' */
			trash = strchr(dev, ' ');
			if(trash == NULL) {
				mounted = -1;	/* parse err */
				break;
			}
			*trash = '\0';
			mp = strchr(trash + 1, ' ');
			if(mp++ == NULL) {
				mounted = -1;	/* parse err */
				break;
			}
			trash = strchr(mp, ' ');
			if(trash == NULL) {
				mounted = -1;	/* parse err */
				break;
			}
			*trash = '\0';
			/* FIXME: okay to always ignore case (needed for NCP)? */
			if(strcasecmp(dev, match) == 0) {
				strncpy(mntpt, mp, PATH_MAX);
				mntpt[PATH_MAX] = NULL;
				mounted = 1;
				if(strcmp(mp,
					    config->volume[vol].
					    mountpoint) == 0) {
					strncpy(mntpt, mp, PATH_MAX);
					mntpt[PATH_MAX] = NULL;
					mounted = 1;
					break;
				}
			}
		}
		return mounted;
	}
#else
	/* FIXME */
	l0g(PMPREFIX "check for previous mount not implemented on arch.\n");
	return ERROR;
#endif
}

/* ============================ log_pm_input () ============================ */
static void log_pm_input(const config_t *const config,
 const unsigned int vol)
{
	char options[MAX_PAR + 1];
	w4rn(PMPREFIX "information for mount:\n");
	w4rn(PMPREFIX "----------------------\n");
	w4rn(PMPREFIX "%s\n",
	     (config->volume[vol].globalconf == TRUE) ?
              "(defined by globalconf)" : "(defined by luserconf)");
	w4rn(PMPREFIX "user:          %s\n", config->volume[vol].user);
	w4rn(PMPREFIX "server:        %s\n", config->volume[vol].server);
	w4rn(PMPREFIX "volume:        %s\n", config->volume[vol].volume);
	w4rn(PMPREFIX "mountpoint:    %s\n",
	     config->volume[vol].mountpoint);
	w4rn(PMPREFIX "options:       %s\n",
	     optlist_to_str(options, config->volume[vol].options));
	w4rn(PMPREFIX "fs_key_cipher: %s\n",
	     config->volume[vol].fs_key_cipher);
	w4rn(PMPREFIX "fs_key_path:   %s\n",
	     config->volume[vol].fs_key_path);
	w4rn(PMPREFIX "use_fstab:   %d\n",
	     config->volume[vol].use_fstab);
	w4rn(PMPREFIX "----------------------\n");
}

/* ============================ mkmountpoint () ============================ */
/* POST:   the directory named d exists && volume->created_mntpt = TRUE
 * FN VAL: if error 0 else 1, errors are logged
 */
static int mkmountpoint(vol_t *const volume, const char *const d) {
	int ret = 1;
	struct passwd *passwd_ent;
	char dcopy[PATH_MAX + 1], *parent;

	assert(vol_t_valid(volume));
	assert(d != NULL);

	w4rn(PMPREFIX "creating mount point %s\n", d);
	strncpy(dcopy, d, sizeof(dcopy) - 1);
	dcopy[PATH_MAX] = '\0';
	parent = g_path_get_dirname(dcopy);
	if(!exists(parent) && mkmountpoint(volume, parent) == 0) {
		ret = 0;
		goto _return;
	}
	if((passwd_ent = getpwnam(volume->user)) != NULL) {
		if (mkdir(d, 0700) != 0) {
			l0g(PMPREFIX "tried to create %s but failed\n",
			    d);
			ret = 0;
			goto _return;
		}
		if (chown(d, passwd_ent->pw_uid, passwd_ent->pw_gid)
		    != 0) {
			l0g(PMPREFIX "could not chown %s to %s\n",
			    d, volume->user);
			ret = 0;
			goto _return;
		}
	} else {
		l0g(PMPREFIX "could not determine uid from %s to make %s\n", volume->user, d);
		ret = 0;
		goto _return;
	}
	volume->created_mntpt = TRUE;
      _return:
	g_free(parent);
	return ret;
}

int do_unmount(config_t *config, const unsigned int vol, fmt_ptrn_t *vinfo,
 const char *const password, const gboolean mkmntpoint)
/* PRE:    config points to a valid config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         vinfo is a valid struct fmt_ptrn_t
 *         mkmntpoint is true if mount point should be rmdir'ed
 * POST:   volume is unmounted
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	GError *err = NULL;
	int i, child_exit, _argc = 0, ret = 1, cstderr = -1;
	pid_t pid = -1;
	char *_argv[MAX_PAR + 1];
        int type;

	assert(config_t_valid(config));
	assert(vinfo != NULL);
	assert(password == NULL);	/* password should point to NULL for unmounting */

	if(Debug == TRUE)
		/*
		 * Often, a process still exists with ~ as its pwd after
		 * logging out.  Running lsof helps debug this.
		 */
		run_lsof(config, vinfo);

        switch(config->volume[vol].type) {
            case SMBMOUNT: type = SMBUMOUNT; break;
            case NCPMOUNT: type = NCPUMOUNT; break;
            default:       type = UMOUNT; break;
        }

        if(config->command[0][type] == NULL)
            l0g(PMPREFIX "{smb,ncp}umount not defined in pam_count.conf\n");

        for(i = 0; config->command[i][type] != NULL; ++i)
            add_to_argv(_argv, &_argc, config->command[i][type], vinfo);

	/* FIXME: ugly hack to support umount.crypt script.  I hope that
	 * util-linux will have native dm_crypt support some day */
	if (config->volume[vol].type == CRYPTMOUNT) {
		_argc = 0;
		add_to_argv(_argv, &_argc, "/usr/bin/umount.crypt", vinfo);
		add_to_argv(_argv, &_argc, "%(MNTPT)", vinfo);
	}
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid, NULL,
	     &pid, NULL, NULL, &cstderr, &err) == FALSE) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		ret = 0;
		goto _return;
	}
	w4rn(PMPREFIX "umount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn(PMPREFIX "waiting for umount\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g(PMPREFIX "error waiting for child\n");
		ret = 0;
		goto _return;
	} else {
		/* pass on through the result from the umount process */
		ret = !WEXITSTATUS(child_exit);
	}
      _return:
	if (mkmntpoint != 0 && config->volume[vol].created_mntpt == TRUE) {
		if (rmdir(config->volume[vol].mountpoint) == -1)	/* non-fatal */
			w4rn(PMPREFIX "could not remove %s\n",
			     config->volume[vol].mountpoint);
	}
	return ret;
}

/* INPUT: fd, a valid file descriptor; buf, a buffer of size count
 * SIDE EFFECTS: buf is written to fd
 * OUTPUT: number of bytes written or 0 on error
 * NOTE: SIGPIPE is ignored during this operation to avoid "broken pipe"
 */
static int pipewrite(int fd, const void *buf, size_t count) {
	int fnval;
	struct sigaction ignoresact = {.sa_handler = SIG_IGN}, oldsact;

	assert(fd >= 0);
	assert(buf != NULL);
	assert(count >= 0);

	/* avoid bomb on command exiting before data written */
	if(sigaction(SIGPIPE, &ignoresact, &oldsact) == -1) {
		fnval = -1;
		goto _return;
	}
	fnval = write(fd, buf, count);
	/* restore old handler */
	if(sigaction(SIGPIPE, &oldsact, NULL) == -1) {
		fnval = -1;
		goto _return;
	}
_return:
	return fnval;
}

static int do_losetup(config_t *config, const unsigned int vol,
 fmt_ptrn_t *vinfo, const unsigned char *password, size_t password_len)
/* PRE:    config points to a valid config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         vinfo is a valid struct fmt_ptrn_t
 *         config->volume[vol].options is valid
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	pid_t pid;
	GError *err = NULL;
	int i, ret = 1, child_exit, _argc = 0, cstderr = -1;
	char *_argv[MAX_PAR + 1];
	const char *cipher =
	    optlist_value(config->volume[vol].options, "encryption");
	const char *keybits =
	    optlist_value(config->volume[vol].options, "keybits");

	assert(config_t_valid(config));
	assert(vinfo != NULL);
	assert(password != NULL);
	/* password_len is unsigned */
	assert(password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	if(config->command[0][LOSETUP] == NULL) {
		l0g(PMPREFIX "losetup not defined in pam_mount.conf\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	/* FIXME: NEW */
	if(cipher != NULL) {
		fmt_ptrn_update_kv(vinfo, "CIPHER", cipher);
		if(keybits != NULL)
			fmt_ptrn_update_kv(vinfo, "KEYBITS", keybits);
	}
	for(i = 0; config->command[i][LOSETUP] != NULL; i++) {
		add_to_argv(_argv, &_argc,
			    config->command[i][LOSETUP], vinfo);
	}
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid, NULL,
	     &pid, NULL, NULL, &cstderr, &err) == FALSE) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		ret = 0;
		goto _return;
	}
	w4rn(PMPREFIX "umount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn(PMPREFIX "waiting for losetup\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g(PMPREFIX "error waiting for child\n");
		ret = 0;
		goto _return;
	} else {
		/* pass on through the result from the losetup process */
		ret = !WEXITSTATUS(child_exit);
	}
      _return:
	return ret;
}

static int do_unlosetup(config_t *config, fmt_ptrn_t *vinfo) {
/* PRE:    config points to a valid config_t*
 *         vinfo is a valid struct fmt_ptrn_t
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
	pid_t pid;
	GError *err = NULL;
	char *_argv[MAX_PAR + 1];
	int i, child_exit, _argc = 0;

	assert(config_t_valid(config));
	assert(vinfo != NULL);

	if(config->command[0][UNLOSETUP] == NULL) {
		l0g(PMPREFIX "unlosetup not defined in pam_mount.conf\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	/* FIXME: NEW */
	for(i = 0; config->command[i][UNLOSETUP] != NULL; i++)
		add_to_argv(_argv, &_argc,
			    config->command[i][UNLOSETUP], vinfo);
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	     &pid, NULL, NULL, NULL, &err) == FALSE) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		return 0;
	}
	w4rn(PMPREFIX "waiting for losetup delete\n");
	waitpid(pid, &child_exit, 0);
	/* pass on through the result */
	return !WEXITSTATUS(child_exit);
}

static int check_filesystem(config_t *config, const unsigned int vol,
 fmt_ptrn_t * vinfo, const unsigned char *password, size_t password_len)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         vinfo is a valid struct fmt_ptrn_t
 * POST:   integrity of volume has been checked
 * FN VAL: if error 0 else 1, errors are logged
 */
{
#if defined (__linux__)
	pid_t pid;
	GError *err = NULL;
	int i, child_exit, _argc = 0, cstdout = -1, cstderr = -1;
	char *_argv[MAX_PAR + 1];
	char *fsck_target =
	    config->volume[vol].volume, options[MAX_PAR + 1];

	assert(config_t_valid(config));
	assert(vinfo != NULL);
	assert(password != NULL);
	assert(password_len >= 0
	       && password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	if(config->command[0][FSCK] == NULL) {
		l0g(PMPREFIX "fsck not defined in pam_mount.conf\n");
		return 0;
	}
	if (optlist_exists(config->volume[vol].options, "loop")) {
		if (!do_losetup
		    (config, vol, vinfo, password, password_len))
			return 0;
		fsck_target = config->fsckloop;
	} else
		w4rn(PMPREFIX "volume not a loopback (options: %s)\n",
		     optlist_to_str(options, config->volume[vol].options));
	/* FIXME: NEW */
	/* FIXME: need to fsck /dev/mapper/whatever... */
	fmt_ptrn_update_kv(vinfo, "FSCKTARGET", fsck_target);
	for (i = 0; config->command[i][FSCK]; i++)
		add_to_argv(_argv, &_argc, config->command[i][FSCK],
			    vinfo);
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	     &pid, NULL, &cstdout, &cstderr, &err) == FALSE) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		return 0;
	}
	log_output(cstdout);	/* stdout and stderr most be logged for fsck */
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn(PMPREFIX "waiting for filesystem check\n");
	waitpid(pid, &child_exit, 0);
	if (optlist_exists(config->volume[vol].options, "loop"))
		if (!do_unlosetup(config, vinfo))
			return 0;
	/* pass on through the result -- okay if 0 (no errors) 
	 * or 1 (errors corrected) */
	return (WEXITSTATUS(child_exit) == 0
		|| WEXITSTATUS(child_exit) == 1);
#else
	l0g(PMPREFIX "checking filesystem not implemented on arch.\n");
	return 1;
#endif
}

int do_mount(config_t *config, const unsigned int vol, fmt_ptrn_t *vinfo,
 const char *password, const gboolean mkmntpoint)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         vinfo is a valid struct fmt_ptrn_t
 *         mkmntpoint is true if mount point should be mkdir'ed
 *         false if mount point was received from pam_mount
 * POST:   volume is mounted
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	char *_argv[MAX_PAR + 1];
	char prev_mntpt[PATH_MAX + 1];
	size_t _password_len;
	int i, mount_again = 0;
	unsigned char _password[MAX_PAR + EVP_MAX_BLOCK_LENGTH];
	int _argc = 0, child_exit = 0, cstdin = -1, cstderr = -1;
	pid_t pid = -1;
        vol_t *vpt;

	assert(config_t_valid(config));
	assert(vinfo != NULL);
	assert(password != NULL);

        vpt = &config->volume[vol];

	/* FIXME: This is a little ugly, especially check for != LCLMOUNT */
	if((mount_again = already_mounted(config, vol, prev_mntpt, vinfo)) != 0) {
		if (mount_again == -1) {
			l0g(PMPREFIX "could not determine if %s is already mounted, failing\n", config->volume[vol].volume);
			return 0;
		} else if(strcmp(prev_mntpt, vpt->mountpoint) == 0) {
			w4rn(PMPREFIX "%s already seems to be mounted at %s, skipping\n", config->volume[vol].volume, prev_mntpt);
			return 1;
		} else {
			w4rn(PMPREFIX "%s already mounted elsewhere at %s\n", config->volume[vol].volume, prev_mntpt);
			/* FIXME: ugly hack to support umount.crypt script.  I hope that
			 * util-linux will have native dm_crypt support some day */
                        if(vpt->type != LCLMOUNT && vpt->type != CRYPTMOUNT)
				mount_again = 0;
		}
	}
        if(!exists(vpt->mountpoint)) {
		if (mkmntpoint) {
                        if(!mkmountpoint(vpt, vpt->mountpoint))
				return 0;
		} else {
			l0g(PMPREFIX "mount point %s does not exist (pam_mount not configured to make it)\n", config->volume[vol].mountpoint);
			return 0;
		}
	}
	if (mount_again) {
		GError *err = NULL;
		if(config->command[0][MNTAGAIN] == NULL) {
			l0g(PMPREFIX "mntagain not defined in pam_mount.conf\n");
			return 0;
		}
		/* FIXME: NEW */
		fmt_ptrn_update_kv(vinfo, "PREVMNTPT", prev_mntpt);
		for(i = 0; config->command[i][MNTAGAIN] != NULL; i++)
			add_to_argv(_argv, &_argc,
				    config->command[i][MNTAGAIN], vinfo);
		log_argv(_argv);
		if (g_spawn_async_with_pipes
		    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
		     set_myuid, NULL, &pid, NULL, NULL, &cstderr,
		     &err) == FALSE) {
			l0g(PMPREFIX "%s\n", err->message);
			g_error_free(err);
			return 0;
		}
	} else {
		GError *err = NULL;
		if(config->command[0][vpt->type] == NULL) {
			l0g(PMPREFIX "proper mount command not defined in pam_mount.conf\n");
			return 0;
		}
		w4rn(PMPREFIX "checking for encrypted filesystem key configuration\n");
		password = (password != NULL) ? password : "";	/* FIXME: better done elsewhere? */
		if(strlen(vpt->fs_key_cipher) > 0) {
			/* _password is binary data -- no strlen, strcpy, etc! */
			w4rn(PMPREFIX "decrypting FS key using system auth. token and %s\n", config->volume[vol].fs_key_cipher);
			/*
			 * config->volume[vol].fs_key_path contains real filesystem
			 * key.
			 */
                    if(!decrypted_key(_password, &_password_len,
                     vpt->fs_key_path, vpt->fs_key_cipher, password))
				return 0;
		} else {
			/* _password is an ASCII string in this case -- we'll treat its
			 * MAX_PAR + EVP_MAX_BLOCK_LENGTH size as the standard string 
			 * MAX_PAR + 1 in this case */
			strncpy((char *) _password, password, MAX_PAR);
			_password[MAX_PAR] = '\0';
			_password_len = strlen(password);
		}
		w4rn(PMPREFIX "about to start building mount command\n");
		/* FIXME: NEW */
		/* FIXME:
		   l0g(PMPREFIX "volume type (%d) is unknown\n", vpt->type);
		   return 0;
		 */
                for(i = 0; config->command[i][vpt->type] != NULL; ++i) {
                    add_to_argv(_argv, &_argc, config->command[i][vpt->type], vinfo);
                }
		log_argv(_argv);
                if(vpt->type == LCLMOUNT &&
                  !check_filesystem(config, vol, vinfo, _password, _password_len))
			l0g(PMPREFIX "error checking filesystem but will continue\n");
		/* send password down pipe to mount process */
                if(vpt->type == SMBMOUNT || vpt->type == CIFSMOUNT)
			setenv("PASSWD_FD", "0", 1);
		if (g_spawn_async_with_pipes
		    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
		     set_myuid, NULL, &pid, &cstdin, NULL, &cstderr,
		     &err) == FALSE) {
			l0g(PMPREFIX "%s\n", err->message);
			g_error_free(err);
			return 0;
		}
                if(vpt->type != NFSMOUNT) {
			if (pipewrite(cstdin, _password, _password_len) !=
			    _password_len)
				/* FIXME: clean: returns value of exit below */
				l0g(PMPREFIX "error sending password to mount\n");
			CLOSE(cstdin);
		}

	}
	/* Paranoia? */
	memset(_password, 0, sizeof(_password));
	w4rn(PMPREFIX "mount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn(PMPREFIX "waiting for mount\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g(PMPREFIX "error waiting for child\n");
		return 0;
	} else {
		/* pass on through the result from the umount process */
		return !WEXITSTATUS(child_exit);
	}
}

/* ============================ mount_op () ================================ */
/*
 * PRE:    mnt is function to execute mount operations: do_mount or do_unmount
 *         vol > 0
 *         config points to a valid struct config_t
 *         config->volume[vol] is a valid struct vol_t
 *         password points to a valid string (can be NULL if UNmounting)
 *         mkmntpoint is true if mount point should be created when it does
 *         not already exist
 * POST:   appropriate mount or unmount operations are performed
 * FN VAL: if error 0 else 1, errors are logged
 * NOTE:   * checked by volume_record_sane
 *         ** checked by read_volume()
 */
int mount_op(int (*mnt)(config_t *, const unsigned int, fmt_ptrn_t *,
 const char *, const int), config_t *config, const unsigned int vol,
 const char *password, const int mkmntpoint)
{
	int fnval;
	fmt_ptrn_t vinfo;
	char options[MAX_PAR + 1];

	assert(config_t_valid(config));

	fmt_ptrn_init(&vinfo);
	fmt_ptrn_update_kv(&vinfo, "MNTPT",
			   config->volume[vol].mountpoint);
	fmt_ptrn_update_kv(&vinfo, "FSCKLOOP", config->fsckloop);
	fmt_ptrn_update_kv(&vinfo, "VOLUME", config->volume[vol].volume);
	fmt_ptrn_update_kv(&vinfo, "SERVER", config->volume[vol].server);
	fmt_ptrn_update_kv(&vinfo, "USER", config->volume[vol].user);
	/* FIXME: should others remain undefined if == ""? */
	optlist_to_str(options, config->volume[vol].options);
	fmt_ptrn_update_kv(&vinfo, "OPTIONS", options);

	if(Debug)
		log_pm_input(config, vol);

	fnval = mnt(config, vol, &vinfo, password, mkmntpoint);
	fmt_ptrn_close(&vinfo);
	return fnval;
}

static inline const char *loop_bk(const char *filename,
 struct loop_info64 *i)
{
    int fd;
    if((fd = open(filename, O_RDONLY)) < 0) {
        return filename;
    }
    if(ioctl(fd, LOOP_GET_STATUS64, i) != 0) {
        close(fd);
        return filename;
    }
    close(fd);
    return (char *)i->lo_file_name; // signed_cast<>
}
