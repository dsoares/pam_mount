/*=============================================================================
mount.c
  Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
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
#include <config.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <glib.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include "compiler.h"
#include "crypto.h"
#include "fmt_ptrn.h"
#include "misc.h"
#include "mount.h"
#include "optlist.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"
#include "spawn.h"
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#    include <fstab.h>
#elif defined(__linux__)
#    include <mntent.h>
#    include <sys/ioctl.h>
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

// Functions
static int already_mounted(const struct config * const, const unsigned int, char * const, struct fmt_ptrn *);
static int check_filesystem(const struct config *, const unsigned int, struct fmt_ptrn *, const unsigned char *, size_t);
static int do_losetup(const struct config *, const unsigned int, struct fmt_ptrn *, const unsigned char *, size_t);
static int do_unlosetup(const struct config *, struct fmt_ptrn *);
static int fstype_nodev(const char *);
static void log_output(int);
static void log_pm_input(const struct config * const, const unsigned int);
static inline const char *loop_bk(const char *, struct loop_info64 *);
static int mkmountpoint(struct vol * const, const char * const);
static int pipewrite(int, const void *, size_t);
static void run_lsof(const struct config * const, struct fmt_ptrn *);
static void vol_to_dev(char *, size_t, const struct vol *);

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
static int split_bsd_mount(char *, const char **, const char **, const char **);
#endif

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
static void run_lsof(const struct config *const config,
 struct fmt_ptrn *vinfo)
{
	int i, _argc = 0, cstdout = -1, child_exit;
	const char *_argv[MAX_PAR + 1];
	GError *err = NULL;
	pid_t pid;
	if(config->command[0][LSOF] == NULL)
		l0g(PMPREFIX "lsof not defined in pam_mount.conf\n");
	/* FIXME: NEW */
	for(i = 0; config->command[i][LSOF] != NULL; i++)
		add_to_argv(_argv, &_argc, config->command[i][LSOF],
			    vinfo);
	log_argv(_argv);

        spawn_set_sigchld();
        if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	  &pid, NULL, &cstdout, NULL, &err)) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		return;
	}
	w4rn(PMPREFIX "lsof output (should be empty)...\n");
	log_output(cstdout);
	w4rn(PMPREFIX "waiting for lsof\n");
	if (waitpid(pid, &child_exit, 0) == -1)
		l0g(PMPREFIX "error waiting for child\n");
        spawn_restore_sigchld();
	CLOSE(cstdout);
}

/* ============================ already_mounted () ========================= */
/*
 * PRE:    config->volume[vol].type is a mount type (LCLMOUNT, SMBMOUNT, ...)
 *         sizeof(mntpt) >= PATH_MAX + 1
 *         vinfo is a valid struct fmt_ptrn
 * POST:   mntpt contains:
 *           config->volume[vol].mountpoint if config->volume[vol].volume is
 *             already mounted there
 *           some other path if config->volume[vol].volume is mounted elsewhere
 *           undefined if config->volume[vol].volume is not mounted
 * FN VAL: 1 if config->volume[vol].volume is mounted, 0 if not, -1 on error
 *         errors are logged
 */
static int already_mounted(const struct config *const config,
 const unsigned int vol, char *const mntpt, struct fmt_ptrn *vinfo)
#if defined(__linux__)
{
    char dev[PATH_MAX+1] = {}, real_mpt[PATH_MAX+1];
    struct mntent *mtab_record;
    int mounted = 0;
    FILE *mtab;
    struct vol *vpt;

    assert(config_valid(config));
    vpt = &config->volume[vol];
    vol_to_dev(dev, sizeof(dev), vpt);

    if((mtab = setmntent("/etc/mtab", "r")) == NULL) {
        l0g(PMPREFIX "could not open /etc/mtab\n");
        return -1;
    }
    if(realpath(vpt->mountpoint, real_mpt) == NULL) {
        w4rn(PMPREFIX "can't get realpath of volume %s: %s\n",
          vpt->mountpoint, strerror(errno));
        strncpy(real_mpt, vpt->mountpoint, PATH_MAX);
        real_mpt[PATH_MAX] = '\0';
    } else {
        real_mpt[PATH_MAX] = '\0';
        l0g(PMPREFIX "realpath of volume \"%s\" is \"%s\"\n",
          vpt->mountpoint, real_mpt);
    }
    w4rn(PMPREFIX "checking to see if %s is already mounted at %s\n",
      dev, vpt->mountpoint);

    while((mtab_record = getmntent(mtab)) != NULL) {
        const char *fsname = mtab_record->mnt_fsname;
        const char *fstype = mtab_record->mnt_type;
        const char *fspt   = mtab_record->mnt_dir;
        int (*xcmp)(const char *, const char *);
        struct loop_info64 loopdev;
        struct stat statbuf;

        if(stat(fsname, &statbuf) == 0 && S_ISBLK(statbuf.st_mode) &&
         major(statbuf.st_rdev) == LOOP_MAJOR) {
            /* If /etc/mtab is a link to /proc/mounts then the loop device
            instead of the real device will be listed -- resolve it. */
            fsname = loop_bk(fsname, &loopdev);
        }

        xcmp = (strcmp(fstype, "smbfs") == 0 || strcmp(fstype, "cifs") == 0 ||
                strcmp(fstype, "ncpfs") == 0) ? strcasecmp : strcmp;

        if(xcmp(fsname, dev) == 0 && (strcmp(fspt, vpt->mountpoint) == 0 ||
         strcmp(fspt, real_mpt) == 0)) {
            mounted = 1;
            strncpy(mntpt, fspt, PATH_MAX);
            mntpt[PATH_MAX] = '\0';
            break;
        }
    }

    endmntent(mtab);
    return mounted;
}
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
{
    char *_argv[MAX_PAR + 1], dev[PATH_MAX+1] = {}, mte[BUFSIZ + 1];
    int i, _argc = 0, cstdout = -1, mounted = 0;
    GError *err = NULL;
    struct vol *vpt;
    pid_t pid;
    FILE *fp;

    assert(config_valid(config));
    vpt = &config->volume[vol];
    vol_to_dev(dev, sizeof(dev), vpt);

    // FIXME: I am not overly fond of using mount, but BSD has no /etc/mtab?
    // "WONTFIX" I would say, eh?
    if(config->command[0][MNTCHECK] == NULL) {
        l0g(PMPREFIX "mntcheck not defined in pam_mount.conf\n");
        return -1;
    }

    for(i = 0; config->command[i][MNTCHECK] != NULL; ++i)
        add_to_argv(_argv, &_argc, config->command[i][MNTCHECK], vinfo);

    log_argv(_argv);

    // FIXME: replace by popen() if available on BSD
    spawn_set_sigchld();
    if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
     &pid, NULL, &cstdout, NULL, &err)) {
        spawn_restore_sigchld();
        l0g(PMPREFIX "%s\n", err->message);
        g_error_free(err);
        return -1;
    }

    fp = fdopen(cstdout, "r");
    while(fgets(mte, sizeof(mte), fp) != NULL) {
        // FIXME: Test it.
        int (*xcmp)(const char *, const char *);
        const char *fsname, *fstype, *fspt;

        w4rn(PMPREFIX "mounted filesystem: %s", mte); // MTE includes '\n'
        if(!split_bsd_mount(mte, &fsname, &fspt, &fstype)) {
            mounted = -1;
            break;
        }

        // Use case-insensitive for SMB, etc.
        // FIXME: Is it called "smbfs" under BSD too?
        xcmp = (fstype != NULL && *fstype != '\0' &&
               (strcmp(fstype, "smbfs") == 0 || strcmp(fstype, "cifs") == 0 ||
               strcmp(fstype, "ncpfs") == 0)) ? strcasecmp : strcmp;

        /* FIXME: Does BSD also turn "symlink mountpoints" into
        "real mountpoints"? */
        if(xcmp(fsname, dev) == 0 && strcmp(fspt, vpt->mountpoint) == 0) {
            mounted = 1;
            strncpy(mntpt, fspt, PATH_MAX);
            mntpt[PATH_MAX] = '\0';
            break;
        }
    }

    fclose(fp); // automatically closes cstdout, too
    waitpid(pid, NULL, 0);
    spawn_restore_sigchld();
    return mounted;
}
#else
{
    // FIXME
    l0g(PMPREFIX "check for previous mount not implemented on arch.\n");
    return -1;
}
#endif

static void vol_to_dev(char *match, size_t s, const struct vol *vol) {
    switch(vol->type) {
        case SMBMOUNT:
        case CIFSMOUNT:
            snprintf(match, s, "//%s/%s", vol->server, vol->volume);
            break;

        case NCPMOUNT:
            /* FIXME: volume sanity check in readconfig.c ensures
            optlist_value() will not return NULL for user.
            [JE] So what to fix? */
            snprintf(match, s, "%s/%s", vol->server,
              optlist_value(vol->options, "user"));
            break;

        case NFSMOUNT:
            snprintf(match, s, "%s:%s", vol->server, vol->volume);
            break;

        case CRYPTMOUNT: {
            /* FIXME: ugly hack to support umount.crypt script. I hope that
            util-linux will have native dm_crypt support some day. */
            char *wp = match + sizeof("/dev/mapper/")-1;
            snprintf(match, s, "/dev/mapper/%s", vol->volume);
            while((wp = strchr(wp, '/')) != NULL)
                *wp = '_';
            break;
        }

        default:
            strncpy(match, vol->volume, s-1);
            match[s-1] = '\0';
            break;
    }
    return;
}

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
static int split_bsd_mount(char *wp, const char **fsname, const char **fspt,
 const char **fstype)
{
    /* mntcheck is currently defined as "/bin/mount" in pam_mount.conf so
    a line is like "/dev/ad0s1 on / (ufs, local)". */

    *fsname = wp;
    if((wp = strchr(wp, ' ')) == NULL) return 0; // parse error

    // wp now at " on ..."
    *wp++ = '\0';
    if((wp = strchr(wp, ' ')) == NULL) return 0;

    // wp now at " fspt"
    *fspt = ++wp;
    if((wp = strchr(wp, ' ')) == NULL) return 0;

    // wp now at " (fstype, local?, options)"
    *wp++ = '\0';
    *fstype = ++wp;
    while(isalnum(*wp)) ++wp;
    *wp = '\0';

    return 1;
}
#endif

/* ============================ log_pm_input () ============================ */
static void log_pm_input(const struct config *const config,
 const unsigned int vol)
{
        const struct vol *vpt = &config->volume[vol];
	char options[MAX_PAR + 1];

	w4rn(PMPREFIX "information for mount:\n");
	w4rn(PMPREFIX "----------------------\n");
	w4rn(PMPREFIX "%s\n",
             vpt->globalconf ? "(defined by globalconf)"
                             : "(defined by luserconf)");
	w4rn(PMPREFIX "user:          %s\n", vpt->user);
	w4rn(PMPREFIX "server:        %s\n", vpt->server);
	w4rn(PMPREFIX "volume:        %s\n", vpt->volume);
	w4rn(PMPREFIX "mountpoint:    %s\n", vpt->mountpoint);
	w4rn(PMPREFIX "options:       %s\n", optlist_to_str(options, vpt->options));
	w4rn(PMPREFIX "fs_key_cipher: %s\n", vpt->fs_key_cipher);
	w4rn(PMPREFIX "fs_key_path:   %s\n", vpt->fs_key_path);
	w4rn(PMPREFIX "use_fstab:   %d\n", vpt->use_fstab);
	w4rn(PMPREFIX "----------------------\n");
        return;
}

/* ============================ mkmountpoint () ============================ */
/* POST:   the directory named d exists && volume->created_mntpt = TRUE
 * FN VAL: if error 0 else 1, errors are logged
 */
static int mkmountpoint(struct vol *const volume, const char *const d) {
	int ret = 1;
	struct passwd *passwd_ent;
	char dcopy[PATH_MAX + 1], *parent;

	assert(vol_valid(volume));
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
		if(chown(d, passwd_ent->pw_uid, passwd_ent->pw_gid) != 0) {
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
	free(parent);
	return ret;
}

int do_unmount(const struct config *config, const unsigned int vol,
 struct fmt_ptrn *vinfo, const char *const password, const gboolean mkmntpoint)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
 *         vinfo is a valid struct fmt_ptrn
 *         mkmntpoint is true if mount point should be rmdir'ed
 * POST:   volume is unmounted
 * FN VAL: if error 0 else 1, errors are logged
 */
	GError *err = NULL;
	int i, child_exit, _argc = 0, ret = 1, cstderr = -1;
	pid_t pid = -1;
	const char *_argv[MAX_PAR + 1];
        const struct vol *vpt;
        int type;

	assert(config_valid(config));
	assert(vinfo != NULL);
	assert(password == NULL);	/* password should point to NULL for unmounting */

        vpt = &config->volume[vol];

        if(Debug)
		/*
		 * Often, a process still exists with ~ as its pwd after
		 * logging out.  Running lsof helps debug this.
		 */
		run_lsof(config, vinfo);

        switch(vpt->type) {
            case SMBMOUNT: type = SMBUMOUNT; break;
            case NCPMOUNT: type = NCPUMOUNT; break;
            case FUSEMOUNT: type = FUSEUMOUNT; break;
            default:       type = UMOUNT; break;
        }

        if(config->command[0][type] == NULL)
            l0g(PMPREFIX "{smb,ncp}umount not defined in pam_count.conf\n");

        for(i = 0; config->command[i][type] != NULL; ++i)
            add_to_argv(_argv, &_argc, config->command[i][type], vinfo);

	/* FIXME: ugly hack to support umount.crypt script.  I hope that
	 * util-linux will have native dm_crypt support some day */
	if(vpt->type == CRYPTMOUNT) {
		_argc = 0;
		add_to_argv(_argv, &_argc, "/usr/bin/umount.crypt", vinfo);
		add_to_argv(_argv, &_argc, "%(MNTPT)", vinfo);
	}
	log_argv(_argv);
        if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid,
          NULL, &pid, NULL, NULL, &cstderr, &err)) {
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
        if(mkmntpoint != 0 && vpt->created_mntpt &&
          rmdir(vpt->mountpoint) == -1) /* non-fatal */
		w4rn(PMPREFIX "could not remove %s\n", vpt->mountpoint);
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
        sigemptyset(&ignoresact.sa_mask);
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

static int do_losetup(const struct config *config, const unsigned int vol,
 struct fmt_ptrn *vinfo, const unsigned char *password, size_t password_len)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
 *         vinfo is a valid struct fmt_ptrn
 *         config->volume[vol].options is valid
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
	pid_t pid;
	GError *err = NULL;
	int i, ret = 1, child_exit, _argc = 0, cstdin = -1, cstderr = -1;
	const char *_argv[MAX_PAR + 1];
        const char *cipher, *keybits;
        const struct vol *vpt;

	assert(config_valid(config));
	assert(vinfo != NULL);
	assert(password != NULL);
	/* password_len is unsigned */
	assert(password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

        vpt     = &config->volume[vol];
        cipher  = optlist_value(vpt->options, "encryption");
        keybits = optlist_value(vpt->options, "keybits");

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
	for(i = 0; config->command[i][LOSETUP] != NULL; ++i)
            add_to_argv(_argv, &_argc, config->command[i][LOSETUP], vinfo);

	log_argv(_argv);
        if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid,
          NULL, &pid, &cstdin, NULL, &cstderr, &err)) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
                return 0;
	}

        // note to self: password is decrypted
        if(pipewrite(cstdin, password, password_len) != password_len) {
            l0g(PMPREFIX "error sending password to losetup\n");
            ret = 0;
        }
        CLOSE(cstdin);
        w4rn(PMPREFIX "losetup errors (should be empty):\n");

	log_output(cstderr);
	CLOSE(cstderr);
	w4rn(PMPREFIX "waiting for losetup\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g(PMPREFIX "error waiting for child\n");
		ret = 0;
	} else if(ret > 0) {
		/* pass on through the result from the losetup process */
		ret = !WEXITSTATUS(child_exit);
	}
	return ret;
}

static int do_unlosetup(const struct config *config, struct fmt_ptrn *vinfo) {
/* PRE:    config points to a valid struct config
 *         vinfo is a valid struct fmt_ptrn
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
	pid_t pid;
	GError *err = NULL;
	const char *_argv[MAX_PAR + 1];
	int i, child_exit, _argc = 0;

	assert(config_valid(config));
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
        if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
          &pid, NULL, NULL, NULL, &err)) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		return 0;
	}
	w4rn(PMPREFIX "waiting for losetup delete\n");
	waitpid(pid, &child_exit, 0);
	/* pass on through the result */
	return !WEXITSTATUS(child_exit);
}

static int check_filesystem(const struct config *config, const unsigned int vol,
 struct fmt_ptrn *vinfo, const unsigned char *password, size_t password_len)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
 *         vinfo is a valid struct fmt_ptrn
 * POST:   integrity of volume has been checked
 * FN VAL: if error 0 else 1, errors are logged
 */
#if defined (__linux__)
	pid_t pid;
	GError *err = NULL;
	int i, child_exit, _argc = 0, cstdout = -1, cstderr = -1;
	const char *_argv[MAX_PAR + 1];
        char options[MAX_PAR + 1];
        const char *fsck_target;
        const struct vol *vpt;

	assert(config_valid(config));
	assert(vinfo != NULL);
	assert(password != NULL);
	assert(password_len >= 0
	       && password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

        vpt = &config->volume[vol];
        fsck_target = vpt->volume;

	if(config->command[0][FSCK] == NULL) {
		l0g(PMPREFIX "fsck not defined in pam_mount.conf\n");
		return 0;
	}

        if(optlist_exists(vpt->options, "bind") ||
         optlist_exists(vpt->options, "move") ||
         fstype_nodev(vpt->fstype) != 0)
                return 1;

	if (optlist_exists(vpt->options, "loop")) {
		if(!do_losetup(config, vol, vinfo, password, password_len))
			return 0;
		fsck_target = config->fsckloop;
	} else
		w4rn(PMPREFIX "volume not a loopback (options: %s)\n",
		     optlist_to_str(options, vpt->options));
	/* FIXME: NEW */
	/* FIXME: need to fsck /dev/mapper/whatever... */
	fmt_ptrn_update_kv(vinfo, "FSCKTARGET", fsck_target);
	for (i = 0; config->command[i][FSCK]; i++)
            add_to_argv(_argv, &_argc, config->command[i][FSCK], vinfo);

	log_argv(_argv);
        if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
          &pid, NULL, &cstdout, &cstderr, &err)) {
		l0g(PMPREFIX "%s\n", err->message);
		g_error_free(err);
		return 0;
	}
	log_output(cstdout);	/* stdout and stderr most be logged for fsck */
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn(PMPREFIX "waiting for filesystem check\n");
	waitpid(pid, &child_exit, 0);
	if(optlist_exists(vpt->options, "loop"))
		if (!do_unlosetup(config, vinfo))
			return 0;
	/* pass on through the result -- okay if 0 (no errors)
	 * or 1 (errors corrected) */
	return WEXITSTATUS(child_exit) == 0 || WEXITSTATUS(child_exit) == 1;
#else
	l0g(PMPREFIX "checking filesystem not implemented on arch.\n");
	return 1;
#endif
}

int do_mount(const struct config *config, const unsigned int vol,
 struct fmt_ptrn *vinfo, const char *password, const gboolean mkmntpoint)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
 *         vinfo is a valid struct fmt_ptrn
 *         mkmntpoint is true if mount point should be mkdir'ed
 *         false if mount point was received from pam_mount
 * POST:   volume is mounted
 * FN VAL: if error 0 else 1, errors are logged
 */
	const char *_argv[MAX_PAR + 1];
	char prev_mntpt[PATH_MAX + 1];
	size_t _password_len;
	int i, mount_again = 0;
	unsigned char _password[MAX_PAR + EVP_MAX_BLOCK_LENGTH];
	int _argc = 0, child_exit = 0, cstdin = -1, cstderr = -1;
	pid_t pid = -1;
        struct vol *vpt;

	assert(config_valid(config));
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
                if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
                  set_myuid, NULL, &pid, NULL, NULL, &cstderr, &err)) {
			l0g(PMPREFIX "%s\n", err->message);
			g_error_free(err);
			return 0;
		}
	} else {
		GError *err = NULL;
                char *mount_user;
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
			strncpy(signed_cast(char *, _password), password, MAX_PAR);
			_password[MAX_PAR] = '\0';
			_password_len = strlen(password);
		}
		w4rn(PMPREFIX "about to start building mount command\n");
		/* FIXME: NEW */
		/* FIXME:
		   l0g(PMPREFIX "volume type (%d) is unknown\n", vpt->type);
		   return 0;
		 */
                for(i = 0; config->command[i][vpt->type] != NULL; ++i)
                    add_to_argv(_argv, &_argc, config->command[i][vpt->type], vinfo);

                if(vpt->type == LCLMOUNT &&
                  !check_filesystem(config, vol, vinfo, _password, _password_len))
			l0g(PMPREFIX "error checking filesystem but will continue\n");
		/* send password down pipe to mount process */
                if(vpt->type == SMBMOUNT || vpt->type == CIFSMOUNT)
			setenv("PASSWD_FD", "0", 1);
		log_argv(_argv);
                mount_user = strcmp(vpt->fstype, "fuse") == 0 ? vpt->user : NULL;
                if(!spawn_ap0(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
                  set_myuid, mount_user, &pid, &cstdin, NULL, &cstderr, &err)) {
			l0g(PMPREFIX "%s\n", err->message);
			g_error_free(err);
			return 0;
		}
                if(vpt->type != NFSMOUNT) {
			if(pipewrite(cstdin, _password, _password_len) != _password_len)
				/* FIXME: clean: returns value of exit below */
				l0g(PMPREFIX "error sending password to mount\n");
		}
                close(cstdin);
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
	}

        if(Debug)
            system("df");

        /* pass on through the result from the umount process */
        return !WEXITSTATUS(child_exit);
}

/* ============================ mount_op () ================================ */
/*
 * PRE:    mnt is function to execute mount operations: do_mount or do_unmount
 *         vol > 0
 *         config points to a valid struct config_t
 *         config->volume[vol] is a valid struct vol
 *         password points to a valid string (can be NULL if UNmounting)
 *         mkmntpoint is true if mount point should be created when it does
 *         not already exist
 * POST:   appropriate mount or unmount operations are performed
 * FN VAL: if error 0 else 1, errors are logged
 * NOTE:   * checked by volume_record_sane
 *         ** checked by read_volume()
 */
int mount_op(mount_op_fn_t *mnt, const struct config *config,
 const unsigned int vol, const char *password, const int mkmntpoint)
{
	int fnval;
	struct fmt_ptrn vinfo;
	char options[MAX_PAR + 1], uuid[16], ugid[16];
        const struct vol *vpt;
        struct passwd *pe;

	assert(config_valid(config));

        vpt = &config->volume[vol];

	fmt_ptrn_init(&vinfo);
	fmt_ptrn_update_kv(&vinfo, "MNTPT", vpt->mountpoint);
	fmt_ptrn_update_kv(&vinfo, "FSCKLOOP", config->fsckloop);
        fmt_ptrn_update_kv(&vinfo, "FSTYPE", vpt->fstype);
	fmt_ptrn_update_kv(&vinfo, "VOLUME", vpt->volume);
	fmt_ptrn_update_kv(&vinfo, "SERVER", vpt->server);
	fmt_ptrn_update_kv(&vinfo, "USER", vpt->user);
        if((pe = getpwnam(vpt->user)) == NULL) {
            w4rn(PMPREFIX "getpwnam(\"%s\") failed: %s\n",
             Config.user, strerror(errno));
        } else {
            snprintf(uuid, sizeof(uuid), "%ld", static_cast(long, pe->pw_uid));
            snprintf(ugid, sizeof(ugid), "%ld", static_cast(long, pe->pw_gid));
            fmt_ptrn_update_kv(&vinfo, "USERUID", uuid);
            fmt_ptrn_update_kv(&vinfo, "USERGID", ugid);
        }

	/* FIXME: should others remain undefined if == ""? */
	optlist_to_str(options, vpt->options);
	fmt_ptrn_update_kv(&vinfo, "OPTIONS", options);

	if(Debug)
		log_pm_input(config, vol);

	fnval = mnt(config, vol, &vinfo, password, mkmntpoint);
	fmt_ptrn_close(&vinfo);
	return fnval;
}

/* copied from libHX */
/* noproto */ static
char *HX_chomp(char *s) {
    size_t len = strlen(s);
    char *p = s + len - 1;
    while(p >= s) {
        if(*p != '\n' && *p != '\r')
            break;
        *p-- = '\0';
    }
    return s;
}

static int fstype_nodev(const char *name) {
    /* Returns 1 if the filesystem does not require a block device,
    0 if it does require a block device,
    -1 if we could not find out. */

    char buf[MAX_PAR];
    FILE *fp;

    if((fp = fopen("/proc/filesystems", "r")) == NULL)
        return -1;

    while(fgets(buf, sizeof(buf), fp) != NULL) {
        char *bp = buf;
        HX_chomp(buf);
        while(isalpha(*bp)) ++bp;
        while(isspace(*bp)) ++bp;
        if(strcasecmp(bp, name) == 0) {
            fclose(fp);
            return strncasecmp(buf, "nodev", 5) == 0;
        }
    }

    fclose(fp);
    return -1;
}

static inline const char *loop_bk(const char *filename,
 struct loop_info64 *i)
{
    int fd;
    if((fd = open(filename, O_RDONLY)) < 0)
        return filename;

#ifndef LOOP_GET_STATUS64
#    error -------------------------------------------------------------------
#    error Your userspace kernel headers (/usr/include/linux/) are out of date
#    error This is NOT a pam-mount bug, but one of your distribution.
#    error See www.sourceforge.net/mailarchive/message.php?msg_id=13974728
#    error for details.
#    error -------------------------------------------------------------------
#endif
    if(ioctl(fd, LOOP_GET_STATUS64, i) != 0) {
        close(fd);
        return filename;
    }
    close(fd);
    return signed_cast(char *, i->lo_file_name);
}

//=============================================================================
