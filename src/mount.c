/*=============================================================================
mount.c
  Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
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
#include <libHX.h>
#include <pwd.h>
#include "compiler.h"
#include "crypto.h"
#include "misc.h"
#include "mount.h"
#include "optlist.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"
#include "spawn.h"
#include "xstdlib.h"
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#    include <fstab.h>
#elif defined(__linux__)
#    include <mntent.h>
#    include <sys/ioctl.h>
#    include <fcntl.h>
#    include <linux/loop.h>
#    include <linux/major.h>
#endif
// Functions
static int already_mounted(const struct config * const, const unsigned int, char * const, struct HXbtree *);
static int check_filesystem(const struct config *, const unsigned int, struct HXbtree *, const unsigned char *, size_t);
static int do_losetup(const struct config *, const unsigned int, struct HXbtree *, const unsigned char *, size_t);
static int do_unlosetup(const struct config *, struct HXbtree *);
static int fstype_nodev(const char *);
static void log_output(int);
static void log_pm_input(const struct config * const, const unsigned int);
static int mkmountpoint(struct vol * const, const char * const);
static int pipewrite(int, const void *, size_t);
static void run_lsof(const struct config * const, struct HXbtree *);
static void vol_to_dev(char *, size_t, const struct vol *);

#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
static inline const char *loop_bk(const char *, struct loop_info64 *);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
static int split_bsd_mount(char *, const char **, const char **, const char **);
#endif

//-----------------------------------------------------------------------------
/*  log_output
    @fd:        file descriptor to read from

    Reads all data from @fd and logs it using w4rn(). @fd is uaually connected
    to a pipe to another process's stdout or stderr.
*/
static void log_output(int fd) {
    char buf[BUFSIZ + 1];
    FILE *fp;

    if((fp = fdopen(fd, "r")) == NULL) {
    	w4rn("error opening file: %s\n", strerror(errno));
    	return;
    }

    setvbuf(fp, NULL, _IOLBF, 0);
    while(fgets(buf, sizeof(buf), fp) != NULL)
        w4rn("%s", buf);
    return;
}


/*  run_lsof
    @config:    current configuration
    @vinfo:

    Runs `lsof` on a directory/mountpoint and logs its output, for debugging
    purposes.
*/
static void run_lsof(const struct config *const config,
    struct HXbtree *vinfo)
{
	int i, _argc = 0, cstdout = -1, child_exit;
	const char *_argv[MAX_PAR + 1];
	GError *err = NULL;
	pid_t pid;
	if(config->command[0][CMD_LSOF] == NULL)
		l0g("lsof not defined in pam_mount.conf.xml\n");
	/* FIXME: NEW */
	for(i = 0; config->command[i][CMD_LSOF] != NULL; i++)
		add_to_argv(_argv, &_argc, config->command[i][CMD_LSOF], vinfo);
	log_argv(_argv);

        if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	  &pid, NULL, &cstdout, NULL, &err)) {
		l0g("%s\n", err->message);
		g_error_free(err);
		return;
	}
	w4rn("lsof output (should be empty)...\n");
	log_output(cstdout);
	w4rn("waiting for lsof\n");
	if (waitpid(pid, &child_exit, 0) == -1)
		l0g("error waiting for child: %s\n", strerror(errno));
        spawn_restore_sigchld();
	CLOSE(cstdout);
}


/*  already_mounted
    @config:    current config
    @vol:       volume index into @config->volume[]
    @mntpt:     destination buffer for current mountpoint
    @vinfo:

    Checks if @config->volume[@vol] is already mounted, and if so, writes the
    mountpoint into @mntpt (which must be at least of size %PATH_MAX+1) and
    returns 1. If the volume is not mounted, returns zero and @mntpt is
    cleared. Returns -1 on error.
*/
static int already_mounted(const struct config *const config,
    const unsigned int vol, char *const mntpt, struct HXbtree *vinfo)
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
        l0g("could not open /etc/mtab\n");
        return -1;
    }
    if(realpath(vpt->mountpoint, real_mpt) == NULL) {
        w4rn("can't get realpath of volume %s: %s\n",
             vpt->mountpoint, strerror(errno));
        strncpy(real_mpt, vpt->mountpoint, sizeof_z(real_mpt));
        real_mpt[sizeof_z(real_mpt)] = '\0';
    } else {
        real_mpt[sizeof_z(real_mpt)] = '\0';
        l0g("realpath of volume \"%s\" is \"%s\"\n",
            vpt->mountpoint, real_mpt);
    }

    *mntpt = '\0';
    w4rn("checking to see if %s is already mounted at %s\n",
         dev, vpt->mountpoint);

    while((mtab_record = getmntent(mtab)) != NULL) {
        const char *fsname = mtab_record->mnt_fsname;
        const char *fstype = mtab_record->mnt_type;
        const char *fspt   = mtab_record->mnt_dir;
        int (*xcmp)(const char *, const char *);
        struct loop_info64 loopdev;
        struct stat statbuf;

#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
        if(stat(fsname, &statbuf) == 0 && S_ISBLK(statbuf.st_mode) &&
         major(statbuf.st_rdev) == LOOP_MAJOR)
            /* If /etc/mtab is a link to /proc/mounts then the loop device
            instead of the real device will be listed -- resolve it. */
            fsname = loop_bk(fsname, &loopdev);
#endif

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
    if(config->command[0][CMD_MNTCHECK] == NULL) {
        l0g("mntcheck not defined in pam_mount.conf.xml\n");
        return -1;
    }

    for(i = 0; config->command[i][CMD_MNTCHECK] != NULL; ++i)
        add_to_argv(_argv, &_argc, config->command[i][CMD_MNTCHECK], vinfo);

    log_argv(_argv);

    // FIXME: replace by popen() if available on BSD
    if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
     &pid, NULL, &cstdout, NULL, &err)) {
        l0g("%s\n", err->message);
        g_error_free(err);
        return -1;
    }

    fp = fdopen(cstdout, "r");
    while(fgets(mte, sizeof(mte), fp) != NULL) {
        // FIXME: Test it.
        int (*xcmp)(const char *, const char *);
        const char *fsname, *fstype, *fspt;

        w4rn("mounted filesystem: %s", mte); // @mte includes '\n'
        if(!split_bsd_mount(mte, &fsname, &fspt, &fstype)) {
            mounted = -1;
            break;
        }

        // Use case-insensitive for SMB, etc.
        // FIXME: Is it called "smbfs" under BSD too?
        xcmp = (fstype != NULL &&
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
    if(waitpid(pid, NULL, 0) != 0)
        l0g("error waiting for child: %s\n", strerror(errno));
    spawn_restore_sigchld();
    return mounted;
}
#else
{
    // FIXME
    l0g("check for previous mount not implemented on arch.\n");
    return -1;
}
#endif


/*  vol_to_dev
    @match:
    @s:
    @vol:       volume to analyze

*/
static void vol_to_dev(char *match, size_t s, const struct vol *vol) {
    switch(vol->type) {
        case CMD_SMBMOUNT:
        case CMD_CIFSMOUNT:
            snprintf(match, s, "//%s/%s", vol->server, vol->volume);
            break;

        case CMD_NCPMOUNT:
            /* FIXME: volume sanity check in rdconf2.c ensures
            optlist_value() will not return NULL for user.
            [JE] So what to fix? */
            snprintf(match, s, "%s/%s", vol->server,
              optlist_value(vol->options, "user"));
            break;

        case CMD_NFSMOUNT:
            snprintf(match, s, "%s:%s", vol->server, vol->volume);
            break;

        case CMD_CRYPTMOUNT: {
            /* FIXME: ugly hack to support umount.crypt script. I hope that
            util-linux will have native dm_crypt support some day. */
            char *wp = match + sizeof_z("/dev/mapper/");
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
    /* mntcheck is currently defined as "/bin/mount" in pam_mount.conf.xml so
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

	w4rn("information for mount:\n");
	w4rn("----------------------\n");
	w4rn("%s\n",
             vpt->globalconf ? "(defined by globalconf)"
                             : "(defined by luserconf)");
	w4rn("user:          %s\n", vpt->user);
	w4rn("server:        %s\n", vpt->server);
	w4rn("volume:        %s\n", vpt->volume);
	w4rn("mountpoint:    %s\n", vpt->mountpoint);
	w4rn("options:       %s\n", optlist_to_str(options, vpt->options));
	w4rn("fs_key_cipher: %s\n", vpt->fs_key_cipher);
	w4rn("fs_key_path:   %s\n", vpt->fs_key_path);
	w4rn("use_fstab:   %d\n", vpt->use_fstab);
	w4rn("----------------------\n");
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

	w4rn("creating mount point %s\n", d);
	strncpy(dcopy, d, sizeof_z(dcopy));
	dcopy[sizeof_z(dcopy)] = '\0';
	parent = g_path_get_dirname(dcopy);
	if(!exists(parent) && mkmountpoint(volume, parent) == 0) {
		ret = 0;
		goto _return;
	}
	if((passwd_ent = getpwnam(volume->user)) != NULL) {
		if (mkdir(d, 0700) != 0) {
			l0g("tried to create %s but failed\n",
			    d);
			ret = 0;
			goto _return;
		}
		if(chown(d, passwd_ent->pw_uid, passwd_ent->pw_gid) != 0) {
			l0g("could not chown %s to %s\n",
			    d, volume->user);
			ret = 0;
			goto _return;
		}
	} else {
		l0g("could not determine uid from %s to make %s\n", volume->user, d);
		ret = 0;
		goto _return;
	}
	volume->created_mntpt = TRUE;
      _return:
	free(parent);
	return ret;
}

int do_unmount(const struct config *config, const unsigned int vol,
    struct HXbtree *vinfo, const char *const password, const bool mkmntpoint)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
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
            case CMD_SMBMOUNT:  type = CMD_SMBUMOUNT;  break;
            case CMD_NCPMOUNT:  type = CMD_NCPUMOUNT;  break;
            case CMD_FUSEMOUNT: type = CMD_FUSEUMOUNT; break;
            default:            type = CMD_UMOUNT;     break;
        }

        if(config->command[0][type] == NULL)
            l0g("{smb,ncp}umount not defined in pam_count.conf.xml\n");

        for(i = 0; config->command[i][type] != NULL; ++i)
            add_to_argv(_argv, &_argc, config->command[i][type], vinfo);

	/* FIXME: ugly hack to support umount.crypt script.  I hope that
	 * util-linux will have native dm_crypt support some day */
	if(vpt->type == CMD_CRYPTMOUNT) {
		_argc = 0;
		add_to_argv(_argv, &_argc, "/sbin/umount.crypt", vinfo);
		add_to_argv(_argv, &_argc, "%(MNTPT)", vinfo);
	}
	log_argv(_argv);
        if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid,
          NULL, &pid, NULL, NULL, &cstderr, &err)) {
		l0g("%s\n", err->message);
		g_error_free(err);
		ret = 0;
		goto _return;
	}
	w4rn("umount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("waiting for umount\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g("error waiting for child: %s\n", strerror(errno));
		ret = 0;
		goto _return;
	} else {
		/* pass on through the result from the umount process */
		ret = !WEXITSTATUS(child_exit);
	}
      _return:
        spawn_restore_sigchld();
        if(mkmntpoint != 0 && vpt->created_mntpt &&
          rmdir(vpt->mountpoint) == -1) /* non-fatal */
		w4rn("could not remove %s\n", vpt->mountpoint);
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
    struct HXbtree *vinfo, const unsigned char *password, size_t password_len)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
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

	if(config->command[0][CMD_LOSETUP] == NULL) {
		l0g("losetup not defined in pam_mount.conf.xml\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	/* FIXME: NEW */
	if(cipher != NULL) {
		format_add(vinfo, "CIPHER", cipher);
		if(keybits != NULL)
			format_add(vinfo, "KEYBITS", keybits);
	}
	for(i = 0; config->command[i][CMD_LOSETUP] != NULL; ++i)
            add_to_argv(_argv, &_argc, config->command[i][CMD_LOSETUP], vinfo);

	log_argv(_argv);
        if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid,
          NULL, &pid, &cstdin, NULL, &cstderr, &err)) {
		l0g("%s\n", err->message);
		g_error_free(err);
                return 0;
	}

        // note to self: password is decrypted
        if(pipewrite(cstdin, password, password_len) != password_len) {
            l0g("error sending password to losetup\n");
            ret = 0;
        }
        CLOSE(cstdin);
        w4rn("losetup errors (should be empty):\n");

	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("waiting for losetup\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g("error waiting for child: %s\n", strerror(errno));
		ret = 0;
	} else if(ret > 0) {
		/* pass on through the result from the losetup process */
		ret = !WEXITSTATUS(child_exit);
	}
        spawn_restore_sigchld();
	return ret;
}

static int do_unlosetup(const struct config *config, struct HXbtree *vinfo)
{
/* PRE:    config points to a valid struct config
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
	pid_t pid;
	GError *err = NULL;
	const char *_argv[MAX_PAR + 1];
	int i, child_exit, _argc = 0;

	assert(config_valid(config));
	assert(vinfo != NULL);

	if(config->command[0][CMD_UNLOSETUP] == NULL) {
		l0g("unlosetup not defined in pam_mount.conf.xml\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	/* FIXME: NEW */
	for(i = 0; config->command[i][CMD_UNLOSETUP] != NULL; i++)
		add_to_argv(_argv, &_argc,
			    config->command[i][CMD_UNLOSETUP], vinfo);
	log_argv(_argv);
        if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
          &pid, NULL, NULL, NULL, &err)) {
		l0g("%s\n", err->message);
		g_error_free(err);
		return 0;
	}
	w4rn("waiting for losetup delete\n");
        if(waitpid(pid, &child_exit, 0) != 0)
            l0g("error waiting for child: %s\n", strerror(errno));
        spawn_restore_sigchld();
	/* pass on through the result */
	return !WEXITSTATUS(child_exit);
}

static int check_filesystem(const struct config *config, const unsigned int vol,
    struct HXbtree *vinfo, const unsigned char *password, size_t password_len)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
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

	if(config->command[0][CMD_FSCK] == NULL) {
		l0g("fsck not defined in pam_mount.conf.xml\n");
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
		w4rn("volume not a loopback (options: %s)\n",
		     optlist_to_str(options, vpt->options));
	/* FIXME: NEW */
	/* FIXME: need to fsck /dev/mapper/whatever... */
	format_add(vinfo, "FSCKTARGET", fsck_target);
	for (i = 0; config->command[i][CMD_FSCK]; i++)
            add_to_argv(_argv, &_argc, config->command[i][CMD_FSCK], vinfo);

	log_argv(_argv);
        if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
          &pid, NULL, &cstdout, &cstderr, &err)) {
		l0g("%s\n", err->message);
		g_error_free(err);
		return 0;
	}
	log_output(cstdout);	/* stdout and stderr most be logged for fsck */
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("waiting for filesystem check\n");
        if(waitpid(pid, &child_exit, 0) != 0)
            l0g("error waiting for child: %s\n", strerror(errno));
        spawn_restore_sigchld();
	if(optlist_exists(vpt->options, "loop"))
		if (!do_unlosetup(config, vinfo))
			return 0;
	/* pass on through the result -- okay if 0 (no errors)
	 * or 1 (errors corrected) */
	return WEXITSTATUS(child_exit) == 0 || WEXITSTATUS(child_exit) == 1;
#else
	l0g("checking filesystem not implemented on arch.\n");
	return 1;
#endif
}


/*  do_mount
    @config:    current config
    @vol:       volume index into @config->vol[]
    @vinfo:
    @password:
    @mkmntpoint: whether to create mountpoint if it does not exist

    Returns zero on error, positive non-zero for success.
*/
int do_mount(const struct config *config, const unsigned int vol,
    struct HXbtree *vinfo, const char *password, const bool mkmntpoint)
{
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
			l0g("could not determine if %s is already mounted, failing\n", config->volume[vol].volume);
			return 0;
		} else if(strcmp(prev_mntpt, vpt->mountpoint) == 0) {
			w4rn("%s already seems to be mounted at %s, skipping\n", config->volume[vol].volume, prev_mntpt);
			return 1;
		} else {
			w4rn("%s already mounted elsewhere at %s\n", config->volume[vol].volume, prev_mntpt);
			/* FIXME: ugly hack to support umount.crypt script.  I hope that
			 * util-linux will have native dm_crypt support some day */
                        if(vpt->type != CMD_LCLMOUNT && vpt->type != CMD_CRYPTMOUNT)
				mount_again = 0;
		}
	}
        if(!exists(vpt->mountpoint)) {
		if (mkmntpoint) {
                        if(!mkmountpoint(vpt, vpt->mountpoint))
				return 0;
		} else {
			l0g("mount point %s does not exist (pam_mount not configured to make it)\n", config->volume[vol].mountpoint);
			return 0;
		}
	}
	if (mount_again) {
		GError *err = NULL;
		if(config->command[0][CMD_MNTAGAIN] == NULL) {
			l0g("mntagain not defined in pam_mount.conf.xml\n");
			return 0;
		}
		/* FIXME: NEW */
		format_add(vinfo, "PREVMNTPT", prev_mntpt);
		for(i = 0; config->command[i][CMD_MNTAGAIN] != NULL; i++)
			add_to_argv(_argv, &_argc,
				    config->command[i][CMD_MNTAGAIN], vinfo);
		log_argv(_argv);
                if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
                  set_myuid, NULL, &pid, NULL, NULL, &cstderr, &err)) {
			l0g("%s\n", err->message);
			g_error_free(err);
			return 0;
		}
	} else {
		GError *err = NULL;
                char *mount_user;
		if(config->command[0][vpt->type] == NULL) {
			l0g("proper mount command not defined in pam_mount.conf.xml\n");
			return 0;
		}
		w4rn("checking for encrypted filesystem key configuration\n");
		password = (password != NULL) ? password : "";	/* FIXME: better done elsewhere? */
		if(strlen(vpt->fs_key_cipher) > 0) {
			/* _password is binary data -- no strlen, strcpy, etc! */
			w4rn("decrypting FS key using system auth. token and %s\n", config->volume[vol].fs_key_cipher);
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
		w4rn("about to start building mount command\n");
		/* FIXME: NEW */
		/* FIXME:
		   l0g("volume type (%d) is unknown\n", vpt->type);
		   return 0;
		 */
                for(i = 0; config->command[i][vpt->type] != NULL; ++i)
                    add_to_argv(_argv, &_argc, config->command[i][vpt->type], vinfo);

                if(vpt->type == CMD_LCLMOUNT &&
                  !check_filesystem(config, vol, vinfo, _password, _password_len))
			l0g("error checking filesystem but will continue\n");
		/* send password down pipe to mount process */
                if(vpt->type == CMD_SMBMOUNT || vpt->type == CMD_CIFSMOUNT)
			setenv("PASSWD_FD", "0", 1);
		log_argv(_argv);
                mount_user = strcmp(vpt->fstype, "fuse") == 0 ? vpt->user : NULL;
                if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
                  set_myuid, mount_user, &pid, &cstdin, NULL, &cstderr, &err)) {
			l0g("%s\n", err->message);
			g_error_free(err);
			return 0;
		}
                if(vpt->type != CMD_NFSMOUNT) {
			if(pipewrite(cstdin, _password, _password_len) != _password_len)
				/* FIXME: clean: returns value of exit below */
				l0g("error sending password to mount\n");
		}
                close(cstdin);
	}
	/* Paranoia? */
	memset(_password, 0, sizeof(_password));
	w4rn("mount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("waiting for mount\n");
	if (waitpid(pid, &child_exit, 0) == -1) {
                spawn_restore_sigchld();
		l0g("error waiting for child: %s\n", strerror(errno));
		return 0;
	}

        spawn_restore_sigchld();
        if(Debug)
            system("df");

        /* pass on through the result from the umount process */
        return !WEXITSTATUS(child_exit);
}


/*  mount_op
    @mnt:       function to execute mount operations (do_mount or do_unmount)
    @config:
    @vol:       volume index into @config->volume[]
    @password:  password string (may be %NULL on unmount)
    @mkmntpoint: whether to create mountpoint if it does not exist

    Returns zero on error, positive non-zero for success.
    Note: Checked by volume_record_sane() and read_volume()
*/
int mount_op(mount_op_fn_t *mnt, const struct config *config,
 const unsigned int vol, const char *password, const int mkmntpoint)
{
	int fnval;
	struct HXbtree *vinfo;
	char options[MAX_PAR + 1];
        const struct vol *vpt;
        struct passwd *pe;

	assert(config_valid(config));

        vpt = &config->volume[vol];

	vinfo = HXformat_init();
	format_add(vinfo, "MNTPT",    vpt->mountpoint);
	format_add(vinfo, "FSCKLOOP", config->fsckloop);
        format_add(vinfo, "FSTYPE",   vpt->fstype);
	format_add(vinfo, "VOLUME",   vpt->volume);
	format_add(vinfo, "SERVER",   vpt->server);
	format_add(vinfo, "USER",     vpt->user);
	misc_add_ntdom(vinfo, vpt->user);

        if((pe = getpwnam(vpt->user)) == NULL) {
            w4rn("getpwnam(\"%s\") failed: %s\n",
             Config.user, strerror(errno));
        } else {
		HXformat_add(vinfo, "USERUID", &pe->pw_uid, HXTYPE_LONG);
		HXformat_add(vinfo, "USERGID", &pe->pw_gid, HXTYPE_LONG);
        }

	/* FIXME: should others remain undefined if == ""? */
	optlist_to_str(options, vpt->options);
	format_add(vinfo, "OPTIONS", options);

	if(Debug)
		log_pm_input(config, vol);

	fnval = mnt(config, vol, vinfo, password, mkmntpoint);
	HXformat_free(vinfo);
	return fnval;
}


/*  fstype_nodev
    @name:      fstype to check

    Returns 1 if the filesystem does not require a block device, 0 if it does
    require a block device, -1 if we could not find out.
*/
static int fstype_nodev(const char *name) {
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


#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
/*  loop_bk
    @filename:  block device to query
    @i:         pointer to result storage

    Run the LOOP_GET_STATUS64 ioctl on @filename and store the result in @i.
    Returns the underlying file of the loop device, or @filename if @filename
    does not seem to be a loop device at all.
*/
static inline const char *loop_bk(const char *filename,
 struct loop_info64 *i)
{
    int fd;
    if((fd = open(filename, O_RDONLY)) < 0)
        return filename;

    if(ioctl(fd, LOOP_GET_STATUS64, i) != 0) {
        close(fd);
        return filename;
    }
    close(fd);
    return signed_cast(char *, i->lo_file_name);
}
#endif

//=============================================================================
