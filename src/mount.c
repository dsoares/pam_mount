/*
 *	Copyright © Elvis Pfützenreuter, 2000
 *	Copyright © Jan Engelhardt, 2006 - 2008
 *	Copyright © Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <config.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX.h>
#include <pwd.h>
#include "crypto.h"
#include "misc.h"
#include "mount.h"
#include "pam_mount.h"
#include "readconfig.h"
#include "spawn.h"
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#	include <fstab.h>
#elif defined(__linux__)
#	include <mntent.h>
#	include <sys/ioctl.h>
#	include <fcntl.h>
#	include <linux/loop.h>
#	include <linux/major.h>
#endif
#ifndef S_IXUGO
#	define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)
#endif

/* Functions */
static int already_mounted(const struct config * const, const struct vol *, struct HXbtree *);
static int fstype_nodev(const char *);
static inline bool mkmountpoint(struct vol *, const char *);
static int pipewrite(int, const void *, size_t);
static void run_ofl(const struct config * const, struct HXbtree *);
static hxmc_t *vol_to_dev(const struct vol *);

//-----------------------------------------------------------------------------
/**
 * log_output
 * @fd:		file descriptor to read from
 * @cmsg:	conditional message
 *
 * Reads all data from @fd and logs it using w4rn(). @fd is usually connected
 * to a pipe to another process's stdout or stderr. Only if @fd actually has
 * output for us, @cmsg will be printed.
 *
 * @fd will be closed.
 */
static void log_output(int fd, const char *cmsg)
{
	char buf[BUFSIZ + 1];
	FILE *fp;

	if ((fp = fdopen(fd, "r")) == NULL) {
		w4rn("error opening file: %s\n", strerror(errno));
		return;
	}

	setvbuf(fp, NULL, _IOLBF, 0);
	if (fgets(buf, sizeof(buf), fp) != NULL) {
		if (cmsg != NULL)
			w4rn("%s", cmsg);

		do {
			w4rn("%s", buf);
		} while (fgets(buf, sizeof(buf), fp) != NULL);
	}
	fclose(fp);
}

/**
 * run_ofl -
 * @config:	current configuration
 * @vinfo:
 *
 * Runs `ofl` on a directory/mountpoint and logs its output, for debugging
 * purposes.
 */
static void run_ofl(const struct config *const config, struct HXbtree *vinfo)
{
	const char *mntpt;
	struct stat sb;

	mntpt = HXbtree_get(vinfo, "MNTPT");
	if (stat(mntpt, &sb) < 0 && errno == ENOENT)
		return;
	ofl_printf = misc_warn;
	ofl(mntpt, 0);
}

/**
 * already_mounted -
 * @config:	current config
 * @vpt:	volume descriptor
 * @vinfo:
 *
 * Checks if @config->volume[@vol] is already mounted, and returns 1 if this
 * the case, 0 if not and -1 on error.
 */
static int already_mounted(const struct config *const config,
    const struct vol *vpt, struct HXbtree *vinfo)
#if defined(__linux__)
{
	hxmc_t *dev;
	char real_mpt[PATH_MAX+1];
	struct mntent *mtab_record;
	bool mounted = false;
	FILE *mtab;

	if ((dev = vol_to_dev(vpt)) == NULL) {
		l0g("pmt::vol_to_dev: %s\n", strerror(errno));
		return -1;
	}

	if ((mtab = setmntent("/etc/mtab", "r")) == NULL) {
		l0g("could not open /etc/mtab\n");
		HXmc_free(dev);
		return -1;
	}
	if (realpath(vpt->mountpoint, real_mpt) == NULL) {
		w4rn("can't get realpath of volume %s: %s\n",
		     vpt->mountpoint, strerror(errno));
		strncpy(real_mpt, vpt->mountpoint, sizeof_z(real_mpt));
		real_mpt[sizeof_z(real_mpt)] = '\0';
	} else {
		real_mpt[sizeof_z(real_mpt)] = '\0';
		l0g("realpath of volume \"%s\" is \"%s\"\n",
		    vpt->mountpoint, real_mpt);
	}

	w4rn("checking to see if %s is already mounted at %s\n",
	     dev, vpt->mountpoint);

	while ((mtab_record = getmntent(mtab)) != NULL) {
		const char *fsname = mtab_record->mnt_fsname;
		const char *fstype = mtab_record->mnt_type;
		const char *fspt   = mtab_record->mnt_dir;
		int (*xcmp)(const char *, const char *);
		struct loop_info64 loopdev;
		struct stat statbuf;

#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
		if (stat(fsname, &statbuf) == 0 && S_ISBLK(statbuf.st_mode) &&
		    major(statbuf.st_rdev) == LOOP_MAJOR)
			/*
			 * If /etc/mtab is a link to /proc/mounts then the loop
			 * device instead of the real device will be listed --
			 * resolve it.
			 */
			fsname = loop_file_name(fsname, &loopdev);
#endif

		xcmp = (strcmp(fstype, "smbfs") == 0 ||
		        strcmp(fstype, "cifs") == 0 ||
		        strcmp(fstype, "ncpfs") == 0) ? strcasecmp : strcmp;

		if (xcmp(fsname, dev) == 0 &&
		    (strcmp(fspt, vpt->mountpoint) == 0 ||
		    strcmp(fspt, real_mpt) == 0)) {
			mounted = true;
			break;
		}
	}

	endmntent(mtab);
	HXmc_free(dev);
	return mounted;
}
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
{
	hxmc_t *dev;
	struct HXdeque *argv;
	char mte[BUFSIZ + 1];
	int i, cstdout = -1, mounted = 0;
	struct vol *vpt;
	pid_t pid;
	FILE *fp;

	vpt = &config->volume[vol];
	if ((dev = vol_to_dev(vpt)) == NULL) {
		l0g("pmt::vol_to_dev: %s\n", strerror(errno));
		return -1;
	}

	//getmntinfo() or getfsstat()
	while (...) {
		struct statfs *sb;
		/* FIXME: Test it. */
		int (*xcmp)(const char *, const char *);

		/* 
		 * Use case-insensitive for SMB, etc. FIXME: Is it called
		 * "smbfs" under BSD too?
		 */
		xcmp = (sb->f_fstypename != NULL &&
		       (strcmp(sb->f_fstypename, "smbfs") == 0 ||
		       strcmp(sb->f_fstypename, "cifs") == 0 ||
		       strcmp(sb->f_fstypename, "ncpfs") == 0)) ?
		       strcasecmp : strcmp;

		/*
		 * FIXME: Does BSD also turn "symlink mountpoints" into "real
		 * mountpoints"?
		 */
		if (xcmp(sb->f_mntfromname, dev) == 0 &&
		    strcmp(sb->f_mntonname, vpt->mountpoint) == 0) {
			mounted = 1;
			break;
		}
	}

	fclose(fp); /* automatically closes @cstdout */
	if (waitpid(pid, NULL, 0) != 0)
		l0g("error waiting for child: %s\n", strerror(errno));
	spawn_restore_sigchld();
	HXmc_free(dev);
	return mounted;
}
#else
{
	l0g("check for previous mount not implemented on arch.\n");
	return -1;
}
#endif

/**
 * vol_to_dev -
 * @vol:	volume to analyze
 *
 * Turn a volume into the mountspec as accepted by the specific mount program.
 */
static hxmc_t *vol_to_dev(const struct vol *vol)
{
	unsigned int len;
	hxmc_t *ret;
	char *p;

	switch (vol->type) {
	case CMD_SMBMOUNT:
	case CMD_CIFSMOUNT:
		ret = HXmc_strinit("//");
		HXmc_strcat(&ret, vol->server);
		HXmc_strcat(&ret, "/");
		HXmc_strcat(&ret, vol->volume);
		break;

	case CMD_NCPMOUNT:
		ret = HXmc_strinit(vol->server);
		HXmc_strcat(&ret, "/");
		HXmc_strcat(&ret, kvplist_get(&vol->options, "user"));
		break;

	case CMD_NFSMOUNT:
		ret = HXmc_strinit(vol->server);
		HXmc_strcat(&ret, ":");
		HXmc_strcat(&ret, vol->volume);
		break;

	case CMD_CRYPTMOUNT:
		/*
		 * FIXME: ugly hack to support umount.crypt script. I hope that
		 * util-linux will have native dm_crypt support some day.
		 */
		ret = HXmc_strinit("/dev/mapper/");
		len = strlen(ret);
		HXmc_strcat(&ret, vol->volume);
		for (p = ret + len; *p != '\0'; ++p)
			if (*p == '/')
				*p = '_';
		break;

	default:
		ret = HXmc_strinit(vol->volume);
		break;
	}

	return ret;
}

static void log_pm_input(const struct config *const config,
    const struct vol *vpt)
{
	hxmc_t *options;

	options = kvplist_to_str(&vpt->options);
	w4rn("information for mount:\n");
	w4rn("----------------------\n");
	w4rn("(defined by %s)\n", vpt->globalconf ? "globalconf" : "luserconf");
	w4rn("user:          %s\n", znul(vpt->user));
	w4rn("server:        %s\n", znul(vpt->server));
	w4rn("volume:        %s\n", znul(vpt->volume));
	w4rn("mountpoint:    %s\n", vpt->mountpoint);
	w4rn("options:       %s\n", options);
	w4rn("fs_key_cipher: %s\n", znul(vpt->fs_key_cipher));
	w4rn("fs_key_path:   %s\n", znul(vpt->fs_key_path));
	w4rn("use_fstab:     %d\n", vpt->use_fstab);
	w4rn("----------------------\n");
	HXmc_free(options);
}

/**
 * mkmountpoint_real - create mountpoint directory
 * @volume:	volume description
 * @d:		directory
 *
 * If the directory @d does not exist, create it and all its parents if
 * @volume->created_mntpt = true. On success, returns true, otherwise false.
 */
static bool mkmountpoint_real(struct vol *const volume, const char *const d)
{
	bool ret = true;
	struct passwd *passwd_ent;
	char dcopy[PATH_MAX + 1], *parent;

	assert(d != NULL);

	strncpy(dcopy, d, sizeof_z(dcopy));
	dcopy[sizeof_z(dcopy)] = '\0';
	parent = HX_dirname(dcopy);
	if (!pmt_fileop_exists(parent) && mkmountpoint(volume, parent) == 0) {
		ret = false;
		goto out;
	}
	if ((passwd_ent = getpwnam(volume->user)) == NULL) {
		l0g("could not determine uid from %s to make %s\n", volume->user, d);
		ret = false;
		goto out;
	}
	/*
	 * The directory will be created in a restricted mode S_IRWXU here.
	 * When mounted, the root directory of the new vfsmount will override
	 * it, so there is no need to use S_IRWXUGO or S_IRWXU | S_IXUGO here.
	 *
	 * Workaround for CIFS on root_squashed NFS: +S_IXUGO
	 */
	if (mkdir(d, S_IRWXU | S_IXUGO) < 0) {
		ret = false;
		goto out;
	}
	if (chown(d, passwd_ent->pw_uid, passwd_ent->pw_gid) < 0) {
		l0g("could not chown %s to %s\n", d, volume->user);
		ret = false;
		goto out;
	}
	volume->created_mntpt = true;
 out:
	free(parent);
	return ret;
}

/**
 * mkmountpoint_pick - create mountpoint for volume
 * @volume:	volume structure
 * @d:		directory to create
 *
 * Switches to the volume user's identity and see if we can create the
 * mountpoint. This is required for NFS mounts with root_squash enabled
 * (assuming the mountpoint's parent is writable by the user, e.g. if it is
 * inside the user's home directory).
 *
 * If that fails, do as usual (create as root, chown to user).
 */
static bool mkmountpoint_pick(struct vol *volume, const char *d)
{
	struct passwd *pe;
	bool ret;

	if ((pe = getpwnam(volume->user)) == NULL) {
		l0g("getpwuid: %s\n", strerror(errno));
		return false;
	}

	w4rn("creating mount point %s\n", d);
	if (seteuid(pe->pw_uid) == 0)
		if (mkmountpoint_real(volume, d))
			return true;

	seteuid(0);
	ret = mkmountpoint_real(volume, d);
	if (!ret)
		l0g("tried to create %s but failed\n", d);
	return ret;
}

/**
 * mkmountpoint -
 *
 * Wrapper for mkmountpoint_pick(). Switch back to root user after
 * mkmountpoint() operation. This is needed, otherwise the PAM stack will
 * (more or less) spuriously fail with PAM_SYSTEM_ERR.
 */
static inline bool mkmountpoint(struct vol *volume, const char *d)
{
	bool r = mkmountpoint_pick(volume, d);
	seteuid(0);
	return r;
}

/**
 * do_unmount -
 * @config:	current config
 * @vpt:	volume descriptor
 * @vinfo:
 * @password:	always %NULL
 *
 * Returns zero on error, positive non-zero for success.
 */
int do_unmount(const struct config *config, struct vol *vpt,
    struct HXbtree *vinfo, const char *const password)
{
	struct HXdeque *argv;
	int child_exit, ret = 1, cstderr = -1;
	pid_t pid = -1;
	int type;

	assert(vinfo != NULL);
	assert(password == NULL);	/* password should point to NULL for unmounting */

	if (Debug)
		/*
		 * Often, a process still exists with ~ as its pwd after
		 * logging out.  Running lsof helps debug this.
		 */
		run_ofl(config, vinfo);

	switch (vpt->type) {
		case CMD_CRYPTMOUNT:
			type = CMD_CRYPTUMOUNT;
			break;
		case CMD_SMBMOUNT:
			type = CMD_SMBUMOUNT;
			break;
		case CMD_NCPMOUNT:
			type = CMD_NCPUMOUNT;
			break;
		case CMD_FUSEMOUNT:
			type = CMD_FUSEUMOUNT;
			break;
		default:
			type = CMD_UMOUNT;
			break;
	}

	if (config->command[type] == NULL || config->command[type]->first == 0)
		l0g("{smb,ncp}umount not defined in pam_count.conf.xml\n");

	argv = arglist_build(config->command[type], vinfo);
	if (!spawn_start(argv, &pid, NULL, NULL, &cstderr, set_myuid, NULL)) {
		ret = 0;
		goto out;
	}

	log_output(cstderr, "umount errors:\n");
	w4rn("waiting for umount\n");
	if (waitpid(pid, &child_exit, 0) < 0) {
		l0g("error waiting for child: %s\n", strerror(errno));
		ret = 0;
		goto out;
	} else {
		/* pass on through the result from the umount process */
		ret = !WEXITSTATUS(child_exit);
	}
 out:
	spawn_restore_sigchld();
	if (config->mkmntpoint && config->rmdir_mntpt && vpt->created_mntpt)
		if (rmdir(vpt->mountpoint) < 0)
			/* non-fatal, but warn */
			w4rn("could not remove %s\n", vpt->mountpoint);
	return ret;
}

/* INPUT: fd, a valid file descriptor; buf, a buffer of size count
 * SIDE EFFECTS: buf is written to fd
 * OUTPUT: number of bytes written or 0 on error
 * NOTE: SIGPIPE is ignored during this operation to avoid "broken pipe"
 */
static int pipewrite(int fd, const void *buf, size_t count)
{
	struct sigaction ignoresact = {.sa_handler = SIG_IGN}, oldsact;
	int fnval;

	assert(fd >= 0);
	assert(buf != NULL);
	assert(count >= 0);

	/* avoid bomb on command exiting before data written */
	sigemptyset(&ignoresact.sa_mask);
	if (sigaction(SIGPIPE, &ignoresact, &oldsact) < 0) {
		fnval = -1;
		goto out;
	}
	fnval = write(fd, buf, count);
	/* restore old handler */
	if (sigaction(SIGPIPE, &oldsact, NULL) < 0) {
		fnval = -1;
		goto out;
	}
 out:
	return fnval;
}

static int check_filesystem(const struct config *config, const struct vol *vpt,
    struct HXbtree *vinfo)
{
/* PRE:    config points to a valid struct config
 *         config->volume[vol] is a valid struct vol
 * POST:   integrity of volume has been checked
 * FN VAL: if error 0 else 1, errors are logged
 */
#if defined (__linux__)
	pid_t pid;
	int child_exit, cstdout = -1, cstderr = -1;
	const char *fsck_target;
	struct HXdeque *argv;

	assert(vinfo != NULL);

	if (vpt->type == CMD_CRYPTMOUNT)
		/*
		 * Cryptmount involves dm-crypt or LUKS, so using the raw
		 * device as fsck target is meaningless.
		 * So we do _not_ set FSCKTARGET in vinfo at all, and
		 * mount_set_fsck() depends on this behavior.
		 */
		return 0;

	fsck_target = vpt->volume;

	if (config->command[CMD_FSCK]->items == 0) {
		l0g("fsck not defined in pam_mount.conf.xml\n");
		return 0;
	}

	if (kvplist_contains(&vpt->options, "bind") ||
	    kvplist_contains(&vpt->options, "move") ||
	    fstype_nodev(vpt->fstype) != 0)
		return 1;

	format_add(vinfo, "FSCKTARGET", fsck_target);

	argv = arglist_build(config->command[CMD_FSCK], vinfo);
	if (!spawn_start(argv, &pid, NULL, &cstdout, &cstderr, NULL, NULL))
		return 0;

	/* stdout and stderr must be logged for fsck */
	log_output(cstdout, NULL);
	log_output(cstderr, NULL);
	w4rn("waiting for filesystem check\n");
	if (waitpid(pid, &child_exit, 0) < 0)
		l0g("error waiting for child: %s\n", strerror(errno));
	spawn_restore_sigchld();
	/*
	 * pass on through the result -- okay if 0 (no errors) or 1 (errors
	 * corrected)
	 */
	return WEXITSTATUS(child_exit) == 0 || WEXITSTATUS(child_exit) == 1;
#else
	l0g("checking filesystem not implemented on arch.\n");
	return 1;
#endif
}

/**
 * mount_set_fsck - set the FSCK environment variable for mount.crypt
 * @config:	configuration
 * @vol:	current volume
 * @vinfo:	variable substituions
 */
static void mount_set_fsck(const struct config *config,
    const struct vol *vol, struct HXbtree *vinfo)
{
	const struct HXdeque_node *i;
	hxmc_t *string, *current;

	if (vol->type != CMD_CRYPTMOUNT)
		return;

	format_add(vinfo, "FSCKTARGET", "");
	string = HXmc_meminit(NULL, 0);

	for (i = config->command[CMD_FSCK]->first; i != NULL; i = i->next) {
		if (HXformat_aprintf(vinfo, &current, i->ptr) > 0) {
			HXmc_strcat(&string, current);
			HXmc_strcat(&string, " ");
		}
		HXmc_free(current);
	}

	setenv("FSCK", string, true);
	HXmc_free(string);
}

/**
 * do_mount -
 * @config:	current config
 * @vpt:	volume descriptor
 * @vinfo:
 * @password:	login password
 *
 * Returns zero on error, positive non-zero for success.
 */
int do_mount(const struct config *config, struct vol *vpt,
    struct HXbtree *vinfo, const char *password)
{
	const struct HXdeque_node *n;
	struct HXdeque *argv;
	hxmc_t *ll_password = NULL;
	int child_exit = 0, cstdin = -1, cstderr = -1;
	const char *mount_user;
	pid_t pid = -1;
	int ret;

	assert(vinfo != NULL);
	assert(password != NULL);

	ret = already_mounted(config, vpt, vinfo);
	if (ret == -1) {
		l0g("could not determine if %s is already mounted, "
		    "failing\n", vpt->volume);
		return 0;
	} else if (ret == 1) {
		w4rn("%s already seems to be mounted at %s, "
		     "skipping\n", vpt->volume, vpt->mountpoint);
		return 1;
	}
	if (!pmt_fileop_exists(vpt->mountpoint)) {
		if (config->mkmntpoint) {
			if (!mkmountpoint(vpt, vpt->mountpoint))
				return 0;
		} else {
			l0g("mount point %s does not exist (pam_mount not "
			    "configured to make it)\n",
			    vpt->mountpoint);
			return 0;
		}
	}

	if (config->command[vpt->type]->items == 0) {
		l0g("proper mount command not defined in "
		    "pam_mount.conf.xml\n");
		return 0;
	}
	w4rn("checking for encrypted filesystem key configuration\n");

	/* FIXME: better done elsewhere? */
	password = (password != NULL) ? password : "";
	if (vpt->fs_key_cipher != NULL && strlen(vpt->fs_key_cipher) > 0) {
		/* ll_password is binary data */
		w4rn("decrypting FS key using system auth. token and "
		     "%s\n", vpt->fs_key_cipher);
		/*
		 * vpt->fs_key_path contains real filesystem key.
		 */
		if (!decrypted_key(&ll_password,
		    vpt->fs_key_path, vpt->fs_key_cipher, password))
			return 0;
	} else {
		ll_password = HXmc_strinit(password);
	}
	w4rn("about to start building mount command\n");
	/* FIXME: NEW */
	/* FIXME:
	   l0g("volume type (%d) is unknown\n", vpt->type);
	   return 0;
	 */

	if ((argv = HXdeque_init()) == NULL)
		misc_log("malloc: %s\n", strerror(errno));
	if (vpt->uses_ssh)
		for (n = config->command[CMD_FD0SSH]->first;
		     n != NULL; n = n->next)
			arglist_add(argv, n->ptr, vinfo);

	for (n = config->command[vpt->type]->first; n != NULL; n = n->next)
		arglist_add(argv, n->ptr, vinfo);

	if (vpt->type == CMD_LCLMOUNT &&
	    !check_filesystem(config, vpt, vinfo))
		l0g("error checking filesystem but will continue\n");
	/* send password down pipe to mount process */
	if (vpt->type == CMD_SMBMOUNT || vpt->type == CMD_CIFSMOUNT)
		setenv("PASSWD_FD", "0", 1);

	mount_set_fsck(config, vpt, vinfo);
	arglist_log(argv);
	mount_user = vpt->noroot ? vpt->user : NULL;
	if (!spawn_start(argv, &pid, &cstdin, NULL, &cstderr,
	    set_myuid, mount_user)) {
		HXmc_free(ll_password);
		return 0;
	}

	if (vpt->type != CMD_NFSMOUNT)
		if (pipewrite(cstdin, ll_password, HXmc_length(ll_password)) !=
		    HXmc_length(ll_password))
			/* FIXME: clean: returns value of exit below */
			l0g("error sending password to mount\n");
	close(cstdin);

	/* Paranoia? */
	memset(ll_password, 0, HXmc_length(ll_password));
	HXmc_free(ll_password);
	log_output(cstderr, "mount errors:\n");
	w4rn("waiting for mount\n");
	if (waitpid(pid, &child_exit, 0) < 0) {
		spawn_restore_sigchld();
		l0g("error waiting for child: %s\n", strerror(errno));
		return 0;
	}

	spawn_restore_sigchld();
	if (Debug)
		spawn_synchronous((const char *const []){"df", "-Ta", NULL});

	/* pass on through the result from the umount process */
	return !WEXITSTATUS(child_exit);
}

/**
 * mount_op -
 * @mnt:	function to execute mount operations (do_mount or do_unmount)
 * @config:	current configuration
 * @vpt:	volume descriptor
 * @password:	password string (may be %NULL on unmount)
 *
 * Returns zero on error, positive non-zero for success.
 * Note: Checked by volume_record_sane() and read_volume()
 */
int mount_op(mount_op_fn_t *mnt, const struct config *config,
    struct vol *vpt, const char *password)
{
	int fnval;
	struct HXbtree *vinfo;
	struct passwd *pe;
	hxmc_t *options;

	if ((vinfo = HXformat_init()) == NULL)
		return 0;
	format_add(vinfo, "MNTPT",    vpt->mountpoint);
	format_add(vinfo, "FSTYPE",   vpt->fstype);
	format_add(vinfo, "VOLUME",   vpt->volume);
	format_add(vinfo, "SERVER",   vpt->server);
	format_add(vinfo, "USER",     vpt->user);
	misc_add_ntdom(vinfo, vpt->user);

	if ((pe = getpwnam(vpt->user)) == NULL) {
		w4rn("getpwnam(\"%s\") failed: %s\n",
		     Config.user, strerror(errno));
	} else {
		unsigned int uid = pe->pw_uid, gid = pe->pw_gid;
		HXformat_add(vinfo, "USERUID", &uid, HXTYPE_UINT);
		HXformat_add(vinfo, "USERGID", &gid, HXTYPE_UINT);
	}

	/* FIXME: should others remain undefined if == ""? */
	options = kvplist_to_str(&vpt->options);
	format_add(vinfo, "OPTIONS", options);

	if (Debug)
		log_pm_input(config, vpt);

	fnval = (*mnt)(config, vpt, vinfo, password);
	HXmc_free(options);
	HXformat_free(vinfo);
	return fnval;
}

/**
 * fstype_nodev -
 * @name:	fstype to check
 *
 * Returns 1 if the filesystem does not require a block device, 0 if it does
 * require a block device, -1 if we could not find out.
 */
static int fstype_nodev(const char *name) {
	char buf[80];
	FILE *fp;

	if (name == NULL)
		return 0;
	if ((fp = fopen("/proc/filesystems", "r")) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *bp = buf;
		HX_chomp(buf);
		while (isalpha(*bp)) ++bp;
		while (isspace(*bp)) ++bp;
		if (strcasecmp(bp, name) == 0) {
			fclose(fp);
			return strncasecmp(buf, "nodev", 5) == 0;
		}
	}

	fclose(fp);
	return -1;
}

/**
 * umount_final - called when the last session has exited
 *
 * Send signals to processes and then unmount.
 */
void umount_final(struct config *config)
{
	struct vol *vol;

	if (config->sig_hup)
		HXlist_for_each_entry_rev(vol, &config->volume_list, list)
			ofl(vol->mountpoint, SIGHUP);
	if (config->sig_term) {
		usleep(config->sig_wait);
		HXlist_for_each_entry_rev(vol, &config->volume_list, list)
			ofl(vol->mountpoint, SIGTERM);
	}
	if (config->sig_kill) {
		usleep(config->sig_wait);
		HXlist_for_each_entry_rev(vol, &config->volume_list, list)
			ofl(vol->mountpoint, SIGKILL);
	}
	HXlist_for_each_entry_rev(vol, &config->volume_list, list) {
		w4rn("going to unmount\n");
		if (!mount_op(do_unmount, config, vol, NULL))
			l0g("unmount of %s failed\n",
			    vol->volume);
	}
}
