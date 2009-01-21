/*
 *	Copyright © Jan Engelhardt, 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <mntent.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include "pam_mount.h"

/**
 * @container:		path to the volume (like (bdev) /dev/sda2 or
 * 			(file) /home/user.!@#)
 * @mountpoint:		where to put this
 * @extra_options:	options to pass down
 * @no_update:		do not update mtab
 * @loop_device:	loop device association, if any
 * @crypto_device:	crypto device
 * @blkdev:		true if @container is a block device
 * @fsck:		true if fsck should be performed
 */
struct mount_options {
	const char *container, *mountpoint, *fstype;
	const char *dmcrypt_cipher, *dmcrypt_hash;
	const char *fsk_hash, *fsk_cipher, *fsk_file;
	hxmc_t *fsk_password, *extra_opts, *crypto_device;
	char *loop_device;
	unsigned int no_update, readonly;
	int dm_timeout;
	bool blkdev;
	bool fsck;
};

/**
 * @object:		what umount should look for
 * @no_update:		skip updating mtab
 * @ro_fallback:	remount read-only on umount error
 * @is_cont:		@object denotes the container
 * @blkdev:		@container is a block device
 */
struct umount_options {
	const char *object;
	unsigned int no_update, ro_fallback;
	bool is_cont, blkdev;
};

static const char *const mtab_file  = "/etc/mtab";
static const char *const kmtab_file = "/proc/mounts";

static hxmc_t *readlinkf(const char *file)
{
	static const unsigned int bufsize = 256;
	const char *const args[] = {"readlink", "-fn", file, NULL};
	struct HXproc proc;
	ssize_t readret;
	char *buf;
	int ret;

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return NULL;
	}
	arglist_llog(args);
	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE | HXPROC_STDOUT;
	if ((ret = HXproc_run_async(args, &proc)) <= 0) {
		fprintf(stderr, "spawn_startl readlink: %s\n", strerror(-ret));
		free(buf);
		return NULL;
	}

	readret = read(proc.p_stdout, buf, bufsize);
	if (readret < 0) {
		fprintf(stderr, "read: %s\n", strerror(errno));
		goto out;
	} else if (readret >= bufsize) {
		fprintf(stderr, "Hm, path too long for us\n");
		goto out;
	}

	buf[readret] = '\0';
	close(proc.p_stdout);
	HXproc_wait(&proc);
	return buf;

 out:
	free(buf);
	close(proc.p_stdout);
	HXproc_wait(&proc);
	return NULL;
}

static void mtcr_parse_suboptions(const struct HXoptcb *cbi)
{
	struct mount_options *mo = cbi->current->uptr;
	hxmc_t *passthru;
	bool first = true;
	char *copt;
	char *key;

	if ((copt = xstrdup(cbi->data)) == NULL)
		return;
	if ((passthru = HXmc_meminit(NULL, strlen(copt))) == NULL)
		abort();

	while ((key = HX_strsep(&copt, ",")) != NULL) {
		char *value = strchr(key, '=');

		if (value != NULL)
			*value++ = '\0';
		while (HX_isspace(*key))
			++key;
		if (strcmp(key, "cipher") == 0)
			mo->dmcrypt_cipher = value;
		else if (strcmp(key, "fsk_cipher") == 0)
			mo->fsk_cipher = value;
		else if (strcmp(key, "fsk_hash") == 0)
			mo->fsk_hash = value;
		else if (strcmp(key, "dm-timeout") == 0)
			mo->dm_timeout = strtoul(value, NULL, 0);
		else if (strcmp(key, "fstype") == 0)
			mo->fstype = value;
		else if (strcmp(key, "keyfile") == 0)
			mo->fsk_file = value;
		else if (strcmp(key, "ro") == 0)
			mo->readonly = true;
		else if (strcmp(key, "rw") == 0)
			mo->readonly = false;
		else if (strcmp(key, "keysize") == 0)
			/* automatically determined from keyfile size */
			l0g("keysize mount option ignored\n");
		else if (strcmp(key, "fsck") == 0)
			mo->fsck = true;
		else if (strcmp(key, "loop") == 0)
			/* automatically detected anyway */
			l0g("loop mount option ignored\n");
		else if (strcmp(key, "hash") == 0)
			mo->dmcrypt_hash = value;
		else if (strcmp(key, "verbose") == 0)
			Debug = pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR] = true;
		else {
			if (!first)
				HXmc_strcat(&passthru, ",");
			first = false;
			HXmc_strcat(&passthru, key);
			if (value != NULL) {
				HXmc_strcat(&passthru, "=");
				HXmc_strcat(&passthru, value);
			}
		}
	}

	if (*passthru != '\0') {
		if (mo->extra_opts == NULL) {
			mo->extra_opts = passthru;
		} else if (*mo->extra_opts != '\0') {
			HXmc_strcat(&mo->extra_opts, ",");
			HXmc_strcat(&mo->extra_opts, passthru);
			HXmc_free(passthru);
		}
	} else {
		HXmc_free(passthru);
	}
}

static bool mtcr_get_mount_options(int *argc, const char ***argv,
    struct mount_options *opt)
{
	struct stat sb;
	struct HXoption options_table[] = {
		{.sh = 'n', .type = HXTYPE_NONE, .ptr = &opt->no_update,
		 .help = "Do not update /etc/mtab"},
		{.sh = 'o', .type = HXTYPE_STRING, .cb = mtcr_parse_suboptions,
		 .uptr = opt, .help = "Mount options"},
		{.sh = 'r', .type = HXTYPE_NONE, .ptr = &opt->readonly,
		 .help = "Set up devices and mounts as read-only"},
		{.sh = 'v', .type = HXTYPE_NONE, .ptr = &Debug,
		 .help = "Enable debugging"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};

	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) <= 0)
		return false;

	pmtlog_path[PMTLOG_DBG][PMTLOG_STDERR] = Debug;

	if (*argc < 2 || *(*argv)[1] == '\0') {
		fprintf(stderr, "%s: You need to specify the device to mount\n",
		        **argv);
		return false;
	}
	if (*argc < 3 || *(*argv)[2] == '\0') {
		fprintf(stderr, "%s: You need to specify the mountpoint\n",
		        **argv);
		return false;
	}

	opt->container  = readlinkf((*argv)[1]);
	opt->mountpoint = readlinkf((*argv)[2]);

	if (stat(opt->mountpoint, &sb) < 0) {
		fprintf(stderr, "%s: stat %s: %s\n", **argv, opt->mountpoint,
		        strerror(errno));
		return false;
	} else if (!S_ISDIR(sb.st_mode)) {
		fprintf(stderr, "%s: %s is not a directory\n",
		        **argv, opt->mountpoint);
		return false;
	}

	if (stat(opt->container, &sb) < 0) {
		fprintf(stderr, "%s: stat %s: %s\n", **argv, opt->container,
		        strerror(errno));
		return false;
	} else if (S_ISBLK(sb.st_mode)) {
		opt->blkdev = true;
	} else if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "%s: %s must either be a regular file or "
		        "block device\n", **argv, opt->container);
		return false;
	}

	if (opt->fsk_file != NULL) {
		if (opt->fsk_cipher == NULL) {
			fprintf(stderr, "%s: No openssl cipher specified "
			        "(use -o fsk_cipher=xxx)\n", **argv);
			return false;
		} else if (opt->fsk_hash == NULL) {
			fprintf(stderr, "%s: No openssl hash specified "
			        "(use -o fsk_hash=xxx)\n", **argv);
			return false;
		}
	}

	if (!ehd_is_luks(opt->container, opt->blkdev) &&
	    opt->dmcrypt_cipher == NULL) {
		fprintf(stderr, "%s: No dmcrypt cipher specified "
		        "(use -o cipher=xxx)\n", **argv);
		return false;
	}

	if (opt->dmcrypt_hash == NULL)
		opt->dmcrypt_hash = "plain";

	opt->fsk_password = pmt_get_password(NULL);
	return true;
}

/**
 * mtcr_mount
 *
 * Returns positive non-zero for success.
 */
static int mtcr_mount(struct mount_options *opt)
{
	const char *mount_args[9];
	const char *fsck_args[4];
	struct stat sb;
	int ret, argk;
	FILE *fp;
	hxmc_t *cd = NULL, *key;

	if (opt->fsk_file == NULL) {
		/* LUKS derives the key material on its own */
		key = HXmc_meminit(opt->fsk_password,
		      HXmc_length(opt->fsk_password));
		if (key == NULL) {
			fprintf(stderr, "HXmc_dup: %s\n", strerror(errno));
			return 0;
		}
	} else {
		key = ehd_decrypt_key(opt->fsk_file, opt->fsk_hash,
		      opt->fsk_cipher, opt->fsk_password);
		if (key == NULL) {
			fprintf(stderr, "Error while decrypting fskey\n");
			return 0;
		}
	}

	ret = ehd_load(opt->container, &cd, opt->dmcrypt_cipher,
	      opt->dmcrypt_hash, reinterpret_cast(const unsigned char *, key),
	      HXmc_length(key), opt->readonly);
	if (ret < 0) {
		fprintf(stderr, "ehd_load: %s\n", strerror(errno));
		return 0;
	} else if (ret == 0) {
		return 0;
	}
	HXmc_free(key);
	if (cd == NULL) {
		if (Debug)
			fprintf(stderr, "No crypto device assigned\n");
		return 0;
	}

	opt->dm_timeout *= 3;
	while (stat(cd, &sb) < 0 && errno == ENOENT && opt->dm_timeout-- > 0)
		usleep(333333);

	if (opt->fsck) {
		argk = 0;
		fsck_args[argk++] = "fsck";
		fsck_args[argk++] = "-p";
		fsck_args[argk++] = cd;
		fsck_args[argk] = NULL;
		assert(argk < ARRAY_SIZE(fsck_args));

		arglist_llog(fsck_args);
		ret = HXproc_run_sync(fsck_args, HXPROC_VERBOSE);

		/*
		 * Return codes higher than 1 indicate that manual intervention
		 * is required, therefore abort the mount/login.
		 * Lower than 0: internal error (e.g. fork).
		 */
		if (ret != 0 && ret != 1) {
			fprintf(stderr, "Automatic fsck failed, manual "
			        "intervention required, run_sync status %d\n",
			        ret);
			ehd_unload(cd, opt->blkdev);
			return false;
		}
	}

	argk = 0;
	mount_args[argk++] = "mount";
#ifdef __linux__
	mount_args[argk++] = "-n";
#endif
	if (opt->fstype != NULL) {
		mount_args[argk++] = "-t";
		mount_args[argk++] = opt->fstype;
	}
	mount_args[argk++] = cd;
	mount_args[argk++] = opt->mountpoint;
	if (opt->extra_opts != NULL) {
		mount_args[argk++] = "-o";
		mount_args[argk++] = opt->extra_opts;
	}
	mount_args[argk] = NULL;

	assert(argk < ARRAY_SIZE(mount_args));
	arglist_llog(mount_args);
	if ((ret = HXproc_run_sync(mount_args, HXPROC_VERBOSE)) != 0) {
		fprintf(stderr, "mount failed with run_sync status %d\n", ret);
		ehd_unload(cd, opt->blkdev);
	} else if (opt->no_update) {
		/* awesome logic */;
	} else if ((fp = fopen(mtab_file, "a")) == NULL) {
		fprintf(stderr, "Could not open %s: %s\n",
		        mtab_file, strerror(errno));
	} else {
		struct mntent newmnt;

		newmnt.mnt_fsname = const_cast1(char *, opt->container);
		newmnt.mnt_dir    = const_cast1(char *, opt->mountpoint);
		newmnt.mnt_type   = "crypt";
		newmnt.mnt_freq   = newmnt.mnt_passno = 0;
		if (opt->extra_opts == NULL)
			newmnt.mnt_opts = "defaults";
		else
			newmnt.mnt_opts = opt->extra_opts;
		if (addmntent(fp, &newmnt) != 0)
			fprintf(stderr, "Could not add mount entry to %s\n",
			        mtab_file);
		fclose(fp);
	}

	return ret == 0;
}

static bool mtcr_get_umount_options(int *argc, const char ***argv,
    struct umount_options *opt)
{
	struct stat sb;
	struct HXoption options_table[] = {
		{.sh = 'f', .type = HXTYPE_NONE,
		 .help = "(Option ignored)"},
		{.sh = 'n', .type = HXTYPE_NONE, .ptr = &opt->no_update,
		 .help = "Do not update /etc/mtab"},
		{.sh = 'r', .type = HXTYPE_NONE, .ptr = &opt->ro_fallback,
		 .help = "(Option ignored)"},
		{.sh = 'v', .type = HXTYPE_NONE, .ptr = &Debug,
		 .help = "Be verbose - enable debugging"},
		HXOPT_AUTOHELP,
		HXOPT_TABLEEND,
	};

	if (HX_getopt(options_table, argc, argv, HXOPT_USAGEONERR) <= 0)
		return false;

	if (*argc < 2 || *(*argv)[1] == '\0') {
		fprintf(stderr, "%s: You need to specify the container "
		        "or its mountpoint\n", **argv);
		return false;
	}

	opt->object = readlinkf((*argv)[1]);
	if (stat(opt->object, &sb) < 0) {
		/* If it does not exist, it cannot be the container. */
		opt->is_cont = false;
		if (errno != ENOENT) {
			fprintf(stderr, "stat %s: %s\n", opt->object,
			        strerror(errno));
			return false;
		}
	} else {
		/* If it is a directory, it cannot be the container either. */
		if (!S_ISDIR(sb.st_mode))
			opt->is_cont = true;
		if (S_ISBLK(sb.st_mode))
			opt->blkdev = true;
	}

	return true;
}

/**
 * mtcr_umount - unloads the EHD from mountpoint
 *
 * Returns positive non-zero for success.
 */
static int mtcr_umount(struct umount_options *opt)
{
	const char *umount_args[5];
	char *final_dir = NULL, *final_fsname = NULL;
	const struct mntent *mnt;
	FILE *fp;
	int ret, argk = 0;

	if (opt->is_cont) {
		/*
		 * Need to find the directory for it, so that we can then
		 * look for the directory in kmtab and find the crypto device.
		 */

		fp = setmntent(mtab_file, "r");
		if (fp == NULL) {
			fprintf(stderr, "Cannot inspect mtab %s: %s\n",
			        mtab_file, strerror(errno));
			return -ENXIO;
		}

		while ((mnt = getmntent(fp)) != NULL)
			if (strcmp(mnt->mnt_fsname, opt->object) == 0) {
				free(final_dir);
				if ((final_dir = xstrdup(mnt->mnt_dir)) == NULL)
					abort();
			}

		endmntent(fp);
		if (final_dir != NULL)
			opt->object = final_dir;
	}

	fp = setmntent(kmtab_file, "r");
	if (fp == NULL) {
		fprintf(stderr, "Cannot inspect kmtab %s: %s\n",
		        kmtab_file, strerror(errno));
		return -ENXIO;
	}

	while ((mnt = getmntent(fp)) != NULL)
		if (strcmp(mnt->mnt_dir, opt->object) == 0) {
			free(final_fsname);
			if ((final_fsname = xstrdup(mnt->mnt_fsname)) == NULL)
				abort();
		}

	endmntent(fp);
	if (final_fsname == NULL) {
		fprintf(stderr, "%s not found in kmtab %s\n",
		        opt->object, kmtab_file);
	}

	umount_args[argk++] = "umount";
	umount_args[argk++] = "-i";
#ifdef __linux__
	if (opt->no_update)
		umount_args[argk++] = "-n";
#endif
	umount_args[argk++] = opt->object;
	umount_args[argk]   = NULL;

	assert(argk < ARRAY_SIZE(umount_args));
	arglist_llog(umount_args);
	if ((ret = HXproc_run_sync(umount_args, HXPROC_VERBOSE)) != 0)
		fprintf(stderr, "umount %s failed with run_sync status %d\n",
		        opt->object, ret);

	if (final_fsname != NULL)
		ret = ehd_unload(final_fsname, opt->blkdev);

	free(final_fsname);
	free(final_dir);
	return ret;
}

int main(int argc, const char **argv)
{
	Debug = false;
	pmtlog_path[PMTLOG_ERR][PMTLOG_STDERR] = true;
	pmtlog_prefix = HX_basename(*argv);

	setenv("PATH", PMT_DFL_PATH, true);
	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	if (strncmp(HX_basename(*argv), "umount", strlen("umount")) == 0) {
		struct umount_options opt;

		memset(&opt, 0, sizeof(opt));
		if (!mtcr_get_umount_options(&argc, &argv, &opt))
			return EXIT_FAILURE;

		return mtcr_umount(&opt) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		struct mount_options opt;

		memset(&opt, 0, sizeof(opt));
		if (!mtcr_get_mount_options(&argc, &argv, &opt))
			return EXIT_FAILURE;

		return mtcr_mount(&opt) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	return EXIT_FAILURE;
}
