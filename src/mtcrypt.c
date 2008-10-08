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
#include <errno.h>
#include <mntent.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/option.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include "misc.h"
#include "pam_mount.h"
#include "spawn.h"

/**
 * @container:		path to the volume (like (bdev) /dev/sda2 or
 * 			(file) /home/user.!@#)
 * @mountpoint:		where to put this
 * @extra_options:	options to pass down
 * @no_update:		do not update mtab
 * @loop_device:	loop device association, if any
 * @crypto_device:	crypto device
 * @blkdev:		true if @container is a block device
 */
struct mount_options {
	const char *container, *mountpoint, *fstype;
	const char *dmcrypt_cipher, *fsk_hash, *fsk_cipher, *fsk_file;
	hxmc_t *fsk_password, *extra_opts, *crypto_device;
	char *loop_device;
	bool blkdev;
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
	ssize_t readret;
	int fd_stdout;
	char *buf;
	pid_t pid;

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return NULL;
	}
	arglist_llog(args);
	if (!spawn_startl(args, &pid, NULL, &fd_stdout)) {
		fprintf(stderr, "spawn_startl readlink: %s\n", strerror(errno));
		free(buf);
		return NULL;
	}

	readret = read(fd_stdout, buf, bufsize);
	if (readret < 0) {
		fprintf(stderr, "read: %s\n", strerror(errno));
		goto out;
	} else if (readret >= bufsize) {
		fprintf(stderr, "Hm, path too long for us\n");
		goto out;
	}

	buf[readret] = '\0';
	close(fd_stdout);
	waitpid(pid, NULL, 0);
	return buf;

 out:
	free(buf);
	close(fd_stdout);
	waitpid(pid, NULL, 0);
	return NULL;
}

static void mtcr_parse_suboptions(struct mount_options *mo, char *copt)
{
	hxmc_t *passthru = HXmc_meminit(NULL, (copt == NULL) ? 0 : strlen(copt));
	bool first = true;
	char *key;

	while ((key = HX_strsep(&copt, ",")) != NULL) {
		char *value = strchr(key, '=');

		if (value != NULL)
			*value++ = '\0';
		if (strcmp(key, "cipher") == 0)
			mo->dmcrypt_cipher = value;
		else if (strcmp(key, "fsk_cipher") == 0)
			mo->fsk_cipher = value;
		else if (strcmp(key, "fsk_hash") == 0)
			mo->fsk_hash = value;
		else if (strcmp(key, "fstype") == 0)
			mo->fstype = value;
		else if (strcmp(key, "keyfile") == 0)
			mo->fsk_file = value;
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

	mo->extra_opts = passthru;
}

static bool mtcr_get_mount_options(int *argc, const char ***argv,
    struct mount_options *opt)
{
	struct stat sb;
	char *o_flag = NULL;
	/* options accepted but ignored for mount(8) interface compat */
	struct HXoption options_table[] = {
		{.sh = 'D', .type = HXTYPE_NONE, .ptr = &Debug,
		 .help = "Enable debugging"},
		{.sh = 'n', .type = HXTYPE_NONE,
		 .help = "(Option ignored)"},
		{.sh = 'o', .type = HXTYPE_STRING, .ptr = &o_flag,
		 .help = "Mount options"},
		{.sh = 'r', .type = HXTYPE_NONE,
		 .help = "(Option ignored)"},
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

	mtcr_parse_suboptions(opt, o_flag);
	if (opt->fsk_file == NULL) {
		fprintf(stderr, "%s: No keyfile specified "
		        "(use -o keyfile=xxx)\n", **argv);
		return false;
	}

	if (opt->dmcrypt_cipher == NULL) {
		fprintf(stderr, "%s: No dmcrypt cipher specified "
		        "(use -o cipher=xxx)\n", **argv);
		return false;
	}

	opt->fsk_password = pmt_get_password();
	return true;
}

/**
 * mtcr_mount
 *
 * Returns positive non-zero for success.
 */
static int mtcr_mount(struct mount_options *opt)
{
	const char *mount_args[7];
	int ret, argk = 0;
	FILE *fp;
	hxmc_t *cd, *key;

	key = ehd_decrypt_key(opt->fsk_file, opt->fsk_hash,
	      opt->fsk_cipher, opt->fsk_password);
	if (key == NULL) {
		fprintf(stderr, "Error while decrypting fskey\n");
		return 0;
	}

	ehd_load(opt->container, &cd, opt->dmcrypt_cipher,
	         reinterpret_cast(const unsigned char *, key),
	         HXmc_length(key));
	if (cd == NULL) {
		fprintf(stderr, "No crypto device assigned\n");
		return 0;
	}

	mount_args[argk++] = "mount";
	mount_args[argk++] = "-n";
	mount_args[argk++] = cd;
	mount_args[argk++] = opt->mountpoint;
	if (opt->extra_opts != NULL) {
		mount_args[argk++] = "-o";
		mount_args[argk++] = opt->extra_opts;
	}
	mount_args[argk] = NULL;

	arglist_llog(mount_args);
	if ((ret = spawn_synchronous(mount_args)) != 0) {
		fprintf(stderr, "mount failed with exit status %d\n",
		        WEXITSTATUS(ret));
		ehd_unload(cd, opt->blkdev);
	} else if ((fp = fopen(mtab_file, "a")) == NULL) {
		fprintf(stderr, "Could not open %s: %s\n",
		        mtab_file, strerror(errno));
	} else {
		struct mntent newmnt;

		newmnt.mnt_fsname = const_cast(char *, opt->container);
		newmnt.mnt_dir    = const_cast(char *, opt->mountpoint);
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
		{.sh = 'D', .type = HXTYPE_UINT, .ptr = &Debug,
		 .help = "Enable debugging"},
		{.sh = 'f', .type = HXTYPE_NONE,
		 .help = "(Option ignored)"},
		{.sh = 'n', .type = HXTYPE_NONE, .ptr = &opt->no_update,
		 .help = "(Option ignored)"},
		{.sh = 'r', .type = HXTYPE_NONE, .ptr = &opt->ro_fallback,
		 .help = "(Option ignored)"},
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
	const char *umount_args[] =
		{"umount", "-i", NULL /* placeholder */, NULL};
	char *final_dir = NULL, *final_fsname = NULL;
	const struct mntent *mnt;
	FILE *fp;
	int ret;

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

	umount_args[2] = opt->object;
	arglist_llog(umount_args);
	if ((ret = spawn_synchronous(umount_args)) != 0) {
		fprintf(stderr, "umount %s failed with status %d\n",
		        opt->object, WEXITSTATUS(ret));
		return 0;
	}

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

	OpenSSL_add_all_ciphers();
	OpenSSL_add_all_digests();

	if (strncmp(HX_basename(*argv), "umount", strlen("umount")) == 0) {
		struct umount_options opt;

		memset(&opt, 0, sizeof(opt));
		if (!mtcr_get_umount_options(&argc, &argv, &opt))
			return EXIT_FAILURE;

		return mtcr_umount(&opt) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		struct mount_options opt = {
			.fsk_hash   = PMT_DFL_FSK_HASH,
			.fsk_cipher = PMT_DFL_FSK_CIPHER,
		};

		if (!mtcr_get_mount_options(&argc, &argv, &opt))
			return EXIT_FAILURE;

		return mtcr_mount(&opt) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	return EXIT_FAILURE;
}
