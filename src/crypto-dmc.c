/*
 *	Copyright © Jan Engelhardt, 2008 - 2009
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#ifdef __linux__
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include "pam_mount.h"

/**
 * dmc_is_luks - check if @path points to a LUKS volume (cf. normal dm-crypt)
 * @path:	path to the crypto container
 * @blkdev:	path is definitely a block device
 */
int dmc_is_luks(const char *path, bool blkdev)
{
	const char *lukscheck_args[] = {
		"cryptsetup", "isLuks", path, NULL,
	};
	char *loop_device;
	int ret;

	if (!blkdev) {
		ret = pmt_loop_setup(path, &loop_device, true);
		if (ret == 0) {
			fprintf(stderr, "No free loop device\n");
			return -1;
		} else if (ret < 0) {
			fprintf(stderr, "%s: could not set up loop device: %s\n",
			        __func__, strerror(-ret));
			return -1;
		}
		lukscheck_args[2] = loop_device;
	}

	if ((ret = HXproc_run_sync(lukscheck_args, HXPROC_VERBOSE)) < 0)
		fprintf(stderr, "run_sync: %s\n", strerror(-ret));
	else if (ret > 0xFFFF)
		/* terminated */
		ret = -1;
	else
		/* exited, and we need success or fail */
		ret = ret == 0;

	if (!blkdev)
		pmt_loop_release(loop_device);
	return ret;
}

static hxmc_t *dmc_crypto_name(const char *s)
{
	hxmc_t *ret;
	char *p;

	ret = HXmc_strinit(s);
	for (p = ret; *p != '\0'; ++p)
		if (!HX_isalnum(*p))
			*p = '_';
	return ret;
}

static bool dmc_run(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	int ret;
	bool is_luks = false;
	const char *start_args[13];
	struct HXproc proc;
	char key_size[HXSIZEOF_Z32];

	ret = dmc_is_luks(mt->lower_device, true);
	if (ret >= 0) {
		int argk = 0;

		is_luks = ret == 1;
		start_args[argk++] = "cryptsetup";
		if (req->readonly)
			start_args[argk++] = "--readonly";
		if (req->fs_cipher != NULL) {
			start_args[argk++] = "-c";
			start_args[argk++] = req->fs_cipher;
		}
		if (is_luks) {
			start_args[argk++] = "luksOpen";
			start_args[argk++] = mt->lower_device;
			start_args[argk++] = mt->crypto_name;
		} else {
			start_args[argk++] = "--key-file=-";
			start_args[argk++] = "-h";
			start_args[argk++] = req->fs_hash;
			start_args[argk++] = "-s";
			snprintf(key_size, sizeof(key_size), "%u",
			         req->key_size * CHAR_BIT);
			start_args[argk++] = key_size;
			start_args[argk++] = "create";
			start_args[argk++] = mt->crypto_name;
			start_args[argk++] = mt->lower_device;
		}
		start_args[argk] = NULL;
		assert(argk < ARRAY_SIZE(start_args));
	} else {
		l0g("cryptsetup isLuks got terminated\n");
		return false;
	}

	if (Debug)
		arglist_llog(start_args);

	memset(&proc, 0, sizeof(proc));
	proc.p_flags = HXPROC_VERBOSE | HXPROC_STDIN;
	if ((ret = HXproc_run_async(start_args, &proc)) <= 0) {
		l0g("Error setting up crypto device: %s\n", strerror(-ret));
		return false;
	}

	/* Ignore return value, we can't do much in case it fails */
	if (write(proc.p_stdin, req->key_data, req->key_size) < 0)
		w4rn("%s: password send erro: %s\n", __func__, strerror(errno));
	close(proc.p_stdin);
	if ((ret = HXproc_wait(&proc)) != 0) {
		w4rn("cryptsetup exited with non-zero status %d\n", ret);
		return false;
	}

	return true;
}

static int dmc_load(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	mt->crypto_name = dmc_crypto_name(mt->container);
	w4rn("Using %s as dmdevice name\n", mt->crypto_name);
	mt->crypto_device = HXmc_strinit("/dev/mapper/");
	HXmc_strcat(&mt->crypto_device, mt->crypto_name);

	return dmc_run(req, mt);
}

static int dmc_unload(const struct ehd_mount *mt)
{
	const char *args[] = {
		"cryptsetup", "remove", NULL, NULL,
	};
	int ret = 1;

	if (mt->crypto_name != NULL)
		args[2] = mt->crypto_name;
	else if (mt->crypto_device != NULL)
		args[2] = mt->crypto_device;
	if (args[2] != NULL) {
		ret = HXproc_run_sync(args, HXPROC_VERBOSE);
		if (ret != 0)
			l0g("Could not unload dm-crypt device \"%s\", "
			    "cryptsetup returned HXproc status %d\n",
			    mt->crypto_device, ret);
		ret = !ret;
	}

	return ret;
}

const struct ehd_crypto_ops ehd_dmcrypt_ops = {
	.load   = dmc_load,
	.unload = dmc_unload,
};

#endif /* __linux__ */
