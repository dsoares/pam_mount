/*
 *	Copyright © Jan Engelhardt, 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <libHX/ctype_helper.h>
#include <libHX/defs.h>
#include <libHX/proc.h>
#include <libHX/string.h>
#include <openssl/evp.h>
#include "pam_mount.h"
#include "config.h"

/**
 * pmt_loop_file_name -
 * @filename:	block device to query
 * @i:		pointer to result storage
 *
 * Run the LOOP_GET_STATUS64 ioctl on @filename and store the result in @i.
 * Returns the underlying file of the loop device, or @filename if @filename
 * does not seem to be a loop device at all.
 */
#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
	/* elsewhere */
#else
const char *pmt_loop_file_name(const char *filename, struct loop_info64 *i)
{
	return filename;
}
#endif

/**
 * pmt_loop_setup - associate file to a loop device
 * @filename:	file to associate
 * @result:	result buffer for path to loop device
 * @ro:		readonly
 *
 * Returns -errno on error, or positive on success,
 * zero when no devices were available.
 */
#if defined(HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME) || \
    defined(HAVE_DEV_VNDVAR_H)
	/* elsewhere */
#else
int pmt_loop_setup(const char *filename, char **result, bool ro)
{
	fprintf(stderr, "%s: no pam_mount support for loop devices "
	        "on this platform\n", __func__);
	return -ENOSYS;
}
#endif

/**
 * pmt_loop_release - release a loop device
 * @device:	loop node
 */
#if defined(HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME) || \
    defined(HAVE_DEV_VNDVAR_H)
	/* elsewhere */
#else
int pmt_loop_release(const char *device)
{
	return -ENOSYS;
}
#endif

/**
 * ehd_is_luks - check if @path points to a LUKS volume (cf. normal dm-crypt)
 * @path:	path to the crypto container
 * @blkdev:	path is definitely a block device
 */
int ehd_is_luks(const char *path, bool blkdev)
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

/**
 * ehd_load_2 - set up dm-crypt device
 */
static bool ehd_load_2(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	int ret;
	bool is_luks = false;
	const char *start_args[11];
	struct HXproc proc;

	ret = ehd_is_luks(mt->lower_device, true);
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

static hxmc_t *ehd_crypto_name(const char *s)
{
	hxmc_t *ret;
	char *p;

	ret = HXmc_strinit(s);
	for (p = ret; *p != '\0'; ++p)
		if (!HX_isalnum(*p))
			*p = '_';
	return ret;
}

/**
 * ehd_mtfree - free data associated with an EHD mount info block
 */
void ehd_mtfree(struct ehd_mount *mt)
{
	free(mt->container);
	HXmc_free(mt->crypto_device);
	HXmc_free(mt->crypto_name);
	if (mt->loop_device != NULL) {
		pmt_loop_release(mt->lower_device);
		free(mt->loop_device);
	}
}

/**
 * ehd_load - set up crypto device for an EHD container
 * @cont_path:		path to the container
 * @crypto_device:	store crypto device here
 * @cipher:		filesystem cipher
 * @hash:		hash function for cryptsetup (default: plain)
 * @fskey:		unencrypted fskey data (not path)
 * @fskey_size:		size of @fskey, in bytes
 * @readonly:		set up loop device as readonly
 */
int ehd_load(const struct ehd_mtreq *req, struct ehd_mount *mt)
{
	struct stat sb;
	int saved_errno, ret;

	memset(mt, 0, sizeof(*mt));
	if (stat(req->container, &sb) < 0) {
		l0g("Could not stat %s: %s\n", req->container, strerror(errno));
		return -errno;
	}

	if ((mt->container = HX_strdup(req->container)) == NULL)
		goto out_err;
	if (S_ISBLK(sb.st_mode)) {
		mt->loop_device  = NULL;
		mt->lower_device = req->container;
	} else {
		/* need losetup since cryptsetup needs block device */
		w4rn("Setting up loop device for file %s\n", req->container);
		ret = pmt_loop_setup(req->container, &mt->loop_device,
		      req->readonly);
		if (ret == 0) {
			l0g("Error: no free loop devices\n");
			goto out_ser;
		} else if (ret < 0) {
			l0g("Error setting up loopback device for %s: %s\n",
			    req->container, strerror(-ret));
			goto out_ser;
		} else {
			w4rn("Using %s\n", mt->loop_device);
			mt->lower_device = mt->loop_device;
		}
	}

	mt->crypto_name = ehd_crypto_name(mt->container);
	w4rn("Using %s as dmdevice name\n", mt->crypto_name);
	mt->crypto_device = HXmc_strinit("/dev/mapper/");
	HXmc_strcat(&mt->crypto_device, mt->crypto_name);

	if (!ehd_load_2(req, mt)) {
		ret = 0;
		goto out_ser;
	}
	return 1;

 out_err:
	ret = -errno;
 out_ser:
	saved_errno = errno;
	ehd_mtfree(mt);
	errno = saved_errno;
	return ret;
}

/**
 * ehd_unload - unload EHD image
 * @crypto_device:	dm-crypt device (/dev/mapper/X)
 * @only_crypto:	do not unload any lower device
 *
 * Determines the underlying device of the crypto target. Unloads the crypto
 * device, and then the loop device if one is used.
 *
 * Using the external cryptsetup program because the cryptsetup C API does
 * not look as easy as the loop one, and does not look shared (i.e. available
 * as a system library) either.
 */
int ehd_unload(struct ehd_mount *mt)
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
			l0g("Could not unload dm-crypt device \"%s\" (%s), "
			    "cryptsetup %s with run_sync status %d\n",
			    mt->crypto_name, mt->crypto_device, ret);
	}

	/* Try to free loop device even if cryptsetup remove failed */
	if (mt->loop_device != NULL)
		ret = pmt_loop_release(mt->loop_device);

	return ret;
}

struct decrypt_info {
	const char *keyfile;
	hxmc_t *password;
	const EVP_CIPHER *cipher;
	const EVP_MD *digest;

	const unsigned char *data;
	unsigned int keysize;

	const unsigned char *salt;
};

static hxmc_t *ehd_decrypt_key2(const struct decrypt_info *info)
{
	unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
	unsigned int out_cumul_len = 0;
	EVP_CIPHER_CTX ctx;
	int out_len = 0;
	hxmc_t *out;

	if (EVP_BytesToKey(info->cipher, info->digest, info->salt,
	    signed_cast(const unsigned char *, info->password),
	    (info->password == NULL) ? 0 : HXmc_length(info->password),
	    1, key, iv) <= 0) {
		l0g("EVP_BytesToKey failed\n");
		return false;
	}

	out = HXmc_meminit(NULL, info->keysize + info->cipher->block_size);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, info->cipher, NULL, key, iv);
	EVP_DecryptUpdate(&ctx, signed_cast(unsigned char *,
		&out[out_len]), &out_len, info->data, info->keysize);
	out_cumul_len += out_len;
	EVP_DecryptFinal_ex(&ctx, signed_cast(unsigned char *,
		&out[out_len]), &out_len);
	out_cumul_len += out_len;
	HXmc_memcat(&out, out, out_cumul_len);
	EVP_CIPHER_CTX_cleanup(&ctx);

	return out;
}

hxmc_t *ehd_decrypt_key(const char *keyfile, const char *digest_name,
    const char *cipher_name, hxmc_t *password)
{
	struct decrypt_info info = {
		.keyfile  = keyfile,
		.digest   = EVP_get_digestbyname(digest_name),
		.cipher   = EVP_get_cipherbyname(cipher_name),
		.password = password,
	};
	hxmc_t *f_ret = NULL;
	unsigned char *buf;
	struct stat sb;
	ssize_t i_ret;
	int fd;

	if (info.digest == NULL) {
		l0g("Unknown digest: %s\n", digest_name);
		return false;
	}
	if (info.cipher == NULL) {
		l0g("Unknown cipher: %s\n", cipher_name);
		return false;
	}
	if ((fd = open(info.keyfile, O_RDONLY)) < 0) {
		l0g("Could not open %s: %s\n", info.keyfile, strerror(errno));
		return false;
	}
	if (fstat(fd, &sb) < 0) {
		l0g("stat: %s\n", strerror(errno));
		goto out;
	}

	if ((buf = xmalloc(sb.st_size)) == NULL)
		return false;

	if ((i_ret = read(fd, buf, sb.st_size)) != sb.st_size) {
		l0g("Incomplete read of %u bytes got %Zd bytes\n",
		    sb.st_size, i_ret);
		goto out2;
	}

	info.salt    = &buf[strlen("Salted__")];
	info.data    = info.salt + PKCS5_SALT_LEN;
	info.keysize = sb.st_size - (info.data - buf);
	f_ret = ehd_decrypt_key2(&info);

 out2:
	free(buf);
 out:
	close(fd);
	return f_ret;
}

static unsigned int __cipher_digest_security(const char *s)
{
	static const char *const blacklist[] = {
		"ecb",
		"rc2", "rc4", "des", "des3",
		"md2", "md4",
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(blacklist); ++i)
		if (strcmp(s, blacklist[i]) == 0)
			return 0;

	return 2;
}

/**
 * cipher_digest_security - returns the secure level of a cipher/digest
 * @s:	name of the cipher or digest specification
 * 	(can either be OpenSSL or cryptsetup name)
 *
 * Returns 0 if it is considered insecure, 1 if I would have a bad feeling
 * using it, and 2 if it is appropriate.
 */
unsigned int cipher_digest_security(const char *s)
{
	char *base, *tmp, *wp;
	unsigned int ret;

	if ((base = xstrdup(s)) == NULL)
		return 2;

	tmp = base;
	while ((wp = HX_strsep(&tmp, ",-.:_")) != NULL)
		if ((ret = __cipher_digest_security(wp)) < 2)
			break;

	free(base);
	return ret;
}

static struct {
	struct sigaction oldact;
	bool echo;
	int fd;
} pmt_pwq_restore;

static void pmt_password_stop(int s)
{
	struct termios ti;

	if (!pmt_pwq_restore.echo)
		return;
	if (tcgetattr(pmt_pwq_restore.fd, &ti) == 0) {
		ti.c_lflag |= ECHO;
		tcsetattr(pmt_pwq_restore.fd, TCSANOW, &ti);
	}
	sigaction(s, &pmt_pwq_restore.oldact, NULL);
	if (s != 0)
		kill(0, s);
}

static hxmc_t *__pmt_get_password(FILE *fp)
{
	hxmc_t *ret = NULL;
	memset(&pmt_pwq_restore, 0, sizeof(pmt_pwq_restore));
	pmt_pwq_restore.fd = fileno(fp);

	if (isatty(fileno(fp))) {
		struct sigaction sa;
		struct termios ti;

		if (tcgetattr(fileno(fp), &ti) == 0) {
			pmt_pwq_restore.echo = ti.c_lflag & ECHO;
			if (pmt_pwq_restore.echo) {
				sigemptyset(&sa.sa_mask);
				sa.sa_handler = pmt_password_stop;
				sa.sa_flags   = SA_RESETHAND;
				sigaction(SIGINT, &sa, NULL);
				ti.c_lflag &= ~ECHO;
				tcsetattr(fileno(fp), TCSANOW, &ti);
				tcflush(fileno(fp), TCIFLUSH);
			}
		}
	}

	if (HX_getl(&ret, fp) != NULL) {
		HX_chomp(ret);
		HXmc_setlen(&ret, strlen(ret));
	}
	pmt_password_stop(0);
	return ret;
}

hxmc_t *pmt_get_password(const char *prompt)
{
	hxmc_t *ret;

	printf("%s", (prompt != NULL) ? prompt : "Password: ");
	fflush(stdout);
	ret = __pmt_get_password(stdin);
	printf("\n");
	return ret;
}
