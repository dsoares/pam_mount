/*
 *	Copyright © Jan Engelhardt, 2008-2011
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <libHX/defs.h>
#include <libHX/init.h>
#include <libHX/string.h>
#include "config.h"
#include "cmt-internal.h"
#include "libcryptmount.h"
#include "pam_mount.h"
#ifdef HAVE_LIBCRYPTO
#	include <openssl/evp.h>
#endif

static pthread_mutex_t ehd_init_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long ehd_use_count;

static void __attribute__((constructor)) ehd_ident(void)
{
	if (getenv("LIBCRYPTMOUNT_IDENTIFY") != NULL)
		fprintf(stderr, "# " PACKAGE_NAME " " PACKAGE_VERSION "\n");
}

EXPORT_SYMBOL int cryptmount_init(void)
{
	int ret;

	pthread_mutex_lock(&ehd_init_lock);
	if (ehd_use_count == 0) {
		ret = HX_init();
		if (ret < 0) {
			pthread_mutex_unlock(&ehd_init_lock);
			return ret;
		}
	}
	++ehd_use_count;
	pthread_mutex_unlock(&ehd_init_lock);
	return 1;
}

EXPORT_SYMBOL void cryptmount_exit(void)
{
	pthread_mutex_lock(&ehd_init_lock);
	if (ehd_use_count == 0)
		fprintf(stderr, "%s: reference count is already zero!\n",
		        __func__);
	else if (--ehd_use_count == 0)
		HX_exit();
	pthread_mutex_unlock(&ehd_init_lock);
}

/**
 * ehd_mtfree - free data associated with an EHD mount info block
 */
EXPORT_SYMBOL void ehd_mountinfo_free(struct ehd_mount_info *mt)
{
	free(mt->container);
	HXmc_free(mt->crypto_device);
	HXmc_free(mt->crypto_name);
	if (mt->loop_device != NULL)
		free(mt->loop_device);
}

/**
 * ehd_load - set up crypto device for an EHD container
 * @req:	parameters for setting up the mount
 * @mt:		EHD mount state
 */
EXPORT_SYMBOL int ehd_load(const struct ehd_mount_request *req,
    struct ehd_mount_info *mt)
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
		ret = ehd_loop_setup(req->container, &mt->loop_device,
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

#ifdef HAVE_LIBCRYPTSETUP
	ret = ehd_dmcrypt_ops.load(req, mt);
#elif defined(HAVE_DEV_CGDVAR_H)
	ret = ehd_cgd_ops.load(req, mt);
#else
	ret = -EOPNOTSUPP;
#endif
	if (ret <= 0)
		goto out_ser;

	return ret;

 out_err:
	ret = -errno;
 out_ser:
	saved_errno = errno;
	ehd_unload(mt);
	ehd_mountinfo_free(mt);
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
EXPORT_SYMBOL int ehd_unload(const struct ehd_mount_info *mt)
{
	int ret, ret2;

#ifdef HAVE_LIBCRYPTSETUP
	ret = ehd_dmcrypt_ops.unload(mt);
#elif defined(HAVE_DEV_CGDVAR_H)
	ret = ehd_cgd_ops.unload(mt);
#else
	ret = -EOPNOTSUPP;
#endif
	/* Try to free loop device even if cryptsetup remove failed */
	if (mt->loop_device != NULL) {
		ret2 = ehd_loop_release(mt->loop_device);
		if (ret > 0)
			ret = ret2;
	}
	return ret;
}

#ifndef HAVE_LIBCRYPTSETUP
EXPORT_SYMBOL int ehd_is_luks(const char *device, bool blkdev)
{
	return -EINVAL;
}
#endif

#ifdef HAVE_LIBCRYPTO
struct decrypt_info {
	const char *password;
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
	    (info->password == NULL) ? 0 : strlen(info->password),
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
	HXmc_setlen(&out, out_cumul_len);
	EVP_CIPHER_CTX_cleanup(&ctx);

	return out;
}

EXPORT_SYMBOL hxmc_t *ehd_decrypt_keyfile(struct ehd_decryptkf_params *par)
{
	struct decrypt_info info = {
		.digest   = EVP_get_digestbyname(par->digest),
		.cipher   = EVP_get_cipherbyname(par->cipher),
		.password = par->password,
	};
	hxmc_t *f_ret = NULL;
	unsigned char *buf;
	struct stat sb;
	ssize_t i_ret;
	int fd;

	if (info.digest == NULL) {
		l0g("Unknown digest: %s\n", par->digest);
		return false;
	}
	if (info.cipher == NULL) {
		l0g("Unknown cipher: %s\n", par->cipher);
		return false;
	}
	if ((fd = open(par->keyfile, O_RDONLY)) < 0) {
		l0g("Could not open %s: %s\n", par->keyfile, strerror(errno));
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
#endif /* HAVE_LIBCRYPTO */

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
			return EHD_SECURITY_SUBPAR;

	return EHD_SECURITY_UNSPEC;
}

/**
 * cipher_digest_security - returns the secure level of a cipher/digest
 * @s:	name of the cipher or digest specification
 * 	(can either be OpenSSL or cryptsetup name)
 *
 * Returns the lowest security class ("weakest element of the chain")
 * of the compound string.
 */
EXPORT_SYMBOL int ehd_cipherdigest_security(const char *s)
{
	char *base, *tmp, *wp;
	unsigned int verdict, ret;

	if (s == NULL)
		return EHD_SECURITY_UNSPEC;
	if ((base = HX_strdup(s)) == NULL)
		return -errno;

	tmp = base;
	verdict = EHD_SECURITY_UNSPEC;
	while ((wp = HX_strsep(&tmp, ",-.:_")) != NULL) {
		ret = __cipher_digest_security(wp);
		if (verdict == EHD_SECURITY_UNSPEC)
			verdict = ret;
		else if (ret < verdict)
			verdict = ret;
	}

	free(base);
	return verdict;
}

static struct {
	struct sigaction oldact;
	bool echo;
	int fd;
} ehd_pwq_restore;

static void ehd_password_stop(int s)
{
	struct termios ti;

	if (!ehd_pwq_restore.echo)
		return;
	if (tcgetattr(ehd_pwq_restore.fd, &ti) == 0) {
		ti.c_lflag |= ECHO;
		tcsetattr(ehd_pwq_restore.fd, TCSANOW, &ti);
	}
	sigaction(s, &ehd_pwq_restore.oldact, NULL);
	if (s != 0)
		kill(0, s);
}

static hxmc_t *__ehd_get_password(FILE *fp)
{
	hxmc_t *ret = NULL;
	memset(&ehd_pwq_restore, 0, sizeof(ehd_pwq_restore));
	ehd_pwq_restore.fd = fileno(fp);

	if (isatty(fileno(fp))) {
		struct sigaction sa;
		struct termios ti;

		if (tcgetattr(fileno(fp), &ti) == 0) {
			ehd_pwq_restore.echo = ti.c_lflag & ECHO;
			if (ehd_pwq_restore.echo) {
				sigemptyset(&sa.sa_mask);
				sa.sa_handler = ehd_password_stop;
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
	ehd_password_stop(0);
	return ret;
}

EXPORT_SYMBOL hxmc_t *ehd_get_password(const char *prompt)
{
	hxmc_t *ret;

	printf("%s", (prompt != NULL) ? prompt : "Password: ");
	fflush(stdout);
	ret = __ehd_get_password(stdin);
	printf("\n");
	return ret;
}
