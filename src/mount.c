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
#include <glib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <assert.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <fstab.h>
#elif defined(__linux__)
#include <mntent.h>
/* FIXME: for LOOP_ code below:
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/loop.h>
#include <linux/major.h>
#include <sys/stat.h>
*/
#endif
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#include <openssl/err.h>
#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32	/* some older openssl versions need this */
#endif
#else
#define EVP_MAX_BLOCK_LENGTH 0	/* FIXME: this is ugly, but needed */
#endif				/* HAVE_LIBCRYPTO */
#include <pam_mount.h>
#include <libgen.h>

extern gboolean debug;

#ifdef HAVE_LIBCRYPTO
/* human readable SSL error message */
static void sslerror (const char* msg) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        l0g("pam_mount: %s: %s", msg, ERR_error_string(err, NULL));
    }
}

/* ============================ hash_authtok () ============================ */
/* INPUT: fp, file containing encrypted stream; cipher; authtok, the key 
 *        to unlock stream contained in fs
 * SIDE AFFECTS: hash, hash(authtok); iv, the initialization vector for fp;
 *               errors are logged
 * OUTPUT: if error 0 else 1
 */
static int hash_authtok(FILE * const fp, const EVP_CIPHER * const cipher,
			const char *const authtok,
			unsigned char *const hash, unsigned char *const iv)
{
	const EVP_MD *md;
	unsigned char salt[PKCS5_SALT_LEN];
	char magic[sizeof "Salted__" - 1];

	assert(fp != NULL);	/* FIXME: check if valid, open file */
	assert(cipher != NULL);	/* FIXME: check if cipher is valid OpenSSL cipher */
	assert(authtok != NULL);
	assert(hash != NULL);	/* FIXME: check hash is big enough? */
	assert(iv != NULL);	/* FIXME: check iv is big enough? */

	if ((fread(magic, 1, sizeof "Salted__" - 1, fp) !=
	     sizeof "Salted__" - 1)
	    || (fread(salt, 1, PKCS5_SALT_LEN, fp) != PKCS5_SALT_LEN)) {
		l0g("pam_mount: %s\n",
		    "error reading salt from encrypted filesystem key");
		return 0;
	}
	if (memcmp(magic, "Salted__", sizeof "Salted__" - 1) != 0) {
		l0g("pam_mount: %s\n",
		    "magic string Salted__ not in filesystem key file");
		return 0;
	}
	md = EVP_md5();
	if (EVP_BytesToKey
	    (cipher, md, salt, authtok, strlen(authtok), 1,
	     hash, iv) <= 0) {
		l0g("pam_mount: %s\n", "failed to hash system password");
		return 0;
	}

	return 1;
}
#endif				/* HAVE_LIBCRYPTO */

/* ============================ decrypted_key () =========================== */
/* INPUT: fs_key_path, the path to an encrypted file (efsk); fs_key_cipher, 
 *        the cipher used to encrypt the file; authtok, the key to unlock the 
 *        file at fs_key_path
 * SIDE AFFECTS: pt_fs_key points to the decrypted data from the file at 
 *               fs_key_path (fsk); pt_fs_key_len is the length of pt_fs_key; 
 *               errors are logged
 * OUTPUT: if error 0 else 1
 * NOTE: pt_fs_key must point to a memory block large enough to hold fsk
 *       (MAX_PAR + EVP_MAX_BLOCK_LENGTH -- length of ct_fs_key + one block)
 *       efsk = encrypted filesystem key (stored in filesystem)
 *       fsk = filesystem key (D(efsk))
 *       pt_fs_key will contain binary data; don't use strlen, strcpy, etc.
 *       pt_fs_key may contain trailing garbage; use pt_fs_key_len
 */
static int
decrypted_key(char *const pt_fs_key, size_t * const pt_fs_key_len,
	      const char *const fs_key_path,
	      const char *const fs_key_cipher, const char *const authtok)
{
/* FIXME: this function may need to be broken up and made more readable */
#ifdef HAVE_LIBCRYPTO
	int ret = 1;
	int segment_len;
	unsigned char ct_fs_key[MAX_PAR];	/* encrypted filesystem key. */
	size_t ct_fs_key_len;
	unsigned char hashed_authtok[EVP_MAX_KEY_LENGTH];	/* hash(system authtok) */
	unsigned char iv[EVP_MAX_IV_LENGTH];
	FILE *fs_key_fp;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;

	assert(pt_fs_key != NULL);
	assert(pt_fs_key_len != NULL);
	assert(fs_key_cipher != NULL);	/* fs_key_cipher = D, where D_key(efsk) = fsk */
	assert(fs_key_path != NULL);	/* path to efsk */
	assert(authtok != NULL);	/* should unlock efsk */

	memset(pt_fs_key, 0x00, MAX_PAR + EVP_MAX_BLOCK_LENGTH);
	OpenSSL_add_all_ciphers();
	EVP_CIPHER_CTX_init(&ctx);
	SSL_load_error_strings();
	if (!(fs_key_fp = fopen(fs_key_path, "r"))) {
		l0g("pam_mount: error opening %s\n", fs_key_path);
		ret = 0;
		goto _return_no_close;
	}
	if (!(cipher = EVP_get_cipherbyname(fs_key_cipher))) {
		l0g("pam_mount: error getting cipher \"%s\"\n",
		    fs_key_cipher);
		ret = 0;
		goto _return;
	}
	if (hash_authtok(fs_key_fp, cipher, authtok, hashed_authtok, iv) ==
	    0) {
		ret = 0;
		goto _return;
	}
	if ((ct_fs_key_len = fread(ct_fs_key, 1, MAX_PAR, fs_key_fp)) == 0) {
		l0g("pam_mount: failed to read encrypted filesystem key from %s\n", fs_key_path);
		ret = 0;
		goto _return;
	}
	if (EVP_DecryptInit_ex(&ctx, cipher, NULL, hashed_authtok, iv) ==
	    0) {
		sslerror("failed to initialize decryption code");
		ret = 0;
		goto _return;
	}
	/* assumes plaintexts is always <= ciphertext + EVP_MAX_BLOCK_LEN in length 
	 * OpenSSL's documentation seems to promise this */
	if (EVP_DecryptUpdate
	    (&ctx, pt_fs_key, &segment_len, ct_fs_key,
	     ct_fs_key_len) == 0) {
		sslerror("failed to decrypt key");
		ret = 0;
		goto _return;
	}
	*pt_fs_key_len = segment_len;
	if (EVP_DecryptFinal_ex
	    (&ctx, &pt_fs_key[*pt_fs_key_len], &segment_len) == 0) {
		sslerror("bad pad on end of encrypted file (wrong algorithm or key size?)");
		ret = 0;
		goto _return;
	}
	*pt_fs_key_len += segment_len;
      _return:
	if (fclose(fs_key_fp) != 0) {
		l0g("pam_mount: error closing file pointer\n");
		ret = 0;
	}
      _return_no_close:
	if (EVP_CIPHER_CTX_cleanup(&ctx) == 0) {
		sslerror("error cleaning up cipher context");
		ret = 0;
	}

	ERR_free_strings();
	/* pt_fs_key_len is unsigned */
	assert(ret == 0
	       || *pt_fs_key_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	return ret;
#else
	l0g("pam_mount: %s\n",
	    "encrypted filesystem key not supported: no openssl");
	return 0;
#endif				/* HAVE_LIBCRYPTO */
}

/* ============================ log_output () ============================== */
/* INPUT: fd, a valid file descriptor
 * SIDE AFFECTS: contents of fd are logged, usually fd is connected by a 
 *               pipe to another process's stdout or stderr
 */
static void log_output(int fd)
{
	FILE *fp;
	char buf[BUFSIZ + 1];
	/* FIXME: check fdopen's retval */
	if ((fp = fdopen(fd, "r")) == NULL) {
		w4rn("pam_mount: error opening file: %s\n",
		     strerror(errno));
		return;
	}
	while (fgets(buf, BUFSIZ + 1, fp))
		w4rn("pam_mount: %s\n", buf);
}

/* ============================ run_lsof () ================================ */
/*
 * NOTE: this fn simply runs lsof on a directory and logs its output for
 * debugging purposes
 */
static void run_lsof(const struct config_t *const config,
		     fmt_ptrn_t * vinfo)
{
	int i, _argc = 0, cstdout = -1, child_exit;
	char *_argv[MAX_PAR + 1];
	GError *err = NULL;
	pid_t pid;
	if (!config->command[0][LSOF])
		l0g("pam_mount: lsof not defined in pam_mount.conf\n");
	/* FIXME: NEW */
	for (i = 0; config->command[i][LSOF]; i++)
		add_to_argv(_argv, &_argc, config->command[i][LSOF],
			    vinfo);
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	     &pid, NULL, &cstdout, NULL, &err) == FALSE) {
		l0g("pam_mount: %s\n", err->message);
		g_error_free(err);
		return;
	}
	w4rn("pam_mount: lsof output (should be empty)...\n");
	log_output(cstdout);
	w4rn("pam_mount: %s\n", "waiting for lsof");
	if (waitpid(pid, &child_exit, 0) == -1)
		l0g("pam_mount: error waiting for child\n");
	CLOSE(cstdout);
}

/* ============================ already_mounted () ========================= */
/*
 * PRE:    config->volume[vol].type is a mount type (LCLMOUNT, SMBMOUNT, ...)
 *         sizeof(mntpt) >= PATH_MAX + 1
 * POST:   mntpt contains:
 *           config->volume[vol].mountpoint if config->volume[vol].volume is
 *             already mounted there
 *           some other path if config->volume[vol].volume is mounted elsewhere
 *           undefined if config->volume[vol].volume is not mounted
 * FN VAL: 1 if config->volume[vol].volume is mounted, 0 if not, -1 on error
 *         errors are logged
 */
static int already_mounted(const struct config_t *const config,
			   const unsigned int vol, char *const mntpt)
{
	char match[PATH_MAX + 1];
	int mounted = 0;
#if defined(__linux__)
	FILE *mtab;
	struct mntent *mtab_record;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	int fds[2];
	pid_t pid;
#endif

	assert(config_t_valid(config));

	memset(match, 0x00, sizeof(match));
	if (config->volume[vol].type == SMBMOUNT
	    || config->volume[vol].type == CIFSMOUNT) {
		strcpy(match, "//");
		strncat(match, config->volume[vol].server,
			PATH_MAX - strlen(match));
		strncat(match, "/", PATH_MAX - strlen(match));
		strncat(match, config->volume[vol].volume,
			PATH_MAX - strlen(match));
	} else if (config->volume[vol].type == NCPMOUNT) {
		strncpy(match, config->volume[vol].server,
			PATH_MAX - strlen(match));
		strncat(match, "/", PATH_MAX - strlen(match));
		/* FIXME: volume sanity check in readconfig.c ensures optlist_value() will not return NULL for user */
		strncat(match,
			optlist_value(config->volume[vol].options, "user"),
			PATH_MAX - strlen(match));
	} else if (config->volume[vol].type == NFSMOUNT) {
		strncpy(match, config->volume[vol].server,
			PATH_MAX - strlen(match));
		strncat(match, ":", PATH_MAX - strlen(match));
		strncat(match, config->volume[vol].volume,
			PATH_MAX - strlen(match));
		/* FIXME: ugly hack to support umount.crypt script.  I hope that
		 * util-linux will have native dm_crypt support some day */
	} else if (config->volume[vol].type == CRYPTMOUNT) {
		int i;
		char escaped_vol[PATH_MAX + 1];
		strncpy(match, "/dev/mapper/", PATH_MAX - strlen(match));
		/* isn't there a function to do this in libc or glib? */
		for (i = 0; config->volume[vol].volume && i < PATH_MAX;
		     i++) {
			if (config->volume[vol].volume[i] == '/')
				escaped_vol[i] = '_';
			else
				escaped_vol[i] =
				    config->volume[vol].volume[i];
		}
		strncat(match, escaped_vol, PATH_MAX - strlen(match));
	} else {
		strncpy(match, config->volume[vol].volume, PATH_MAX);
	}
#if defined(__linux__)
	if (!(mtab = fopen("/etc/mtab", "r"))) {
		l0g("pam_mount: %s\n", "could not open /etc/mtab");
		return -1;
	}
	w4rn("pam_mount: checking to see if %s is already mounted at %s\n",
	     match, config->volume[vol].mountpoint);
	while ((mtab_record = getmntent(mtab)) != NULL) {
               char const *mnt_fsname = mtab_record->mnt_fsname;
               struct stat statbuf;
		/* FIXME: need to figure out where LOOP_GET_STATUS64 is from
               if (stat(mnt_fsname, &statbuf) == 0 &&
                    S_ISBLK(statbuf.st_mode) &&
                    major(statbuf.st_rdev) == LOOP_MAJOR) {
		*/
			/* if /etc/mtab is a link to /proc/mounts then the loop
			 * device instead of the real device will be listed --
			 * resolve it.
			 */
		/*
                       int fd = open(mnt_fsname, O_RDONLY);
                       if (fd != -1) {
                               struct loop_info64 loopinfo64;
                               if (ioctl(fd, LOOP_GET_STATUS64, &loopinfo64) == 0)
                                       mnt_fsname = loopinfo64.lo_file_name;
                               close(fd);
                       }
               }
		*/
		/* FIXME: okay to always ignore case (needed for NCP)? */
		if (!strcasecmp(mnt_fsname, match)) {
			strncpy(mntpt, mtab_record->mnt_dir, PATH_MAX);
			mntpt[PATH_MAX] = 0x00;
			mounted = 1;
			if (!strcmp(mtab_record->mnt_dir,
				    config->volume[vol].mountpoint)) {
				strncpy(mntpt, mtab_record->mnt_dir,
					PATH_MAX);
				mntpt[PATH_MAX] = 0x00;
				break;
			}
		}
	}
	fclose(mtab);
	return mounted;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	{
		FILE *fp;
		GError *err = NULL;
		int i, _argc = 0, cstdout = -1;
		char *_argv[MAX_PAR + 1], dev[BUFSIZ + 1];
		/*
		 * FIXME: I'm not overly fond of using mount, but BSD has no
		 * /etc/mtab?
		 */
		if (!config->command[0][MNTCHECK]) {
			l0g("pam_mount: mntcheck not defined in pam_mount.conf\n");
			return -1;
		}
		/* FIXME: NEW */
		for (i = 0; config->command[i][MNTCHECK]; i++)
			add_to_argv(_argv, &_argc,
				    config->command[i][MNTCHECK], vinfo);
		log_argv(_argv);
		if (g_spawn_async_with_pipes
		    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL,
		     NULL, &pid, NULL, &cstdout, NULL, &err) == FALSE) {
			l0g("pam_mount: %s\n", err->message);
			g_error_free(err);
			return -1;
		}
		fp = fdopen(cstdout, "r");
		while (fgets(dev, BUFSIZ, fp)) {
			/*
			 * FIXME: A bit ugly but
			 * works.
			 */
			char *mp, *trash;
			w4rn("pam_mount: mounted filesystem: %s", dev);	/* dev includes '\n' */
			trash = strchr(dev, ' ');
			if (!trash) {
				mounted = -1;	/* parse err */
				break;
			}
			*trash = 0x00;
			mp = strchr(trash + 1, ' ');
			if (!mp++) {
				mounted = -1;	/* parse err */
				break;
			}
			trash = strchr(mp, ' ');
			if (!trash) {
				mounted = -1;	/* parse err */
				break;
			}
			*trash = 0x00;
			/* FIXME: okay to always ignore case (needed for NCP)? */
			if (!strcasecmp(dev, match)) {
				strncpy(mntpt, mp, PATH_MAX);
				mntpt[PATH_MAX] = 0x00;
				mounted = 1;
				if (!strcmp(mp,
					    config->volume[vol].
					    mountpoint)) {
					strncpy(mntpt, mp, PATH_MAX);
					mntpt[PATH_MAX] = 0x00;
					mounted = 1;
					break;
				}
			}
		}
		return mounted;
	}
#else
	/* FIXME */
	l0g("pam_mount: %s\n",
	    "check for previous mount not implemented on arch.");
	return ERROR;
#endif
}

/* ============================ log_pm_input () ============================ */
static void log_pm_input(const struct config_t *const config,
			 const unsigned int vol)
{
	char options[MAX_PAR + 1];
	w4rn("pam_mount: %s\n", "information for mount:");
	w4rn("pam_mount: %s\n", "--------");
	w4rn("pam_mount: %s\n",
	     config->volume[vol].
	     globalconf == TRUE ? "(defined by globalconf)" :
	     "(defined by luserconf)");
	w4rn("pam_mount: user:          %s\n", config->volume[vol].user);
	w4rn("pam_mount: server:        %s\n", config->volume[vol].server);
	w4rn("pam_mount: volume:        %s\n", config->volume[vol].volume);
	w4rn("pam_mount: mountpoint:    %s\n",
	     config->volume[vol].mountpoint);
	w4rn("pam_mount: options:       %s\n",
	     optlist_to_str(options, config->volume[vol].options));
	w4rn("pam_mount: fs_key_cipher: %s\n",
	     config->volume[vol].fs_key_cipher);
	w4rn("pam_mount: fs_key_path:   %s\n",
	     config->volume[vol].fs_key_path);
	w4rn("pam_mount: use_fstab:   %d\n",
	     config->volume[vol].use_fstab);
	w4rn("pam_mount: %s\n", "--------");
}

/* ============================ mkmountpoint () ============================ */
/* POST:   the directory named d exists && volume->created_mntpt = TRUE
 * FN VAL: if error 0 else 1, errors are logged
 */
static int mkmountpoint(vol_t * const volume, const char *const d)
{
	int ret = 1;
	struct passwd *passwd_ent;
	char dcopy[PATH_MAX + 1], *parent;

	assert(vol_t_valid(volume));
	assert(d != NULL);

	w4rn("pam_mount: creating mount point %s\n", d);
	strncpy(dcopy, d, PATH_MAX);
	dcopy[PATH_MAX] = (char) 0x00;
	parent = g_dirname(dcopy);
	if (exists(parent) == 0 && mkmountpoint(volume, parent) == 0) {
		ret = 0;
		goto _return;
	}
	if ((passwd_ent = getpwnam(volume->user))) {
		if (mkdir(d, 0700) != 0) {
			l0g("pam_mount: tried to create %s but failed\n",
			    d);
			ret = 0;
			goto _return;
		}
		if (chown(d, passwd_ent->pw_uid, passwd_ent->pw_gid)
		    != 0) {
			l0g("pam_mount: could not chown %s to %s\n",
			    d, volume->user);
			ret = 0;
			goto _return;
		}
	} else {
		l0g("pam_mount: could not determine uid from %s to make %s\n", volume->user, d);
		ret = 0;
		goto _return;
	}
	volume->created_mntpt = TRUE;
      _return:
	g_free(parent);
	return ret;
}

/* ============================ do_unmount () ============================== */
int
do_unmount(struct config_t *config, const unsigned int vol,
	   fmt_ptrn_t * vinfo, const char *const password,
	   const gboolean mkmntpoint)
/* PRE:    config points to a valid struct config_t*
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

	assert(config_t_valid(config));
	assert(vinfo != NULL);
	assert(password == NULL);	/* password should point to NULL for unmounting */

	if (debug == TRUE)
		/*
		 * Often, a process still exists with ~ as its pwd after
		 * logging out.  Running lsof helps debug this.
		 */
		run_lsof(config, vinfo);
	/* FIXME: NEW */
	for (i = 0; config->command[i][UMOUNT]; i++)
		add_to_argv(_argv, &_argc, config->command[i][UMOUNT],
			    vinfo);
	/* FIXME: ugly hack to support umount.crypt script.  I hope that
	 * util-linux will have native dm_crypt support some day */
	if (config->volume[vol].type == CRYPTMOUNT) {
		_argc = 0;
		add_to_argv(_argv, &_argc, "/usr/bin/umount.crypt", vinfo);
		add_to_argv(_argv, &_argc, "%(MNTPT)", vinfo);
	}
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, setrootid, NULL,
	     &pid, NULL, NULL, &cstderr, &err) == FALSE) {
		l0g("pam_mount: %s\n", err->message);
		g_error_free(err);
		ret = 0;
		goto _return;
	}
	w4rn("pam_mount: umount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("pam_mount: %s\n", "waiting for umount");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g("pam_mount: error waiting for child\n");
		ret = 0;
		goto _return;
	} else {
		/* pass on through the result from the umount process */
		ret = !WEXITSTATUS(child_exit);
	}
      _return:
	if (mkmntpoint != 0 && config->volume[vol].created_mntpt == TRUE) {
		if (rmdir(config->volume[vol].mountpoint) == -1)	/* non-fatal */
			w4rn("pam_mount: could not remove %s\n",
			     config->volume[vol].mountpoint);
	}
	return ret;
}

/* ============================ pipewrite () =============================== */ 
/* INPUT: fd, a valid file descriptor; buf, a buffer of size count
 * SIDE AFFECTS: buf is written to fd
 * OUTPUT: number of bytes written or 0 on error
 * NOTE: SIGPIPE is ignored during this operation to avoid "broken pipe"
 */
int pipewrite(int fd, const void *buf, size_t count)
{
	int fnval;
	struct sigaction ignoresact = {
		.sa_handler = SIG_IGN
	}, oldsact;

	assert(fd >= 0);
	assert(buf != NULL);
	assert(count >= 0);

	/* avoid bomb on command exiting before data written */
	if (sigaction(SIGPIPE, &ignoresact, &oldsact) < 0) {
		fnval = -1;
		goto _return;
	}
	fnval = write(fd, buf, count);
	/* restore old handler */
	if (sigaction(SIGPIPE, &oldsact, NULL) < 0) {
		fnval = -1;
		goto _return;
	}
_return:
	return fnval;
}

/* ============================ do_losetup () ============================== */
int
do_losetup(struct config_t *config, const unsigned int vol,
	   fmt_ptrn_t * vinfo, const unsigned char *password,
	   size_t password_len)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         vinfo is a valid struct fmt_ptrn_t
 *         config->volume[vol].options is valid
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	pid_t pid;
	GError *err = NULL;
	int i, ret = 1, child_exit, _argc = 0, cstdin = -1, cstderr = -1;
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

	if (!config->command[0][LOSETUP]) {
		l0g("pam_mount: losetup not defined in pam_mount.conf\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	/* FIXME: NEW */
	if (cipher) {
		fmt_ptrn_update_kv(vinfo, "CIPHER", cipher);
		if (keybits)
			fmt_ptrn_update_kv(vinfo, "KEYBITS", keybits);
	}
	for (i = 0; config->command[i][LOSETUP]; i++) {
		add_to_argv(_argv, &_argc,
			    config->command[i][LOSETUP], vinfo);
	}
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, setrootid, NULL,
	     &pid, NULL, NULL, &cstderr, &err) == FALSE) {
		l0g("pam_mount: %s\n", err->message);
		g_error_free(err);
		ret = 0;
		goto _return;
	}
	w4rn("pam_mount: umount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("pam_mount: %s\n", "waiting for umount");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g("pam_mount: error waiting for child\n");
		ret = 0;
		goto _return;
	} else {
		/* pass on through the result from the umount process */
		ret = !WEXITSTATUS(child_exit);
	}
      _return:
	return ret;
}

/* ============================ do_unlosetup () ============================ */
int do_unlosetup(struct config_t *config, fmt_ptrn_t * vinfo)
/* PRE:    config points to a valid struct config_t*
 *         vinfo is a valid struct fmt_ptrn_t
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	pid_t pid;
	GError *err = NULL;
	char *_argv[MAX_PAR + 1];
	int i, child_exit, _argc = 0;

	assert(config_t_valid(config));
	assert(vinfo != NULL);

	if (!config->command[0][UNLOSETUP]) {
		l0g("pam_mount: unlosetup not defined in pam_mount.conf\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	/* FIXME: NEW */
	for (i = 0; config->command[i][UNLOSETUP]; i++)
		add_to_argv(_argv, &_argc,
			    config->command[i][UNLOSETUP], vinfo);
	log_argv(_argv);
	if (g_spawn_async_with_pipes
	    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL,
	     &pid, NULL, NULL, NULL, &err) == FALSE) {
		l0g("pam_mount: %s\n", err->message);
		g_error_free(err);
		return 0;
	}
	w4rn("pam_mount: %s\n", "waiting for losetup delete");
	waitpid(pid, &child_exit, 0);
	/* pass on through the result */
	return (!WEXITSTATUS(child_exit));
}

/* ============================ check_filesystem () ======================== */
static int
check_filesystem(struct config_t *config, const unsigned int vol,
		 fmt_ptrn_t * vinfo, const unsigned char *password,
		 size_t password_len)
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
	assert(0 <= password_len
	       && password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	if (!config->command[0][FSCK]) {
		l0g("pam_mount: fsck not defined in pam_mount.conf\n");
		return 0;
	}
	if (optlist_exists(config->volume[vol].options, "loop")) {
		if (!do_losetup
		    (config, vol, vinfo, password, password_len))
			return 0;
		fsck_target = config->fsckloop;
	} else
		w4rn("pam_mount: volume not a loopback (options: %s)\n",
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
		l0g("pam_mount: %s\n", err->message);
		g_error_free(err);
		return 0;
	}
	log_output(cstdout);	/* stdout and stderr most be logged for fsck */
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("pam_mount: %s\n", "waiting for filesystem check");
	waitpid(pid, &child_exit, 0);
	if (optlist_exists(config->volume[vol].options, "loop"))
		if (!do_unlosetup(config, vinfo))
			return 0;
	/* pass on through the result -- okay if 0 (no errors) 
	 * or 1 (errors corrected) */
	return (WEXITSTATUS(child_exit) == 0
		|| WEXITSTATUS(child_exit) == 1);
#else
	l0g("pam_mount: %s\n",
	    "checking filesystem not implemented on arch.");
	return 1;
#endif
}

/* ============================ do_mount () ================================ */
int
do_mount(struct config_t *config, const unsigned int vol,
	 fmt_ptrn_t * vinfo, const char *password,
	 const gboolean mkmntpoint)
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

	assert(config_t_valid(config));
	assert(vinfo);
	assert(password);

	/* FIXME: This is a little ugly, especially check for != LCLMOUNT */
	if ((mount_again = already_mounted(config, vol, prev_mntpt))) {
		if (mount_again == -1) {
			l0g("pam_mount: could not determine if %s is already mounted, failing\n", config->volume[vol].volume);
			return 0;
		} else
		    if (strcmp
			(prev_mntpt,
			 config->volume[vol].mountpoint) == 0) {
			w4rn("pam_mount: %s already seems to be mounted at %s, skipping\n", config->volume[vol].volume, prev_mntpt);
			return 1;
		} else {
			w4rn("pam_mount: %s already mounted elsewhere at %s\n", config->volume[vol].volume, prev_mntpt);
			/* FIXME: ugly hack to support umount.crypt script.  I hope that
			 * util-linux will have native dm_crypt support some day */
			if (config->volume[vol].type != LCLMOUNT
			    && config->volume[vol].type != CRYPTMOUNT)
				mount_again = 0;
		}
	}
	if (!exists(config->volume[vol].mountpoint)) {
		if (mkmntpoint) {
			if (!mkmountpoint
			    (&config->volume[vol],
			     config->volume[vol].mountpoint))
				return 0;
		} else {
			l0g("pam_mount: mount point %s does not exist (pam_mount not configured to make it)\n", config->volume[vol].mountpoint);
			return 0;
		}
	}
	if (mount_again) {
		GError *err = NULL;
		if (!config->command[0][MNTAGAIN]) {
			l0g("pam_mount: mntagain not defined in pam_mount.conf\n");
			return 0;
		}
#if defined(__linux__)
		/* FIXME: NEW */
		fmt_ptrn_update_kv(vinfo, "PREVMNTPT", prev_mntpt);
		for (i = 0; config->command[i][MNTAGAIN]; i++)
			add_to_argv(_argv, &_argc,
				    config->command[i][MNTAGAIN], vinfo);
		log_argv(_argv);
		if (g_spawn_async_with_pipes
		    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
		     setrootid, NULL, &pid, NULL, NULL, &cstderr,
		     &err) == FALSE) {
			l0g("pam_mount: %s\n", err->message);
			g_error_free(err);
			return 0;
		}
#else
		/* FIXME */
		l0g("pam_mount: %s\n",
		    "multiple mounts of same volume not implemented on arch.");
		return 0;
#endif
	} else {
		GError *err = NULL;
		if (!config->command[0][config->volume[vol].type]) {
			l0g("pam_mount: proper mount command not defined in pam_mount.conf\n");
			return 0;
		}
		w4rn("pam_mount: %s\n",
		     "checking for encrypted filesystem key configuration");
		password = password ? password : "";	/* FIXME: better done elsewhere? */
		if (strlen(config->volume[vol].fs_key_cipher)) {
			/* _password is binary data -- no strlen, strcpy, etc! */
			w4rn("pam_mount: decrypting FS key using system auth. token and %s\n", config->volume[vol].fs_key_cipher);
			/*
			 * config->volume[vol].fs_key_path contains real filesystem
			 * key.
			 */
			if (!decrypted_key
			    (_password, &_password_len,
			     config->volume[vol].fs_key_path,
			     config->volume[vol].fs_key_cipher, password))
				return 0;
		} else {
			/* _password is an ASCII string in this case -- we'll treat its
			 * MAX_PAR + EVP_MAX_BLOCK_LENGTH size as the standard string 
			 * MAX_PAR + 1 in this case */
			strncpy(_password, password, MAX_PAR);
			_password[MAX_PAR] = 0x00;
			_password_len = strlen(password);
		}
		w4rn("pam_mount: %s\n",
		     "about to start building mount command");
		/* FIXME: NEW */
		/* FIXME:
		   l0g("pam_mount: %s\n",
		   "config->volume[vol].type is unknown");
		   return 0;
		 */
		for (i = 0; config->command[i][config->volume[vol].type];
		     i++)
			add_to_argv(_argv, &_argc,
				    config->command[i][config->volume[vol].
						       type], vinfo);
		log_argv(_argv);
		if (config->volume[vol].type == LCLMOUNT
		    && !check_filesystem(config, vol, vinfo, _password,
					 _password_len))
			l0g("pam_mount: %s\n",
			    "error checking filesystem but will continue");
		/* send password down pipe to mount process */
		if (config->volume[vol].type == SMBMOUNT
		    || config->volume[vol].type == CIFSMOUNT)
			setenv("PASSWD_FD", "0", 1);
		if (g_spawn_async_with_pipes
		    (NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
		     setrootid, NULL, &pid, &cstdin, NULL, &cstderr,
		     &err) == FALSE) {
			l0g("pam_mount: %s\n", err->message);
			g_error_free(err);
			return 0;
		}
		if (config->volume[vol].type != NFSMOUNT) {
			if (pipewrite(cstdin, _password, _password_len) !=
			    _password_len)
				/* FIXME: clean: returns value of exit below */
				l0g("pam_mount: error sending password to mount\n");
			CLOSE(cstdin);
		}

	}
_return:
	/* Paranoia? */
	memset(_password, 0x00, MAX_PAR + EVP_MAX_BLOCK_LENGTH);
	w4rn("pam_mount: mount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("pam_mount: %s\n", "waiting for mount");
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g("pam_mount: error waiting for child\n");
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
int mount_op(int (*mnt)
	      (struct config_t * config, const unsigned int vol,
	       fmt_ptrn_t * vinfo, const char *password,
	       const int mkmntpoint), struct config_t *config,
	     const unsigned int vol, const char *password,
	     const int mkmntpoint)
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
	if (strlen(options))
		fmt_ptrn_update_kv(&vinfo, "OPTIONS", options);

	if (debug)
		log_pm_input(config, vol);

	fnval = mnt(config, vol, &vinfo, password, mkmntpoint);
	fmt_ptrn_close(&vinfo);
      _return:
	return fnval;
}
