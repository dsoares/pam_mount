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
#endif
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32	/* some older openssl versions need this */
#endif
#else
#define EVP_MAX_BLOCK_LENGTH 0  /* FIXME: this is ugly, but needed */
#endif				/* HAVE_LIBCRYPTO */
#include <pam_mount.h>
#include <libgen.h>

extern int debug;

#ifdef HAVE_LIBCRYPTO
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
	unsigned char salt[PKCS5_SALT_LEN];
	char magic[sizeof "Salted__" - 1];

	assert(fp);		/* FIXME: check if valid, open file */
	assert(cipher);		/* FIXME: check if cipher is valid OpenSSL cipher */
	assert(authtok);
	assert(hash);		/* FIXME: check hash is big enough? */
	assert(iv);		/* FIXME: check iv is big enough? */

	if ((fread(magic, 1, sizeof "Salted__" - 1, fp) !=
	     sizeof "Salted__" - 1)
	    || (fread(salt, 1, PKCS5_SALT_LEN, fp) != PKCS5_SALT_LEN)) {
		l0g("pam_mount: %s\n",
		    "error reading salt from encrypted filesystem key");
		return 0;
	}
	if (memcmp(magic, "Salted__", sizeof "Salted__" - 1)) {
		l0g("pam_mount: %s\n",
		    "magic string Salted__ not in filesystem key file");
		return 0;
	}
	if (!EVP_BytesToKey
	    (cipher, EVP_md5(), salt, authtok, strlen(authtok), 1,
	     hash, iv)) {
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
decrypted_key(char *const pt_fs_key, int *const pt_fs_key_len,
	      const char *const fs_key_path,
	      const char *const fs_key_cipher, const char *const authtok)
{
/* FIXME: this function may need to be broken up and made more readable */
#ifdef HAVE_LIBCRYPTO
	int segment_len;
	unsigned char ct_fs_key[MAX_PAR];	/* encrypted filesystem key. */
	int ct_fs_key_len;
	unsigned char hashed_authtok[EVP_MAX_KEY_LENGTH];	/* hash(system authtok) */
	unsigned char iv[EVP_MAX_IV_LENGTH];
	FILE *fs_key_fp;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;

	assert(pt_fs_key);
	assert(pt_fs_key_len);
	assert(fs_key_cipher);	/* fs_key_cipher = D, where D_key(efsk) = fsk */
	assert(fs_key_path);	/* path to efsk */
	assert(authtok);	/* should unlock efsk */

	memset(pt_fs_key, 0x00, MAX_PAR + EVP_MAX_BLOCK_LENGTH);
	OpenSSL_add_all_ciphers();
	if (!(cipher = EVP_get_cipherbyname(fs_key_cipher))) {
		l0g("pam_mount: error getting cipher \"%s\"\n",
		    fs_key_cipher);
		return 0;
	}
	if ((fs_key_fp = fopen(fs_key_path, "r")) <= 0) {
		l0g("pam_mount: error opening %s\n", fs_key_path);
		return 0;
	}
	if (!hash_authtok(fs_key_fp, cipher, authtok, hashed_authtok, iv))
		return 0;
	if ((ct_fs_key_len = fread(ct_fs_key, 1, MAX_PAR, fs_key_fp)) <= 0) {
		l0g("pam_mount: failed to read encrypted filesystem key from %s\n", fs_key_path);
		return 0;
	}
	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_DecryptInit_ex(&ctx, cipher, NULL, hashed_authtok, iv)) {
		l0g("pam_mount: %s\n",
		    "failed to initialize decryption code");
		return 0;
	}
	/* assumes plaintexts is always <= ciphertext + EVP_MAX_BLOCK_LEN in length 
	 * OpenSSL's documentation seems to promise this */
	if (!EVP_DecryptUpdate
	    (&ctx, pt_fs_key, &segment_len, ct_fs_key, ct_fs_key_len)) {
		l0g("pam_mount: %s\n", "failed to decrypt key");
		return 0;
	}
	*pt_fs_key_len = segment_len;
	if (!EVP_DecryptFinal_ex
	    (&ctx, &pt_fs_key[*pt_fs_key_len], &segment_len)) {
		l0g("pam_mount: %s\n",
		    "bad pad on end of encrypted file (wrong algorithm or key size?)");
		return 0;
	}
	*pt_fs_key_len += segment_len;
	EVP_CIPHER_CTX_cleanup(&ctx);
	fclose(fs_key_fp);

	assert(0 <= *pt_fs_key_len
	       && *pt_fs_key_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	return 1;
#else
	l0g("pam_mount: %s\n",
	    "encrypted filesystem key not supported: no openssl");
	return 0;
#endif				/* HAVE_LIBCRYPTO */
}

/* ============================ add_to_argv () ============================= */
/* POST: arg has been added to end of argv, which is NULL * terminated
 *       argc++
 * NOTE: this function exits on an error as an error means a buffer
 *       overflow would otherwise have occured
 */
static void add_to_argv(char *argv[], int *const argc, char *const arg)
{
	assert(argv);
	/* need room for one more + terminating NULL for execv */
	assert(argc && 0 <= *argc && *argc <= MAX_PAR - 1);
	assert(arg);

	if (*argc == MAX_PAR) {
		l0g("pam_mount: %s\n",
		    "too many arguments to mount command");
		exit(EXIT_FAILURE);
	}
	argv[(*argc)++] = arg;
	argv[*argc] = 0x00;
}

/* ============================ log_argv () ================================ */
void log_argv(char *const argv[])
/* PRE:  argv[0...n] point to valid strings != NULL
 *       argv[n + 1] is NULL
 * POST: argv[0...n] is logged in a nice manner
 */
{
	/* FIXME: UGLY! */
	int i;
	char str[MAX_PAR + 1];
	if (!debug)
		return;
	strncpy(str, argv[0], MAX_PAR - 1);	/* -1 for ' ' */
	strcat(str, " ");
	str[MAX_PAR] = 0x00;
	for (i = 1; argv[i] && strlen(str) < MAX_PAR - 1; i++) {
		strncat(str, argv[i], MAX_PAR - strlen(str) - 1);
		strcat(str, " ");
		str[MAX_PAR] = 0x00;
		if (strlen(str) >= MAX_PAR)	/* Should never be greater */
			break;
	}
	w4rn("pam_mount: command: %s\n", str);
}

/* ============================ procopen () ================================ */
/* INPUT: path, a program to execute; argv, a null-terminated array of 
 *        argument strings; do_setuid, whether to setuid(0) or not
 * SIDE AFFECTS: cstdin; cstdout; cstderr; errors are logged
 * OUTPUT: if error -1 else PID of child process
 */
int procopen(const char *const path, char *const argv[],
	     const int do_setuid, int *const cstdin, int *const cstdout,
	     int *const cstderr)
{
	int _stdin[2], _stdout[2], _stderr[2];
	pid_t pid = -1;

	assert(path);
	assert(argv);

	if (cstdin)
		if (pipe(_stdin) == -1) {
			l0g("pam_mount: creating pipe failed: %s\n",
			    strerror(errno));
			return -1;
		}
	if (cstdout)
		if (pipe(_stdout) == -1) {
			l0g("pam_mount: creating pipe failed: %s\n",
			    strerror(errno));
			return -1;
		}
	if (cstderr)
		if (pipe(_stderr) == -1) {
			l0g("pam_mount: creating pipe failed: %s\n",
			    strerror(errno));
			return -1;
		}
	if ((pid = fork()) < 0) {
		l0g("pam_mount: fork failed\n");
		return -1;
	} else if (!pid) {	/* child */
		if (cstdin) {
			CLOSE(_stdin[1]);
			if (dup2(_stdin[0], STDIN_FILENO) == -1) {
				l0g("pam_mount: %s\n",
				    "error setting up pipe: %s",
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (cstdout) {
			CLOSE(_stdout[0]);
			if (dup2(_stdout[1], STDOUT_FILENO) == -1) {
				l0g("pam_mount: %s\n",
				    "error setting up pipe: %s",
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (cstderr) {
			CLOSE(_stderr[0]);
			if (dup2(_stderr[1], STDERR_FILENO) == -1) {
				l0g("pam_mount: %s\n",
				    "error setting up pipe: %s",
				    strerror(errno));
				exit(EXIT_FAILURE);
			}
		}
		if (do_setuid)
			/*
			 * setuid 0 since GNU/Linux mount balks at euid of 0, 
			 * uid != 0. I think this is safe because volume 
			 * and mount point must be owned by user if mount 
			 * is defined in ~/.pam_mount.
			 */
			if (setuid(0) == -1)
				w4rn("pam_mount: %s\n",
				     "error setting uid to 0");
		log_argv(argv);
		execv(path, argv);
		l0g("pam_mount: error running %s: %s\n", path,
		    strerror(errno));
		exit(EXIT_FAILURE);
	} else {		/* parent */
		if (cstdin) {
			CLOSE(_stdin[0])
			    * cstdin = _stdin[1];
		}
		if (cstdout) {
			CLOSE(_stdout[1])
			    * cstdout = _stdout[0];
		}
		if (cstderr) {
			CLOSE(_stderr[1])
			    * cstderr = _stderr[0];
		}
	}
	return pid;
}

/* ============================ log_output () ============================== */
/* INPUT: fd, a valid file descriptor
 * SIDE AFFECTS: contents of fd are logged, usually fd is connected by a 
 *               pipe to another process's stdout or stderr
 */
void log_output(int fd)
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
static void run_lsof(const struct config_t *const config, const int vol)
{
	int _argc = 0, cstdout = -1, child_exit;
	char *_argv[MAX_PAR + 1];
	pid_t pid;
	if (!config->command[0][LSOF])
		l0g("pam_mount: lsof not defined in pam_mount.conf\n");
	while (config->command[_argc][LSOF])
		add_to_argv(_argv, &_argc, config->command[_argc][LSOF]);
	add_to_argv(_argv, &_argc, config->volume[vol].mountpoint);
	if ((pid =
	     procopen(_argv[0], &_argv[1], 0, NULL, &cstdout, NULL)) == -1)
		return;
	w4rn("pam_mount: lsof output (should be empty)...\n");
	log_output(cstdout);
	w4rn("pam_mount: %s\n", "waiting for mount");
	waitpid(pid, &child_exit, 0);
	CLOSE(cstdout);
}

/* ============================ mkmountpoint () ============================ */
/*
/* POST:   the directory named d exists && volume->created_mntpt = 1
 * FN VAL: if error 0 else 1, errors are logged
 */
int mkmountpoint(vol_t * const volume, const char *const d)
{
	struct passwd *passwd_ent;
	char dcopy[PATH_MAX + 1], *parent;

	assert(volume->user);
	assert(d);

	w4rn("pam_mount: creating mount point %s\n", d);
	strncpy(dcopy, d, PATH_MAX);
	dcopy[PATH_MAX] = 0x00;
	parent = dirname(dcopy);
	if (!exists(parent) && !mkmountpoint(volume, parent))
		return 0;
	if ((passwd_ent = getpwnam(volume->user))) {
		if (mkdir(d, 0700) != 0) {
			l0g("pam_mount: tried to create %s but failed\n",
			    d);
			return 0;
		}
		if (chown(d, passwd_ent->pw_uid, passwd_ent->pw_gid)
		    != 0) {
			l0g("pam_mount: could not chown %s to %s\n",
			    d, volume->user);
			return 0;
		}
	} else {
		l0g("pam_mount: could not determine uid from %s to make %s\n", volume->user, d);
		return 0;
	}
	volume->created_mntpt = 1;
	return 1;
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
			   const int vol, char *const mntpt)
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

	assert(config->volume[vol].volume);
	assert(config->volume[vol].server);
	assert(config->volume[vol].mountpoint);

	memset(match, 0x00, sizeof(match));
	if (config->volume[vol].type == SMBMOUNT) {
		strcpy(match, "//");
		strncat(match, config->volume[vol].server,
			PATH_MAX - strlen(match));
		strncat(match, "/", PATH_MAX - strlen(match));
		strncat(match, config->volume[vol].volume,
			PATH_MAX - strlen(match));
	} else if (config->volume[vol].type == CIFSMOUNT) {
		strncpy(match, config->volume[vol].server,
			PATH_MAX - strlen(match));
		strncat(match, "/", PATH_MAX - strlen(match));
		strncat(match, config->volume[vol].volume,
			PATH_MAX - strlen(match));
	} else if (config->volume[vol].type == NCPMOUNT) {
		strncpy(match, config->volume[vol].server,
			PATH_MAX - strlen(match));
		strncat(match, "/", PATH_MAX - strlen(match));
		strncat(match, config->volume[vol].volume,
			PATH_MAX - strlen(match));
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
	while (mtab_record = getmntent(mtab))
		if (!strcmp(mtab_record->mnt_fsname, match)) {
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
	fclose(mtab);
	return mounted;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
	{
		FILE *fp;
		int _argc = 0, cstdout = -1;
		char *_argv[MAX_PAR + 1], dev[BUFSIZ + 1];
		/*
		 * FIXME: I'm not overly fond of using mount, but BSD has no
		 * /etc/mtab?
		 */
		if (!config->command[0][MNTCHECK]) {
			l0g("pam_mount: mntcheck not defined in pam_mount.conf\n");
			return -1;
		}
		while (config->command[_argc][MNTCHECK])
			add_to_argv(_argv, &_argc,
				    config->command[_argc][MNTCHECK]);
		if ((pid =
		     procopen(_argv[0], &_argv[1], 0, NULL, &cstdout,
			      NULL)) == -1)
			return -1;
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
			if (!strcmp(dev, match)) {
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
			 const int vol)
{
	int i;
	char options[MAX_PAR + 1];
	w4rn("pam_mount: %s\n", "information for mount:");
	w4rn("pam_mount: %s\n", "--------");
	w4rn("pam_mount: %s\n",
	     config->volume[vol].
	     globalconf ? "(defined by globalconf)" :
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

/* ============================ do_unmount () ============================== */
int
do_unmount(struct config_t *config, const int vol,
	   const char *const password, const int mkmntpoint)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         mkmountpoint is true if mount point should be rmdir'ed
 * POST:   volume is unmounted
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	int child_exit, _argc = 0;
	pid_t pid = -1;
	char *_argv[MAX_PAR + 1];

	assert(!password);	/* password should point to NULL for unmounting */

	if (!config->command[0][UMOUNT]) {
		l0g("pam_mount: umount not defined in pam_mount.conf\n");
		return 0;
	}
	if (debug)
		/*
		 * Often, a process still exists with ~ as its pwd after
		 * logging out.  Running lsof helps debug this.
		 */
		run_lsof(config, vol);
	while (config->command[_argc][UMOUNT])
		add_to_argv(_argv, &_argc, config->command[_argc][UMOUNT]);
	/* Need to unmount mount point not volume to support SMB mounts, etc. */
	add_to_argv(_argv, &_argc, config->volume[vol].mountpoint);
	if ((pid =
	     procopen(_argv[0], &_argv[1], 1, NULL, NULL, NULL)) == -1)
		return 0;
	waitpid(pid, &child_exit, 0);
	if (mkmntpoint && config->volume[vol].created_mntpt) {
		if (rmdir(config->volume[vol].mountpoint) == -1)	/* non-fatal */
			w4rn("pam_mount: could not remove %s\n",
			     config->volume[vol].mountpoint);
	}
	/* pass on through the result from the umount process */
	return (!WEXITSTATUS(child_exit));
}

/* ============================ do_losetup () ============================== */
int
do_losetup(struct config_t *config, const int vol,
	   const unsigned char *password, int password_len)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         config->volume[vol].options is valid
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	pid_t pid;
	int child_exit, fds[2], _argc = 0, cstdin = -1;
	char *_argv[MAX_PAR + 1];
	char *cipher =
	    optlist_value(config->volume[vol].options, "encryption");
	char *keybits =
	    optlist_value(config->volume[vol].options, "keybits");
	assert(password);
	assert(0 <= password_len
	       && password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	if (!config->command[0][LOSETUP]) {
		l0g("pam_mount: losetup not defined in pam_mount.conf\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	while (config->command[_argc][LOSETUP])
		add_to_argv(_argv, &_argc,
			    config->command[_argc][LOSETUP]);
	if (cipher) {
		add_to_argv(_argv, &_argc, "-p0");
		add_to_argv(_argv, &_argc, "-e");
		add_to_argv(_argv, &_argc, cipher);
	}
	if (keybits) {
		add_to_argv(_argv, &_argc, "-k");
		add_to_argv(_argv, &_argc, keybits);
	}
	add_to_argv(_argv, &_argc, config->fsckloop);
	add_to_argv(_argv, &_argc, config->volume[vol].volume);
	if (cipher) {
		if ((pid =
		     procopen(_argv[0], &_argv[1], 0, &cstdin, NULL, NULL)) == -1)
			return 0;
		write(cstdin, password, password_len);
		CLOSE(cstdin);
	} else {
		if ((pid = procopen(_argv[0], &_argv[1], 0, NULL, NULL, NULL)) == -1)
			return 0;
	}
	w4rn("pam_mount: %s\n", "waiting for losetup");
	waitpid(pid, &child_exit, 0);
	/* pass on through the result */
	return (!WEXITSTATUS(child_exit));
}

/* ============================ do_unlosetup () ============================ */
int do_unlosetup(struct config_t *config)
/* PRE:    config points to a valid struct config_t*
 * POST:   volume has associated with a loopback device
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	pid_t pid;
	char *_argv[MAX_PAR + 1];
	int child_exit, _argc = 0;
	if (!config->command[0][UNLOSETUP]) {
		l0g("pam_mount: unlosetup not defined in pam_mount.conf\n");
		return 0;
	}
	/* FIXME: support OpenBSD */
	while (config->command[_argc][UNLOSETUP])
		add_to_argv(_argv, &_argc,
			    config->command[_argc][UNLOSETUP]);
	add_to_argv(_argv, &_argc, config->fsckloop);
	if ((pid =
	     procopen(_argv[0], &_argv[1], 0, NULL, NULL, NULL)) == -1)
		return 0;
	w4rn("pam_mount: %s\n", "waiting for losetup delete");
	waitpid(pid, &child_exit, 0);
	/* pass on through the result */
	return (!WEXITSTATUS(child_exit));
}

/* ============================ check_filesystem () ======================== */
int
check_filesystem(struct config_t *config, const int vol,
		 const unsigned char *password, int password_len)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 * POST:   integrity of volume has been checked
 * FN VAL: if error 0 else 1, errors are logged
 */
{
#if defined (__linux__)
	pid_t pid;
	int child_exit, _argc = 0;
	char *_argv[MAX_PAR + 1];
	char *fsck_target =
	    config->volume[vol].volume, options[MAX_PAR + 1];

	assert(password);
	assert(0 <= password_len
	       && password_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	if (!config->command[0][FSCK]) {
		l0g("pam_mount: fsck not defined in pam_mount.conf\n");
		return 0;
	}
	if (optlist_exists(config->volume[vol].options, "loop")) {
		if (!do_losetup(config, vol, password, password_len))
			return 0;
		fsck_target = config->fsckloop;
	} else
		w4rn("pam_mount: volume not a loopback (options: %s)\n",
		     optlist_to_str(options, config->volume[vol].options));
	while (config->command[_argc][FSCK])
		add_to_argv(_argv, &_argc, config->command[_argc][FSCK]);
	add_to_argv(_argv, &_argc, config->fsckloop);
	if ((pid =
	     procopen(_argv[0], &_argv[1], 0, NULL, NULL, NULL)) == -1)
		return 0;
	w4rn("pam_mount: %s\n", "waiting for filesystem check");
	waitpid(pid, &child_exit, 0);
	if (optlist_exists(config->volume[vol].options, "loop"))
		if (!do_unlosetup(config))
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
do_mount(struct config_t *config, const int vol, const char *password,
	 const int mkmntpoint)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         mkmntpoint is true if mount point should be mkdir'ed
 *         false if mount point was received from pam_mount
 * POST:   volume is mounted
 * FN VAL: if error 0 else 1, errors are logged
 */
{
	char *_argv[MAX_PAR + 1];
	char options[MAX_PAR + 1];
	char prev_mntpt[PATH_MAX + 1];
	int _password_len, mount_again = 0;
	unsigned char _password[MAX_PAR + EVP_MAX_BLOCK_LENGTH];
	int _argc = 0, child_exit = 0, cstdin = -1, cstderr = -1;
	pid_t pid = -1;

	assert(password);

	/* FIXME: This is a little ugly, especially check for != LCLMOUNT */
	if ((mount_again = already_mounted(config, vol, prev_mntpt)))
		if (mount_again == -1) {
			l0g("pam_mount: could not determine if %s is already mounted, failing\n", config->volume[vol].volume);
			return 0;
		} else
		    if (!strcmp
			(prev_mntpt, config->volume[vol].mountpoint)) {
			w4rn("pam_mount: %s already seems to be mounted at %s, skipping\n", config->volume[vol].volume, prev_mntpt);
			return 1;
		} else {
			w4rn("pam_mount: %s already mounted elsewhere at %s\n", config->volume[vol].volume, prev_mntpt);
			if (config->volume[vol].type != LCLMOUNT)
				mount_again = 0;
		}
	if (!exists(config->volume[vol].mountpoint))
		if (mkmntpoint) {
			if (!mkmountpoint
			    (&config->volume[vol],
			     config->volume[vol].mountpoint))
				return 0;
		} else {
			l0g("pam_mount: mount point %s does not exist (pam_mount not configured to make it)\n", config->volume[vol].mountpoint);
			return 0;
		}
	if (mount_again) {
		if (!config->command[0][MNTAGAIN]) {
			l0g("pam_mount: mntagain not defined in pam_mount.conf\n");
			return 0;
		}
#if defined(__linux__)
		while (config->command[_argc][MNTAGAIN])
			add_to_argv(_argv, &_argc,
				    config->command[_argc][MNTAGAIN]);
		add_to_argv(_argv, &_argc, prev_mntpt);
		add_to_argv(_argv, &_argc, config->volume[vol].mountpoint);
		if ((pid =
		     procopen(_argv[0], &_argv[1], 1, NULL, NULL,
			      &cstderr)) == -1)
			return 0;
#else
		/* FIXME */
		l0g("pam_mount: %s\n",
		    "multiple mounts of same volume not implemented on arch.");
		return 0;
#endif
	} else {
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
		while (config->command[_argc][config->volume[vol].type])
			add_to_argv(_argv, &_argc,
				    config->command[_argc][config->
							   volume[vol].
							   type]);
		if (config->volume[vol].type == NCPMOUNT) {
			char *tmp;	/* FIXME: never freed */
			w4rn("pam_mount: %s\n", "mount type is NCPMOUNT");
			if (asprintf
			    (&tmp, "%s/%s", config->volume[vol].server,
			     config->volume[vol].user) == -1) {
				l0g("pam_mount: asprintf error: %s\n",
				    strerror(errno));
				return 0;
			}
			add_to_argv(_argv, &_argc, tmp);
			add_to_argv(_argv, &_argc,
				    config->volume[vol].mountpoint);
			add_to_argv(_argv, &_argc, "-o");
			if (asprintf
			    (&tmp, "pass-fd=0,volume=%s%s%s",
			     config->volume[vol].volume,
			     optlist_len(config->volume[vol].
					 options) ? "," : "",
			     optlist_to_str(options,
					    config->volume[vol].
					    options)) == -1) {
				l0g("pam_mount: asprintf error: %s\n",
				    strerror(errno));
				return 0;
			}
			add_to_argv(_argv, &_argc, tmp);
		} else if (config->volume[vol].type == SMBMOUNT) {
			char *tmp;	/* FIXME: never freed */
			w4rn("pam_mount: %s\n", "mount type is SMBMOUNT");
			if (asprintf
			    (&tmp, "//%s/%s", config->volume[vol].server,
			     config->volume[vol].volume) == -1) {
				l0g("pam_mount: asprintf error: %s\n",
				    strerror(errno));
				return 0;
			}
			add_to_argv(_argv, &_argc, tmp);
			add_to_argv(_argv, &_argc,
				    config->volume[vol].mountpoint);
			add_to_argv(_argv, &_argc, "-o");
			if (asprintf(&tmp, "username=%s%s%s",
				     config->volume[vol].user,
				     optlist_len(config->volume[vol].
						 options) ? "," : "",
				     optlist_to_str(options,
						    config->volume[vol].
						    options)) == -1) {
				l0g("pam_mount: asprintf error: %s\n",
				    strerror(errno));
				return 0;
			}
			add_to_argv(_argv, &_argc, tmp);
		} else if (config->volume[vol].type == CIFSMOUNT) {
			char *tmp;	/* FIXME: never freed */
			w4rn("pam_mount: %s\n", "mount type is CIFSMOUNT");
			if (asprintf
			    (&tmp, "//%s/%s", config->volume[vol].server,
			     config->volume[vol].volume) == -1) {
				l0g("pam_mount: asprintf error: %s\n",
				    strerror(errno));
				return 0;
			}
			add_to_argv(_argv, &_argc, tmp);
			add_to_argv(_argv, &_argc,
				    config->volume[vol].mountpoint);
			add_to_argv(_argv, &_argc, "-S");	/* passwd from stdin */
			add_to_argv(_argv, &_argc, "-o");
			if (asprintf
			    (&tmp, "user=%s%s%s", config->volume[vol].user,
			     optlist_len(config->volume[vol].
					 options) ? "," : "",
			     optlist_to_str(options,
					    config->volume[vol].
					    options)) == -1) {
				l0g("pam_mount: asprintf error: %s\n",
				    strerror(errno));
				return 0;
			}
			add_to_argv(_argv, &_argc, tmp);
		} else if (config->volume[vol].type == LCLMOUNT) {
			w4rn("pam_mount: %s\n", "mount type is LCLMOUNT");
			if (optlist_len(config->volume[vol].options)) {
				add_to_argv(_argv, &_argc, "-o");
				add_to_argv(_argv, &_argc,
					    optlist_to_str(options,
							   config->
							   volume[vol].
							   options));
			}
			add_to_argv(_argv, &_argc,
				    config->volume[vol].volume);
			if (!config->volume[vol].use_fstab)
				add_to_argv(_argv, &_argc,
					    config->volume[vol].
					    mountpoint);
			if (!check_filesystem
			    (config, vol, _password, _password_len))
				l0g("pam_mount: %s\n",
				    "error checking filesystem but will continue");
		} else if (config->volume[vol].type == NFSMOUNT) {
			w4rn("pam_mount: %s\n", "mount type is NFSMOUNT");
			if (optlist_len(config->volume[vol].options)) {
				add_to_argv(_argv, &_argc, "-o");
				add_to_argv(_argv, &_argc,
					    optlist_to_str(options,
							   config->
							   volume[vol].
							   options));
			}
			add_to_argv(_argv, &_argc,
				    config->volume[vol].volume);
			if (!config->volume[vol].use_fstab)
				add_to_argv(_argv, &_argc,
					    config->volume[vol].
					    mountpoint);
		} else {
			l0g("pam_mount: %s\n",
			    "config->volume[vol].type is unknown");
			return 0;
		}
		/* send password down pipe to mount process */
		if (config->volume[vol].type == SMBMOUNT)
			setenv("PASSWD_FD", "0", 1);
		if ((pid =
		     procopen(_argv[0], &_argv[1], 1, &cstdin, NULL,
			      &cstderr)) == -1)
			return 0;
		/* FIXME: This causes execution to stop if all loop devices 
		 * are already being used.  Mount exits before prompting for 
		 * a password in this case.
		 */
		write(cstdin, _password, _password_len);
		CLOSE(cstdin);
	}
	/* Paranoia? */
	memset(_password, 0x00, MAX_PAR + EVP_MAX_BLOCK_LENGTH);
	w4rn("pam_mount: mount errors (should be empty):\n");
	log_output(cstderr);
	CLOSE(cstderr);
	w4rn("pam_mount: %s\n", "waiting for mount");
	waitpid(pid, &child_exit, 0);
	/* pass on through the result from the mount process */
	return !WEXITSTATUS(child_exit);
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
	      (struct config_t * config, const int vol,
	       const char *password, const int mkmntpoint),
	     struct config_t *config,
	     const int vol, const char *password, const int mkmntpoint)
{
	assert(0 <= config->volume[vol].type
	       && config->volume[vol].type < COMMAND_MAX);
	assert(config->volume[vol].fs_key_cipher);
	assert(config->volume[vol].fs_key_path);
	assert(config->volume[vol].server);
	assert(config->volume[vol].user);
	assert(config->volume[vol].volume);
	assert(config->volume[vol].mountpoint);
	assert(!strlen(config->volume[vol].fs_key_cipher) || strlen(config->volume[vol].fs_key_path));	/* should be guaranteed by volume_record_sane() */
	assert(config->volume[vol].type == LCLMOUNT || strlen(config->volume[vol].server));	/* should be guaranteed by volume_record_sane() */

	if (debug)
		log_pm_input(config, vol);
	return mnt(config, vol, password, mkmntpoint);
}
