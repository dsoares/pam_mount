/*   FILE: pam_mount.h
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

#ifndef _PAM_MOUNT_H
#define _PAM_MOUNT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <security/pam_modules.h>
#include <errno.h>
#include <limits.h>
#include <optlist.h>
#include <unistd.h>
#include <new/fmt_ptrn.h>

#ifdef __OpenBSD__
#define CONFIGFILE	"/etc/pam_mount.conf"
#else
#define CONFIGFILE	"/etc/security/pam_mount.conf"
#endif				/* __OpenBSD__ */

	extern int errno;

#define CLOSE(a) if (close(a)==-1) { \
    l0g("pam_mount: could not close fd: %s\n", strerror(errno)); \
    l0g("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
}

#define MAX_PAR		127

#define DEBUG_DEFAULT		FALSE
#define MKMOUNTPOINT_DEFAULT	FALSE
#define FSCKLOOP_DEFAULT	"/dev/loop7"

	typedef enum command_type_t {
		SMBMOUNT,
		CIFSMOUNT,
		NCPMOUNT,
		LCLMOUNT,
		CRYPTMOUNT,	/* FIXME: hope to have this in util-linux
				 * (LCLMOUNT) some day */
		NFSMOUNT,
		UMOUNT,
		PMHELPER,
		LSOF,
		MNTAGAIN,
		MNTCHECK,
		FSCK,
		LOSETUP,
		UNLOSETUP,
		PMVARRUN,
		COMMAND_MAX,
	} command_type_t;

	typedef enum auth_type_t {
		GET_PASS,
		USE_FIRST_PASS,
		TRY_FIRST_PASS
	} auth_type_t;

	typedef struct pam_args_t {
		auth_type_t auth_type;
	} pam_args_t;

	typedef struct pm_command_t {
		command_type_t type;
		char *fs;
		char *command_name;
		char *def[MAX_PAR + 1];
	} pm_command_t;

	typedef struct vol_t {
		command_type_t type;
		gboolean globalconf;	/* TRUE if config. from global
					 * config, FALSE if luserconf */
		gboolean created_mntpt;	/* set so umount knows to rm
					 * it */
		char fs_key_cipher[MAX_PAR + 1];
		char fs_key_path[PATH_MAX + 1];
		char server[MAX_PAR + 1];
		char user[MAX_PAR + 1];	/* user field in a
					 * single volume config
					 * record; can be "*" */
		char volume[MAX_PAR + 1];	/* FIXME: PATH_MAX */
		optlist_t *options;	/* may be NULL if no options */
		char mountpoint[PATH_MAX + 1];
		gboolean use_fstab;
		gboolean used_wildcard;
	} vol_t;

	typedef struct config_t {
		char *user;	/* user logging in */
		gboolean debug;
		gboolean mkmountpoint;
		unsigned int volcount;
		char luserconf[PATH_MAX + 1];
		char fsckloop[PATH_MAX + 1];
		char *command[MAX_PAR + 1][COMMAND_MAX];
		optlist_t *options_require;
		optlist_t *options_allow;
		optlist_t *options_deny;
		vol_t *volume;
	} config_t;

/* ============================ exists () ================================== */
	int exists(const char *file);

/* ============================ owns () ==================================== */
	gboolean owns(const char *user, const char *file);

/* ============================ l0g () ===================================== */
	void l0g(const char *format, ...);

/* ============================ w4rn () ==================================== */
	void w4rn(const char *format, ...);

/* ============================ luserconf_volume_record_sane () ============ */
	gboolean luserconf_volume_record_sane(config_t * config, int vol);

/* ============================ volume_record_sane () ====================== */
	gboolean volume_record_sane(config_t * config, int vol);

/* ============================ readconfig () ============================== */
	int readconfig(const char *user, char *file, int globalconf,
		       config_t * config);

/* ============================ initconfig () ============================== */
	int initconfig(config_t * config);

/* ============================ freeconfig () ============================== */
	void freeconfig(config_t config);

/* ============================ expandconfig () ============================ */
	int expandconfig(config_t * config);

/* ============================ do_mount () ================================ */
	int do_mount(struct config_t *config, const unsigned int vol,
		     fmt_ptrn_t * vinfo, const char *password,
		     const gboolean mkmntpoint);

/* ============================ do_unmount () ============================== */
	int do_unmount(struct config_t *config, const unsigned int vol,
		       fmt_ptrn_t * vinfo, const char *password,
		       const gboolean mkmntpoint);

/* ============================ mount_op () ================================ */
	int mount_op(int (*mnt)
		      (struct config_t * config, const unsigned int vol,
		       fmt_ptrn_t * vinfo, const char *password,
		       const int mkmntpoint), struct config_t *config,
		     const unsigned int vol, const char *password,
		     const int mkmntpoint);

/* ============================ pm_command_t_valid () ====================== */
	gboolean pm_command_t_valid(const pm_command_t * c);

/* ============================ vol_t_valid () ============================= */
	gboolean vol_t_valid(const vol_t * v);

/* ============================ config_t_valid () ========================== */
	gboolean config_t_valid(const config_t * c);

/* ============================ procopen () ================================ */
	pid_t procopen(const char *const path, char *const argv[],
			      const int do_setuid, /*@null@ */
			      int *const cstdin, /*@null@ */
			      int *const cstdout,
			      /*@null@ */ int *const cstderr);

/* ============================ str_to_long () ============================= */
	long str_to_long(char *n);

/* ============================ add_to_argv () ============================= */
void add_to_argv(char *argv[], int *const argc, char *const arg, fmt_ptrn_t *vinfo);

#ifdef __cplusplus
}
#endif
#endif				/* _PAM_MOUNT_H */
