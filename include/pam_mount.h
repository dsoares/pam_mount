#ifndef _PAM_MOUNT_H
#define _PAM_MOUNT_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <security/pam_modules.h>
#include <errno.h>

#ifdef __OpenBSD__
#define CONFIGFILE	"/etc/pam_mount.conf"
#else
#define CONFIGFILE	"/etc/security/pam_mount.conf"
#endif				/* __OpenBSD__ */

	extern int      errno;

#define CLOSE(a) if (close(a)==-1) { \
    log("pam_mount: could not close fd: %s\n", strerror(errno)); \
    log("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
}

#define PIPE(a) if (pipe(a)==-1) { \
    log("pam_mount: could open pipe: %s\n", strerror(errno)); \
    log("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
}

#define MAX_PAR		127

#define DEBUG_DEFAULT		0
#define MKMOUNTPOINT_DEFAULT	0
#define GETPASS_DEFAULT		0

	typedef enum command_type_t {
		SMBMOUNT,
		CIFSMOUNT,
		NCPMOUNT,
		LCLMOUNT,
		UMOUNT,
		PMHELPER,
		LSOF,
		MNTCHECK,
		COMMAND_MAX
	}               command_type_t;

	typedef struct pm_command_t {
		command_type_t  type;
		char           *fs;
		char           *command_name;
	}               pm_command_t;

	typedef struct vol_t {
		command_type_t  type;
		int             globalconf;	/* 1 if config. from global
						 * config, 0 if luserconf */
		int             created_mntpt;	/* set so umount knows to rm
						 * it */
		char            fs_key_cipher[MAX_PAR + 1];
		char            fs_key_path[FILENAME_MAX + 1];
		char            server[MAX_PAR + 1];
		char            user[MAX_PAR + 1];	/* user field in a
							 * single volume config
							 * record; can be "*" */
		char            volume[MAX_PAR + 1];
		char            options[MAX_PAR + 1];
		char            mountpoint[FILENAME_MAX + 1];
	}               vol_t;

	typedef struct config_t {
		const char     *user;	/* user logging in */
		int             debug;
		int             mkmountpoint;
		int             volcount;
		char            luserconf[FILENAME_MAX + 1];
		char           *command[MAX_PAR + 1][COMMAND_MAX];
		char           *options_require[MAX_PAR + 1];
		char           *options_allow[MAX_PAR + 1];
		char           *options_deny[MAX_PAR + 1];
		vol_t          *volume;
	}               config_t;

/* ============================ exists () ================================== */
	int             exists(const char *file);

/* ============================ owns () ==================================== */
	int             owns(const char *user, const char *file);

/* ============================ log () ===================================== */
	void            log(const char *mask, const char *arg);

/* ============================ w4rn () ==================================== */
	void            w4rn(const char *mask, const char *arg);

/* ============================ read_password () =========================== */
	int             read_password(pam_handle_t * pamh, const char *prompt1,
				                      char **pass);

/* ============================ do_mount () ================================ */
	int             do_mount(struct config_t * config, const int vol, const char *password, const int mkmntpoint, const int mntpt_from_fstab);

/* ============================ do_unmount () ============================== */
	int             do_unmount(struct config_t * config, const int vol, const char *password, const int mkmntpoint, const int mntpt_from_fstab);

/* ============================ mount_op () ================================ */
	int             mount_op(int (*mnt) (struct config_t * config, const int vol, const char *password, const int mkmntpoint, const int mntpt_from_fstab), struct config_t * config, const int vol, const char *password, const int mkmntpoint);

#ifdef __cplusplus
}
#endif
#endif				/* _PAM_MOUNT_H */
