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
#include <limits.h>
#include <optlist.h>

#ifdef __OpenBSD__
#define CONFIGFILE	"/etc/pam_mount.conf"
#else
#define CONFIGFILE	"/etc/security/pam_mount.conf"
#endif				/* __OpenBSD__ */

	extern int      errno;

#define CLOSE(a) if (close(a)==-1) { \
    l0g("pam_mount: could not close fd: %s\n", strerror(errno)); \
    l0g("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
}

#define PIPE(a) if (pipe(a)==-1) { \
    l0g("pam_mount: could open pipe: %s\n", strerror(errno)); \
    l0g("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
}

#define MAX_PAR		127

#define DEBUG_DEFAULT		0
#define MKMOUNTPOINT_DEFAULT	0
#define FSCKLOOP_DEFAULT	"/dev/loop7"

	typedef enum command_type_t {
		SMBMOUNT,
		CIFSMOUNT,
		NCPMOUNT,
		LCLMOUNT,
		NFSMOUNT,
		UMOUNT,
		PMHELPER,
		LSOF,
		MNTAGAIN,
		MNTCHECK,
		FSCK,
		LOSETUP,
		UNLOSETUP,
		COMMAND_MAX
	}               command_type_t;
	
	typedef enum auth_type_t {
		GET_PASS,
		USE_FIRST_PASS,
		TRY_FIRST_PASS
	} auth_type_t;

	typedef struct pam_args_t {
		auth_type_t auth_type;
	} pam_args_t;

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
		char            fs_key_path[PATH_MAX + 1];
		char            server[MAX_PAR + 1];
		char            user[MAX_PAR + 1];	/* user field in a
							 * single volume config
							 * record; can be "*" */
		char            volume[MAX_PAR + 1]; /* FIXME: PATH_MAX */
		optlist_t       options;
		char            mountpoint[PATH_MAX + 1];
		int 		use_fstab;
	}               vol_t;

	typedef struct config_t {
		const char     *user;	/* user logging in */
		int             debug;
		int             mkmountpoint;
		int             volcount;
		char            luserconf[PATH_MAX + 1];
		char		fsckloop[PATH_MAX + 1];
		char           *command[MAX_PAR + 1][COMMAND_MAX];
		optlist_t	options_require;
		optlist_t	options_allow;
		optlist_t	options_deny;
		vol_t          *volume;
	}               config_t;

/* ============================ exists () ================================== */
	int             exists(const char *file);

/* ============================ owns () ==================================== */
	int             owns(const char *user, const char *file);

/* ============================ l0g () ===================================== */
	void            l0g(const char *format, ...);

/* ============================ w4rn () ==================================== */
	void            w4rn(const char *format, ...);

/* ============================ read_password () =========================== */
	int             read_password(pam_handle_t * pamh, const char *prompt1,
				                      char **pass);

/* ============================ do_mount () ================================ */
	int             do_mount(struct config_t * config, const int vol, const char *password, const int mkmntpoint);

/* ============================ do_unmount () ============================== */
	int             do_unmount(struct config_t * config, const int vol, const char *password, const int mkmntpoint);

/* ============================ mount_op () ================================ */
	int             mount_op(int (*mnt) (struct config_t * config, const int vol, const char *password, const int mkmntpoint), struct config_t * config, const int vol, const char *password, const int mkmntpoint);

#ifdef __cplusplus
}
#endif
#endif				/* _PAM_MOUNT_H */
