#ifndef _PAM_MOUNT_H
#define _PAM_MOUNT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <security/pam_modules.h>

#define CONFIGFILE	"/etc/security/pam_mount.conf"

#define MAX_PAR		127

#define DEBUG_DEFAULT		0
#define MKMOUNTPOINT_DEFAULT	0
#define GETPASS_DEFAULT		0

    typedef enum command_type_t {
	SMBMOUNT,
	NCPMOUNT,
	LCLMOUNT,
	UMOUNT,
	PMHELPER,
	LSOF,
	COMMAND_MAX
    } command_type_t;

    typedef struct pm_command_t {
	command_type_t type;
	char *fs;
	char *command_name;
    } pm_command_t;

    typedef struct data_t {	/* This is what is passed to pmhelper via pipe. */
	command_type_t type;
	int unmount;
	int globalconf;		/* 1 if set by global config, 0 if luserconf */
	char fs_key_cipher[MAX_PAR + 1];
	char fs_key_path[FILENAME_MAX + 1];
	char server[MAX_PAR + 1];
	char user[MAX_PAR + 1];	/* user field in a simgle volume config 
				 * record; can be "*" */
	char volume[MAX_PAR + 1];
	char options[MAX_PAR + 1];
	char mountpoint[FILENAME_MAX + 1];
	char ucommand[FILENAME_MAX + 1];
	char lsof[FILENAME_MAX + 1];
	char password[FILENAME_MAX + 1];
	char argv[FILENAME_MAX + 1][MAX_PAR + 1];	/* for building mount command */
	int argc;
    } data_t;

    typedef struct config_t {
	const char *user;	/* user logging in */
	int debug;
	int mkmountpoint;
	int volcount;
	char luserconf[FILENAME_MAX + 1];
	char *system_password;
	char *command[MAX_PAR + 1][COMMAND_MAX];
	char *options_require[MAX_PAR + 1];
	char *options_allow[MAX_PAR + 1];
	char *options_deny[MAX_PAR + 1];
	data_t *data;
    } config_t;

/* ============================ exists () ================================== */
    int exists(const char *file);

/* ============================ owns () ==================================== */
    int owns(const char *user, const char *file);

/* ============================ log () ===================================== */
    void log(const char *mask, const char *arg);

/* ============================ w4rn () ==================================== */
    void w4rn(const char *mask, const char *arg);

/* ============================ read_password () =========================== */
    int read_password(pam_handle_t * pamh, const char *prompt1,
		      char **pass);

#ifdef __cplusplus
}
#endif
#endif				/* _PAM_MOUNT_H */
