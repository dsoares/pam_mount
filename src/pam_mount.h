#ifndef PMT_PAM_MOUNT_H
#define PMT_PAM_MOUNT_H 1

#include <limits.h>
#include <stdbool.h>
#include <libHX/clist.h>
#include <libHX/list.h>

#define MAX_PAR         127
#ifndef S_IRUGO
#	define S_IRUGO (S_IRUSR | S_IRGRP | S_IROTH)
#endif
#ifndef S_IRWXU
#	define S_IRWXU (S_IRUSR | S_IWUSR | S_IWOTH)
#endif
#ifndef S_IRXG
#	define S_IRXG (S_IRGRP | S_IXGRP)
#endif
#ifndef S_IRXO
#	define S_IRXO (S_IROTH | S_IXOTH)
#endif
#define sizeof_z(x) (sizeof(x) - 1)

enum auth_type {
	GET_PASS,
	USE_FIRST_PASS,
	TRY_FIRST_PASS,
	SOFT_TRY_PASS,
};

enum command_type {
	CMD_SMBMOUNT,
	CMD_SMBUMOUNT,
	CMD_CIFSMOUNT,
	CMD_NCPMOUNT,
	CMD_NCPUMOUNT,
	CMD_FUSEMOUNT,
	CMD_FUSEUMOUNT,
	CMD_LCLMOUNT,
	CMD_CRYPTMOUNT,
	CMD_CRYPTUMOUNT,
	CMD_NFSMOUNT,
	CMD_UMOUNT,
	CMD_PMHELPER,
	CMD_MNTCHECK,
	CMD_FSCK,
	CMD_LOSETUP,
	CMD_UNLOSETUP,
	CMD_PMVARRUN,
	CMD_TRUECRYPTMOUNT,
	CMD_TRUECRYPTUMOUNT,
	CMD_FD0SSH,
	_CMD_MAX,
	CMD_NONE,
};

struct vol {
	struct HXlist_head list;
	enum command_type type;
	/* true if configuration from global config, false if luserconf */
	bool globalconf;
	/* set, so that umount can rmdir it */
	bool created_mntpt;
	const char *user;
	char *fstype, *server, *volume, *mountpoint;
	char *fs_key_cipher, *fs_key_path;
	/* May be NULL if no options */
	struct HXclist_head options;
	bool use_fstab;
	bool used_wildcard;
	bool uses_ssh;
};

/**
 * @sig_hup:	send SIGHUP to processes keeping mountpoint open
 * @sig_term:	send SIGTERM - " -
 * @sig_kill:	send SIGKILL - " -
 * @sig_wait:	wait this many seconds between sending signals,
 * 		in microseconds
 */
struct config {
	/* user logging in */
	char *user;
	unsigned int debug;
	bool mkmntpoint, rmdir_mntpt;
	hmc_t *luserconf;
	char *fsckloop;
	char *command[_CMD_MAX][MAX_PAR+1];
	struct HXbtree *options_require, *options_allow, *options_deny;
	struct HXclist_head volume_list;
	int level;
	char *msg_authpw, *msg_sessionpw, *path;

	bool sig_hup, sig_term, sig_kill;
	unsigned int sig_wait;
};

struct pam_args {
	enum auth_type auth_type;
	bool nullok;
};

struct kvp {
	char *key, *value;
	struct HXlist_head list;
};

/*
 *
 */
static inline const char *znul(const char *s)
{
	return (s == NULL) ? "(null)" : s;
}

/*
 *	OFL-LIB.C
 */
extern int (*ofl_printf)(const char *, ...);
extern bool ofl(const char *, unsigned int);

/*
 *	PAM_MOUNT.C
 */
#ifndef HAVE_VISIBILITY_HIDDEN
	/* Workaround Xserver issue */
#	define Debug pmt_debug
#endif
extern unsigned int Debug;
extern struct config Config;
extern struct pam_args Args;

/*
 *	SPAWN.C
 */
extern int spawn_synchronous(const char *const *);

#endif /* PMT_PAM_MOUNT_H */
