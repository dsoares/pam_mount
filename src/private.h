#ifndef PMT_PRIVATE_H
#define PMT_PRIVATE_H 1

#include "optlist.h"
#include "xstdlib.h"

#define CLOSE(a) do { \
	if(close(a) == -1) { \
		l0g("pam_mount: could not close fd: %s\n", strerror(errno)); \
		l0g("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
		exit(EXIT_FAILURE); \
	} \
} while(0)
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
	CMD_NFSMOUNT,
	CMD_UMOUNT,
	CMD_PMHELPER,
	CMD_LSOF,
	CMD_MNTAGAIN,
	CMD_MNTCHECK,
	CMD_FSCK,
	CMD_LOSETUP,
	CMD_UNLOSETUP,
	CMD_PMVARRUN,
	_CMD_MAX,
	CMD_NONE,
};

struct vol {
	enum command_type type;
	/* true if configuration from global config, false if luserconf */
	bool globalconf;
	/* set, so that umount will rmdir it */
	bool created_mntpt;
	char fs_key_cipher[MAX_PAR + 1];
	char fs_key_path[PATH_MAX + 1];
	char server[MAX_PAR + 1];
	/* user field in a single volume record; can be "*" */
	char user[MAX_PAR + 1];
	char fstype[MAX_PAR + 1];
	/* FIXME: PATH_MAX */
	char volume[MAX_PAR + 1];
	/* May be NULL if no options */
	optlist_t *options;
	char mountpoint[PATH_MAX + 1];
	bool use_fstab;
	bool used_wildcard;
};

struct config {
	/* user logging in */
	char *user;
	bool debug;
	bool mkmntpoint;
	unsigned int volcount;
	char luserconf[PATH_MAX + 1];
	char fsckloop[PATH_MAX + 1];
	char *command[MAX_PAR + 1][_CMD_MAX];
	optlist_t *options_require;
	optlist_t *options_allow;
	optlist_t *options_deny;
	struct vol *volume;
	int level;
};

#endif /* PMT_PRIVATE_H */
