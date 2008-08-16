#ifndef PMT_PRIVATE_H
#define PMT_PRIVATE_H 1

#include <libHX/clist.h>
#include <libHX/list.h>
#include <limits.h>
#include <stdbool.h>

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
	char fs_key_cipher[MAX_PAR + 1];
	char fs_key_path[PATH_MAX + 1];
	char server[MAX_PAR + 1];
	/* user field in a single volume record; can be "*" */
	char user[MAX_PAR + 1];
	char fstype[MAX_PAR + 1];
	/* FIXME: PATH_MAX */
	char volume[MAX_PAR + 1];
	/* May be NULL if no options */
	struct HXclist_head options;
	char mountpoint[PATH_MAX + 1];
	bool use_fstab;
	bool used_wildcard;
	bool uses_ssh;
};

struct config {
	/* user logging in */
	char *user;
	unsigned int debug;
	bool mkmntpoint, rmdir_mntpt;
	char luserconf[PATH_MAX + 1];
	char fsckloop[PATH_MAX + 1];
	char *command[_CMD_MAX][MAX_PAR+1];
	struct HXbtree *options_require, *options_allow, *options_deny;
	struct HXclist_head volume_list;
	int level;
	char *msg_authpw, *msg_sessionpw, *path;
};

#endif /* PMT_PRIVATE_H */
