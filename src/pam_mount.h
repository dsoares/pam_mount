#ifndef PMT_PAM_MOUNT_H
#define PMT_PAM_MOUNT_H 1

#include <limits.h>
#include <stdbool.h>
#include <libHX/clist.h>
#include <libHX/list.h>
#include <libHX/option.h>
#include "config.h"

#ifdef HAVE_VISIBILITY_HIDDEN
#	define EXPORT_SYMBOL __attribute__((visibility("default")))
#else
#	define EXPORT_SYMBOL
#endif

#ifndef S_IRXG
#	define S_IRXG (S_IRGRP | S_IXGRP)
#endif
#ifndef S_IRXO
#	define S_IRXO (S_IROTH | S_IXOTH)
#endif
#define sizeof_z(x) (sizeof(x) - 1)

/*
 * So many programs trash a useful $PATH (including mount(8)),
 * so just provide our own.
 */
#define PMT_DFL_PATH \
	"/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
#define PMT_DFL_DMCRYPT_CIPHER "aes-cbc-essiv:sha256"
#define PMT_DFL_FSK_CIPHER     "aes-256-cbc"
#define PMT_DFL_FSK_HASH       "md5"

struct HXbtree;
struct HXdeque;
struct loop_info64;

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
	CMD_FSCK,
	CMD_PMVARRUN,
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
	bool noroot;
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
	hxmc_t *luserconf;
	struct HXdeque *command[_CMD_MAX];
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
static inline void format_add(struct HXbtree *table, const char *key,
    const char *value)
{
	HXformat_add(table, key, value, HXTYPE_STRING | HXFORMAT_IMMED);
}

static inline const char *znul(const char *s)
{
	return (s == NULL) ? "(null)" : s;
}

/*
 *	LOOP.C
 */
extern const char *loop_file_name(const char *, struct loop_info64 *);
extern int ehd_load(const char *, hxmc_t **, const char *, const char *,
	const unsigned char *, unsigned int, bool);
extern int ehd_unload(const char *, bool);
extern hxmc_t *ehd_decrypt_key(const char *, const char *, const char *,
	const char *);
extern unsigned int cipher_digest_security(const char *);
extern hxmc_t *pmt_get_password(void);

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
