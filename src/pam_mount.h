#ifndef PMT_PAM_MOUNT_H
#define PMT_PAM_MOUNT_H 1

#include <libHX/list.h>
#include <stdbool.h>

struct config;

enum auth_type {
	GET_PASS,
	USE_FIRST_PASS,
	TRY_FIRST_PASS,
	SOFT_TRY_PASS,
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
 *	PAM_MOUNT.C
 */
#ifndef HAVE_VISIBILITY_HIDDEN
	/* Workaround Xserver issue */
#	define Debug pmt_debug
#endif
extern bool Debug;
extern struct config Config;
extern struct pam_args Args;

#endif /* PMT_PAM_MOUNT_H */
