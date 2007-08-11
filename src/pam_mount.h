#ifndef PMT_PAM_MOUNT_H
#define PMT_PAM_MOUNT_H 1

#include <glib.h>

struct config;

enum auth_type {
	GET_PASS,
	USE_FIRST_PASS,
	TRY_FIRST_PASS,
};

struct pam_args {
	enum auth_type auth_type;
	const char *password_prompt;
};

/*
 *	PAM_MOUNT.C
 */
#ifndef HAVE_VISIBILITY_HIDDEN
	/* Workaround Xserver issue */
#	define Debug pmt_debug
#endif
extern int Debug;
extern struct config Config;
extern struct pam_args Args;

#endif /* PMT_PAM_MOUNT_H */
