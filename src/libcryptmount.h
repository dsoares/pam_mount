#ifndef _CRYPTMOUNT_H
#define _CRYPTMOUNT_H 1

#include <libHX/string.h>
#ifndef __cplusplus
#	include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Result codes for ehd_cipherdigest_security
 * (negative indicates system error code).
 *
 * %EHD_SECURITY_BLACKLISTED:	cipher/digest classified as absolute no-go
 * %EHD_SECURITY_SUBPAR:	use of cipher/digest is disrecommended
 * %EHD_SECURITY_UNSPEC:	no verdict
 * %EHD_SECURITY_ADEQUATE:	cipher/digest passes
 *
 * Ordering is supported, x < %EHD_SECURITY_* may be used.
 */
enum {
	EHD_SECURITY_BLACKLISTED = 0,
	EHD_SECURITY_SUBPAR,
	EHD_SECURITY_UNSPEC,
	EHD_SECURITY_ADEQUATE,
};

/**
 * struct ehd_mount_request - mapping and mount request for EHD
 * @container:		path to disk image
 * @mountpoint:		where to mount the volume on
 * @readonly:		whether to create a readonly vfsmount
 * @key_data:		key material/password
 * @key_size:		size of key data, in bytes
 * @fs_cipher:		cipher used for filesystem, if any. (cryptsetup name)
 * @fs_hash:		hash used for filesystem, if any. (cryptsetup name)
 * @trunc_keysize:	extra cryptsetup instruction for truncation (in bytes)
 */
struct ehd_mount_request {
	const char *container;
	const char *mountpoint;
	const char *fs_cipher, *fs_hash;
	const void *key_data;
	unsigned int key_size, trunc_keysize;
	bool readonly;
};

struct ehd_mount_info;

extern int cryptmount_init(void);
extern void cryptmount_exit(void);

extern int ehd_load(const struct ehd_mount_request *, struct ehd_mount_info *);
extern int ehd_unload(const struct ehd_mount_info *);

extern int ehd_cipherdigest_security(const char *);
extern hxmc_t *ehd_get_password(const char *);

/*
 *	loop.c
 */
enum {
	EHD_LOSETUP_RW = 0,
	EHD_LOSETUP_RO = 1,
};

extern int ehd_loop_setup(const char *, char **, bool);
extern int ehd_loop_release(const char *);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _CRYPTMOUNT_H */
