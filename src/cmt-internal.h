#ifndef _CMT_INTERNAL_H
#define _CMT_INTERNAL_H 1

#include <stdbool.h>

struct ehd_mount_info;

/**
 * struct ehd_mount_request - mapping and mount request for EHD
 * @container:		path to disk image
 * @mountpoint:		where to mount the volume on
 * @fs_cipher:		cipher used for filesystem, if any. (cryptsetup name)
 * @fs_hash:		hash used for filesystem, if any. (cryptsetup name)
 * @key_data:		key material/password
 * @key_size:		size of key data, in bytes
 * @trunc_keysize:	extra cryptsetup instruction for truncation (in bytes)
 * @readonly:		whether to create a readonly vfsmount
 */
struct ehd_mount_request {
	char *container, *mountpoint;
	char *fs_cipher, *fs_hash;
	void *key_data;
	unsigned int key_size, trunc_keysize;
	bool readonly;
};

struct ehd_crypto_ops {
	int (*load)(const struct ehd_mount_request *, struct ehd_mount_info *);
	int (*unload)(const struct ehd_mount_info *);
};

extern const struct ehd_crypto_ops ehd_cgd_ops;
extern const struct ehd_crypto_ops ehd_dmcrypt_ops;

#endif /* _CMT_INTERNAL_H */
