#ifndef _CMT_INTERNAL_H
#define _CMT_INTERNAL_H 1

struct ehd_mount_request;
struct ehd_mount_info;

struct ehd_crypto_ops {
	int (*load)(const struct ehd_mount_request *, struct ehd_mount_info *);
	int (*unload)(const struct ehd_mount_info *);
};

extern const struct ehd_crypto_ops ehd_cgd_ops;
extern const struct ehd_crypto_ops ehd_dmcrypt_ops;

#endif /* _CMT_INTERNAL_H */
