#ifndef _CMT_INTERNAL_H
#define _CMT_INTERNAL_H 1

struct ehd_mount_request;
struct ehd_mount;

struct ehd_crypto_ops {
	int (*load)(const struct ehd_mount_request *, struct ehd_mount *);
	int (*unload)(const struct ehd_mount *);
};

#endif /* _CMT_INTERNAL_H */
