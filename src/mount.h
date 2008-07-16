#ifndef PMT_MOUNT_H
#define PMT_MONUT_H 1

#include <stdbool.h>

struct config;
struct HXbtree;

typedef int (mount_op_fn_t)(const struct config *, struct vol *,
	struct HXbtree *, const char *);

/*
 *	MOUNT.C
 */
extern mount_op_fn_t do_mount, do_unmount;
extern int mount_op(mount_op_fn_t *, const struct config *, struct vol *,
	const char *);
extern void umount_final(struct config *);

#endif /* PMT_MOUNT_H */
