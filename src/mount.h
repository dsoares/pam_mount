#ifndef PMT_MOUNT_H
#define PMT_MONUT_H 1

#include <stdbool.h>
#include "private.h"

typedef int (mount_op_fn_t)(const struct config *, const unsigned int,
	struct HXbtree *, const char *, const bool);

/*
 *	MOUNT.C
 */
extern mount_op_fn_t do_mount, do_unmount;
extern int mount_op(mount_op_fn_t *, const struct config *, const unsigned int,
	const char *, bool);

#endif /* PMT_MOUNT_H */
