/*
 *	Copyright © Jan Engelhardt, 2007 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include "config.h"
#ifdef HAVE_GETMNTINFO
#include <sys/statvfs.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/string.h>
#include "pam_mount.h"

int pmt_already_mounted(const struct config *config,
    const struct vol *vpt, struct HXbtree *vinfo)
{
	hxmc_t *dev;
	bool mounted = false;
	struct statvfs *mntbuf;
	int num_mounts, i;

	if ((num_mounts = getmntinfo(&mntbuf, ST_NOWAIT)) <= 0) {
		l0g("getmntinfo: %s\n", strerror(errno));
		return -1;
	}

	if ((dev = pmt_vol_to_dev(vpt)) == NULL) {
		l0g("pmt::vol_to_dev: %s\n", strerror(errno));
		return -1;
	}

	for (i = 0; i < num_mounts; ++i) {
		const struct statvfs *mnt = &mntbuf[i];
		int (*xcmp)(const char *, const char *);

		xcmp = (mnt->f_fstypename != NULL &&
		       (strcmp(mnt->f_fstypename, "smbfs") == 0 ||
		       strcmp(mnt->f_fstypename, "cifs") == 0 ||
		       strcmp(mnt->f_fstypename, "ncpfs") == 0)) ?
		       strcasecmp : strcmp;

		/*
		 * FIXME: Does BSD also turn "symlink mountpoints" into "real
		 * mountpoints"?
		 */
		if (xcmp(mnt->f_mntfromname, dev) == 0 &&
		    strcmp(mnt->f_mntonname, vpt->mountpoint) == 0) {
			mounted = 1;
			break;
		}
	}

	HXmc_free(dev);
	return mounted;
}
#endif /* HAVE_GETMNTINFO */
