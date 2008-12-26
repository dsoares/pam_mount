/*
 *	Copyright © Jan Engelhardt, 2007 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include "config.h"
#ifdef HAVE_GETMNTENT
#include <sys/stat.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libHX/arbtree.h>
#include <libHX/string.h>
#include "misc.h"
#include "pam_mount.h"
#include <mntent.h>
#ifdef HAVE_LINUX_MAJOR_H
#	include <linux/major.h>
#else
#	define LOOP_MAJOR 7
#endif
#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
#	include <linux/loop.h>
#endif

int pmt_already_mounted(const struct config *const config,
    const struct vol *vpt, struct HXbtree *vinfo)
{
	hxmc_t *dev;
	char real_mpt[PATH_MAX+1];
	struct mntent *mtab_record;
	bool mounted = false;
	FILE *mtab;

	if ((dev = pmt_vol_to_dev(vpt)) == NULL) {
		l0g("pmt::vol_to_dev: %s\n", strerror(errno));
		return -1;
	}

	if ((mtab = setmntent("/etc/mtab", "r")) == NULL) {
		l0g("could not open /etc/mtab\n");
		HXmc_free(dev);
		return -1;
	}
	if (realpath(vpt->mountpoint, real_mpt) == NULL) {
		w4rn("can't get realpath of volume %s: %s\n",
		     vpt->mountpoint, strerror(errno));
		strncpy(real_mpt, vpt->mountpoint, sizeof_z(real_mpt));
		real_mpt[sizeof_z(real_mpt)] = '\0';
	} else {
		real_mpt[sizeof_z(real_mpt)] = '\0';
		l0g("realpath of volume \"%s\" is \"%s\"\n",
		    vpt->mountpoint, real_mpt);
	}

	w4rn("checking to see if %s is already mounted at %s\n",
	     dev, vpt->mountpoint);

	while ((mtab_record = getmntent(mtab)) != NULL) {
		const char *fsname = mtab_record->mnt_fsname;
		const char *fstype = mtab_record->mnt_type;
		const char *fspt   = mtab_record->mnt_dir;
		int (*xcmp)(const char *, const char *);
#ifdef HAVE_STRUCT_LOOP_INFO64_LO_FILE_NAME
		struct loop_info64 loopdev;
		struct stat statbuf;

		if (stat(fsname, &statbuf) == 0 && S_ISBLK(statbuf.st_mode) &&
		    major(statbuf.st_rdev) == LOOP_MAJOR)
			/*
			 * If /etc/mtab is a link to /proc/mounts then the loop
			 * device instead of the real device will be listed --
			 * resolve it.
			 */
			fsname = loop_file_name(fsname, &loopdev);
#endif

		xcmp = (strcmp(fstype, "smbfs") == 0 ||
		        strcmp(fstype, "cifs") == 0 ||
		        strcmp(fstype, "ncpfs") == 0) ? strcasecmp : strcmp;

		if (xcmp(fsname, dev) == 0 &&
		    (strcmp(fspt, vpt->mountpoint) == 0 ||
		    strcmp(fspt, real_mpt) == 0)) {
			mounted = true;
			break;
		}
	}

	endmntent(mtab);
	HXmc_free(dev);
	return mounted;
}
#endif /* HAVE_GETMNTENT */
