/*
 *	Copyright © Jan Engelhardt, 2007 - 2008
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#include "config.h"
#if !defined(HAVE_GETMNTENT) && defined(HAVE_GETMNTINFO) /* entire file */

#ifdef HAVE_SYS_MOUNT_H
#	include <sys/mount.h>
#endif
#ifdef HAVE_SYS_STATVFS_H
#	include <sys/statvfs.h>
#endif
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <libHX/string.h>
#include "pam_mount.h"

#if defined(__FreeBSD__)
#	define local_statfs statfs
#	define LOCAL_NOWAIT MNT_NOWAIT
#elif defined(__NetBSD__)
#	define local_statfs statvfs
#	define LOCAL_NOWAIT ST_NOWAIT
#endif

#endif /* !HAVE_GETMNTENT && HAVE_GETMNTINFO */
