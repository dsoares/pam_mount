/*   FILE: pam_mount_private.h
 * AUTHOR: W. Michael Petullo <mike@flyn.org>
 *   DATE: 2005
 *
 * Copyright (C) 2005 W. Michael Petullo <mike@flyn.org>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PAM_MOUNT_PRIVATE_H
#define _PAM_MOUNT_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

int option_in_list(optlist_t * haystack, const char *needle);
DOTCONF_CB(read_volume);

#ifdef __cplusplus
}
#endif
#endif				/* _PAM_MOUNT_PRIVATE_H */
