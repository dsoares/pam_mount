/*=============================================================================
private.h
  Copyright © Jan Engelhardt <jengelh [at] linux01 gwdg de>, 2005

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to:
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
  Boston, MA  02110-1301  USA

  -- For details, see the file named "LICENSE.LGPL2"
=============================================================================*/
#ifndef PMT_PRIVATE_H
#define PMT_PRIVATE_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "optlist.h"

#define CLOSE(a) if(close(a) == -1) { \
    l0g("pam_mount: could not close fd: %s\n", strerror(errno)); \
    l0g("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
}
#define MAX_PAR 127
#define PMPREFIX "pam_mount: "

typedef enum command_type_t {
    SMBMOUNT,
    SMBUMOUNT,
    CIFSMOUNT,
    NCPMOUNT,
    NCPUMOUNT,
    LCLMOUNT,
    CRYPTMOUNT, // FIXME: hope to have this in util-linux (LCLMOUNT) some day
    NFSMOUNT,
    UMOUNT,
    PMHELPER,
    LSOF,
    MNTAGAIN,
    MNTCHECK,
    FSCK,
    LOSETUP,
    UNLOSETUP,
    PMVARRUN,
    COMMAND_MAX,
} command_type_t;

typedef enum auth_type_t {
    GET_PASS,
    USE_FIRST_PASS,
    TRY_FIRST_PASS
} auth_type_t;

typedef struct pam_args_t {
    auth_type_t auth_type;
} pam_args_t;

typedef struct pm_command_t {
    command_type_t type;
    char *fs;
    char *command_name;
    char *def[MAX_PAR + 1];
} pm_command_t;

typedef struct vol_t {
    command_type_t type;
    gboolean globalconf;        // TRUE if config. from global config, FALSE if luserconf
    gboolean created_mntpt;     // set so umount knows to rm it
    char fs_key_cipher[MAX_PAR + 1];
    char fs_key_path[PATH_MAX + 1];
    char server[MAX_PAR + 1];
    char user[MAX_PAR + 1];     // user field in a single volume config record; can be "*"
    char fstype[MAX_PAR + 1];
    char volume[MAX_PAR + 1];   // FIXME: PATH_MAX
    optlist_t *options;         // may be NULL if no options
    char mountpoint[PATH_MAX + 1];
    gboolean use_fstab;
    gboolean used_wildcard;
} vol_t;

typedef struct config_t {
    char *user;	/* user logging in */
    gboolean debug;
    gboolean mkmntpoint;
    unsigned int volcount;
    char luserconf[PATH_MAX + 1];
    char fsckloop[PATH_MAX + 1];
    char *command[MAX_PAR + 1][COMMAND_MAX];
    optlist_t *options_require;
    optlist_t *options_allow;
    optlist_t *options_deny;
    vol_t *volume;
} config_t;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_PRIVATE_H

//=============================================================================
