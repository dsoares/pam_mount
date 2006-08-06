/*=============================================================================
private.h
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2006

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

#include "optlist.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __STRINGIFY_EXPAND(s)   #s
#define __STRINGIFY(s)          __STRINGIFY_EXPAND(s)
#define CLOSE(a) do { if(close(a) == -1) { \
    l0g("pam_mount: could not close fd: %s\n", strerror(errno)); \
    l0g("pam_mount: %s\n", "I don't like failed system calls -- I quit"); \
    exit(EXIT_FAILURE); \
} } while(0)
#define MAX_PAR         127
#define PMPREFIX        "pam_mount(" __FILE__ ":" __STRINGIFY(__LINE__) ") "
#ifndef S_IRUGO
#    define S_IRUGO (S_IRUSR | S_IRGRP | S_IROTH)
#endif
#ifndef S_IRWXU
#    define S_IRWXU (S_IRUSR | S_IWUSR | S_IWOTH)
#endif
#ifndef S_IRXG
#    define S_IRXG (S_IRGRP | S_IXGRP)
#endif
#ifndef S_IRXO
#    define S_IRXO (S_IROTH | S_IXOTH)
#endif

enum command_type {
    SMBMOUNT,
    SMBUMOUNT,
    CIFSMOUNT,
    NCPMOUNT,
    NCPUMOUNT,
    FUSEMOUNT,
    FUSEUMOUNT,
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
};

struct vol {
    enum command_type type;
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
};

struct config {
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
    struct vol *volume;
};

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_PRIVATE_H

//=============================================================================
