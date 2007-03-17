/*=============================================================================
misc.h
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2007

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
#ifndef PMT_MISC_H
#define PMT_MISC_H 1

#include <sys/types.h>
#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __STRINGIFY_EXPAND(s) #s
#define __STRINGIFY(s)        __STRINGIFY_EXPAND(s)

struct config;
struct vol;

/*
 *      MISC.C
 */
#define PMPREFIX       "pam_mount(" __FILE__ ":" __STRINGIFY(__LINE__) ") "
#define l0g(fmt, ...)  misc_log((PMPREFIX fmt), ## __VA_ARGS__)
#define w4rn(fmt, ...) misc_warn((PMPREFIX fmt), ## __VA_ARGS__)

extern void add_to_argv(const char **, int * const, const char * const,
    struct HXbtree *);
extern int config_valid(const struct config *);
extern int exists(const char *);
extern void log_argv(const char * const *);
extern void misc_add_ntdom(struct HXbtree *, const char *);
extern void misc_log(const char *, ...);
extern void misc_warn(const char *, ...);
extern int owns(const char *, const char *);
extern char *relookup_user(const char *);
extern void set_myuid(void *);
extern long str_to_long(const char *);
extern int vol_valid(const struct vol *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MISC_H

//=============================================================================
