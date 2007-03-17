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

#ifdef __cplusplus
extern "C" {
#endif

struct config;
struct vol;

/*
 *      MISC.C
 */
extern void add_to_argv(const char **, int * const, const char * const,
    struct HXbtree *);
extern int config_valid(const struct config *);
extern int exists(const char *);
extern void l0g(const char *, ...);
extern void log_argv(const char * const *);
extern void misc_add_ntdom(struct HXbtree *, const char *);
extern int owns(const char *, const char *);
extern char *relookup_user(const char *);
extern void set_myuid(void *);
extern long str_to_long(const char *);
extern int vol_valid(const struct vol *);
extern void w4rn(const char *, ...);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MISC_H

//=============================================================================
