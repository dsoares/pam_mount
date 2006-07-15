/*=============================================================================
misc.h
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
#ifndef PMT_MISC_H
#define PMT_MISC_H 1

#include <sys/types.h>
#include <glib.h>
#include "fmt_ptrn.h"
#include "private.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void add_to_argv(const char **, int * const, const char * const,
    struct fmt_ptrn *);
extern gboolean config_t_valid(const config_t *);
extern int exists(const char *);
extern void l0g(const char *, ...);
extern void log_argv(const char * const *);
extern gboolean owns(const char *, const char *);
extern char *relookup_user(const char *);
extern void set_myuid(void *);
extern gboolean static_string_valid(const char *, const size_t);
extern long str_to_long(const char *);
extern gboolean vol_t_valid(const struct vol *);
extern void w4rn(const char *, ...);

static inline int pm_command_t_valid(const config_t *x) { return TRUE; }

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MISC_H

//=============================================================================
