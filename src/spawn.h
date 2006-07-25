/*=============================================================================
spawn.h
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
#ifndef PMT_SPAWN_H
#define PMT_SPAWN_H 1

#include <glib.h>
#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *      SPAWN.C
 */
extern int spawn_set_sigchld(void);
extern int spawn_restore_sigchld(void);

/*
 *      INLINE FUNCTIONS
 */
static inline gboolean spawn_ap0(const char *wd, const char *const *argv,
 const char *const *envp, GSpawnFlags flags, GSpawnChildSetupFunc cs,
 void *data, int *pid, int *istdin, int *istdout, int *istderr, GError **err)
{
    return g_spawn_async_with_pipes(wd, const_cast(char **, argv),
           const_cast(char **, envp), flags, cs, data, pid, istdin,
           istdout, istderr, err);
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_SPAWN_H

//=============================================================================
