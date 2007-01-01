/*=============================================================================
spawn.h
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
#ifndef PMT_SPAWN_H
#define PMT_SPAWN_H 1

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *      SPAWN.C
 */
extern int spawn_apS(const char *, const char *const *, const char *const *,
    GSpawnFlags, GSpawnChildSetupFunc, void *, int *, int *, int *, int *,
    GError **);
extern int spawn_restore_sigchld(void);
extern int spawn_set_sigchld(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_SPAWN_H

//=============================================================================
