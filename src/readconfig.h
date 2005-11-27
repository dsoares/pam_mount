/*=============================================================================
readconfig.h
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
#ifndef PMT_READCONFIG_H
#define PMT_READCONFIG_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include "dotconf.h"
#include "private.h"

extern int expandconfig(const config_t *);
extern void freeconfig(config_t *);
extern int initconfig(config_t *);
extern gboolean luserconf_volume_record_sane(const config_t *, int);
extern int readconfig(const char *, const char *, int, config_t *);
extern DOTCONF_CB(read_volume);
extern gboolean volume_record_sane(const config_t *, int);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_READCONFIG_H

//=============================================================================
