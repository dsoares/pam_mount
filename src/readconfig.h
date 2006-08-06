/*=============================================================================
readconfig.h
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
#ifndef PMT_READCONFIG_H
#define PMT_READCONFIG_H 1

#include "dotconf.h"
#include "xstdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

struct config;

/*
 *      READCONFIG.C
 */
extern int expandconfig(const struct config *);
extern void freeconfig(struct config *);
extern int initconfig(struct config *);
extern bool luserconf_volume_record_sane(const struct config *, int);
extern int readconfig(const char *, const char *, int, struct config *);
extern bool volume_record_sane(const struct config *, int);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_READCONFIG_H

//=============================================================================
