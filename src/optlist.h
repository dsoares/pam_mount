/*=============================================================================
optlist.h
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
#ifndef PMT_OPTLIST_H
#define PMT_OPTLIST_H 1

#include <glib.h>
#include "pair.h"

#ifdef __cplusplus
extern "C" {
#endif

#define optlist_next(element)   g_list_next(element)
#define optlist_key(element)    (((struct pair *)(element)->data)->key)
#define optlist_val(element)    (((struct pair *)(element)->data)->val)
#define optlist_len(list)       g_list_length(list)

typedef GList optlist_t;

extern gboolean optlist_exists(optlist_t *, const char *);
extern char *optlist_to_str(char *, const optlist_t *);
extern const char *optlist_value(optlist_t *, const char *);
extern gboolean str_to_optlist(optlist_t **, const char *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_OPTLIST_H

//=============================================================================
