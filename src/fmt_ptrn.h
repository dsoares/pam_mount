/*=============================================================================
fmt_ptrn.h
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
#ifndef PMT_FMT_PTRN_H
#define PMT_FMT_PTRN_H 1

#include <sys/types.h>
#include <limits.h>
#include <glib.h>
#include <stdio.h> // BUFSIZ
#include <zlib.h>
#include "buffer.h"
#include "xstdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pair;

struct fmt_ptrn {
    gzFile template_fp;
    char template_path[PATH_MAX + 1];
    long line_num;
    struct buffer raw_buf;      // Buffer for unfilled data
    struct buffer filled_buf;   // Buffer for filled data
    struct buffer lookup_buf;   // Lookup buffer; here so it is persistent
    char errmsg[BUFSIZ + 1];    // General errors
    GQueue *parse_errmsg;       // Parse errors
    GTree *fillers;             // Format pattern / value pairs
};

/*
 *      FMT_PTRN.C
 */
extern int fmt_ptrn_close(struct fmt_ptrn *);
extern bool fmt_ptrn_parse_err(const struct fmt_ptrn *);
extern void enqueue_parse_errmsg(struct fmt_ptrn *, const char *, ...);

extern char *fmt_ptrn_filled(struct fmt_ptrn *, const char *);
extern int fmt_ptrn_init(struct fmt_ptrn *);
extern bool fmt_ptrn_open(const char *, struct fmt_ptrn *);
extern char *fmt_ptrn_parse_strerror(struct fmt_ptrn *);
extern void fmt_ptrn_update_kv(struct fmt_ptrn *, const char *, const char *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_FMT_PTRN_H

//=============================================================================
