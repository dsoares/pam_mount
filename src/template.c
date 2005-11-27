/*=============================================================================
template.c
  Copyright (C) W. Michael Putello <new@flyn.org>, 1999
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
#include <config.h>
#include <sys/stat.h>
#include <dirent.h>
#include <glib.h>
#include <libgen.h> // basename()
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
#    include <pwdb/pwdb_public.h>
#else
#    include <pwd.h>
#endif
#include "common.h"
#include "fmt_ptrn.h"
#include "template.h"

static int _at_path(char *);
static void _build_template_dir(char *, const char *, const char *);

/* Globals. */
static char _template_errmsg[BUFSIZ + 1];
static char _template_local_dir[PATH_MAX + 1];
static char _template_global_dir[PATH_MAX + 1];

/* ============================ _build_template_dir () ====================== */
static void _build_template_dir(char *path, const char *dir,
				const char *type)
{
    strcpy(path, dir);
    if(type != NULL) {
	strcat(path, "/");
	strcat(path, type);
    }
    strcat(path, "/");
}

/* ============================ _at_path () ================================= */
static int _at_path(char *template_path) {
/* Make sure template_path is big enough to have .gz added to the end! */
    struct stat stat_buf;
    if(stat(template_path, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode))
	return 1;
    else {
	strcat(template_path, ".gz");
	if(stat(template_path, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode))
	    return 1;
    }
    return 0;
}

/* ============================ template_find () ============================ */
int template_find(char *template_path, /*const char *filename,*/
		  const char *type, const char *template_name,
		  const int use_global)
{
    if (!use_global) {
	/* Try $HOME/.new/templates first. */
	_build_template_dir(template_path, _template_local_dir, type);
	strcat(template_path, template_name);
    }
    if((!use_global && !_at_path(template_path))
	|| use_global) {
	_build_template_dir(template_path, _template_global_dir, type);
	strcat(template_path, template_name);
    }
    if (!_at_path(template_path)) {
	sprintf(_template_errmsg, "no template for type %s", type);
	return 0;
    }
    return 1;
}
