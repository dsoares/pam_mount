/*   FILE: common.h -- 
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 16 January 2000
 *
 * Copyright (c) 1999 W. Michael Petullo <new@flyn.org>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _COMMON_H
#define _COMMON_H

#include <dirent.h>
#include <new/fmt_ptrn.h>

extern char **environ;

/* Bit mask values for arguments. */
#define FORCE 0x1		/* Overwrite existing file. */
#define USE_GLOBAL 0x2		/* Ignore local templates. */

#ifdef __cplusplus
extern "C" {
#endif
/* ============================ homedir () ================================== */
//	char *homedir(char *homedir);

/* ============================ print_dir () ================================ */
    void print_dir(DIR * dp);

/* ============================ today () ==================================== */
/* Make sure date is at least large enough to hold "10 September 1999". */
//    char *today(char *date);

/* ============================= initialize_fillers_from_file () ============ */
void initialize_fillers_from_file(fmt_ptrn_t *x, char *path);

/* ============================= initialize_fillers () ====================== */
void initialize_fillers(fmt_ptrn_t *x);

/* ============================ parse_kv () ================================ */ 
//int parse_kv (char *str, char **key, char **val);

#ifdef __cplusplus
}
#endif
#endif				/* _COMMON_H */
