/*   FILE: template.h -- 
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

#ifndef TEMPLATE_H
#define TEMPLATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

/* ============================= template_init () =========================== *//* Initializes the template library. */
   void template_init(void);

/* ============================= template_set_global_dir () ================= */
/* Set the global template directory -- takes a full path. */
    int template_set_global_dir(const char *path);

/* ============================= template_set_local_dir () ================== */
/* Set the local template directory -- takes a directory to concatenate onto 
 * the user's home directory.
 */
    int template_set_local_dir(const char *dir);

/* ============================ template_set_type () ======================= */ 
/* Set the file's type.  Returns 1 if the type can be determined. */
int template_set_type(char *type, const char *filename); 

/* ============================ template_find () ============================ */
int template_find(char *template_path, /*const char *filename,*/ const char *type,
			  const char *template_name, const int use_global);

/* ============================= template_list () =========================== */
/* Prints the templates associated with the given type of file.  Returns 0 in 
 * the case of an error.
 */
 int template_list(const char *type);

/* ============================ template_write_it_using_map () ============== */
int template_write_it_using_map (const char *filepath, const int force, const char *template_path, GList *map, char *mapping_file);

/* ============================= template_perror () ========================= */
/* Prints the last non-parse error. */
    void template_perror(const char *msg);

/* ============================= template_strerror () ======================= */
/* Returns the last non-parse error. */
    char *template_strerror(void);

/* ============================= template_destroy () ======================== */
/* Releases the resources associated with the template library. */
    void template_destroy(void);

#ifdef __cplusplus
}
#endif
#endif				/* TEMPLATE_H */
