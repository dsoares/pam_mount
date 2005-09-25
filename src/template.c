/*   FILE: template.c --
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 01 MAY 1999
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

#include <new/common.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <config.h>
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
#include <pwdb/pwdb_public.h>
#else
#include <pwd.h>
#endif				/* HAVE_PWDB_PWDB_PUBLIC_H */

static void _build_template_dir(char *, const char *, const char *);
static int _at_path(char *);
static int _mk_parent_dirs(const char *);
static int _template_write(fmt_ptrn_t *, FILE *);

/* Globals. */
static char _template_errmsg[BUFSIZ + 1];
static char _template_local_dir[PATH_MAX + 1];
static char _template_global_dir[PATH_MAX + 1];

/* ============================ template_init () ============================ */
void template_init(void)
{
    strcpy(_template_errmsg, "no error");
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
    if (pwdb_start() != PWDB_SUCCESS)
	sprintf(_template_errmsg, "could not start pwdb lib");
#endif
}

/* ============================ template_destroy () ========================= */
void template_destroy(void)
{
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
    pwdb_end();
#endif
}

/* ============================ template_set_type () ======================== */
int template_set_type(char *type, const char *filename)
{
    char *dot = strrchr(filename, '.');
    if(dot != NULL)
	strcpy(type, (dot == filename) ? dot : ++dot);
    return (dot != NULL) ? 1 : 0;
}

/* ============================ template_set_local_dir () =================== */
int template_set_local_dir(const char *d)
{
    const char *dir;
    if((dir = g_get_home_dir()) == NULL) {
	sprintf(_template_errmsg, "could not get homedir");
	return 0;
    }
    strcpy(_template_local_dir, dir);
    strcat(_template_local_dir, "/");
    strcat(_template_local_dir, d);
    return 1;
}

/* ============================ template_set_global_dir () ================== */
int template_set_global_dir(const char *path)
{
    strncpy(_template_global_dir, path, sizeof(_template_global_dir));
    return 1;
}

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
static int _at_path(char *template_path)
/* Make sure template_path is big enough to have .gz added to the end! */
{
    struct stat stat_buf;
    if (stat(template_path, &stat_buf) != -1 && S_ISREG(stat_buf.st_mode))
	return 1;
    else {
	strcat(template_path, ".gz");
	if (stat(template_path, &stat_buf) != -1 && S_ISREG(stat_buf.st_mode))
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

/* ============================ template_list () ============================ */
int template_list(const char *type)
{
    char template_path[PATH_MAX + 1];
    DIR *dp;
    printf("Personal templates for file type .%s:\n", type);
    /* Try $HOME/.new/templates first. */
    _build_template_dir(template_path, _template_local_dir, type);
    if((dp = opendir(template_path)) == NULL)
	printf("  <none>\n");
    else
	print_dir(dp);
    closedir(dp);
    printf("\nGlobal templates for file type .%s:\n", type);
    /* Try global location. */
    _build_template_dir(template_path, _template_global_dir, type);
    if((dp = opendir(template_path)) == NULL)
	printf("  <none>\n");
    else
	print_dir(dp);
    closedir(dp);
    return 1;
}

/* ============================ _mk_parent_dirs () ========================= */
static int _mk_parent_dirs(const char *path)
{
    char path_copy[PATH_MAX + 1], *delim, *ptr;
    struct stat stat_buf;
    mode_t mode = 0777;
    ptr = strcpy(path_copy, path);
    while((delim = strchr(ptr, '/')) != NULL) {
	if(strcspn(ptr, "/") == 0) {
	    /* Found leading '/.' */
	    ptr++;
	    continue;
	}
	*delim = '\0';
	ptr = delim + 1;
	if (stat(path_copy, &stat_buf) == -1)
	    if (mkdir(path_copy, mode) < 0)
		return 0;
	*delim = '/';
    }
    return 1;
}

/* ============================ _template_write () ========================== */
static int _template_write(fmt_ptrn_t * template, FILE * output_file)
{
    char b[BUFSIZ];
    while(fmt_ptrn_gets(b, sizeof(b), template) != NULL)
	fprintf(output_file, "%s", b);
    return 1;
}

/* ============================ template_write_it_using_map () ============== */
int template_write_it_using_map(const char *filepath, const int force,
				const char *template_path, GList * m, char *mapping_file)
{
    fmt_ptrn_t map;
    struct stat stat_buf;
    FILE *output_file;
    GList *ptr;
    if(strcmp("-", filepath) != 0) {
    if (!force && stat(filepath, &stat_buf) != -1) {
	sprintf(_template_errmsg, "%s exists", filepath);
	return 0;
    }
    if (!_mk_parent_dirs(filepath)) {
	sprintf(_template_errmsg, "could not create parent dirs for %s",
		filepath);
	return 0;
    }
    if((output_file = fopen(filepath, "w")) == NULL) {
	sprintf(_template_errmsg, "could not open %s", filepath);
	return 0;
    }
    } else
        output_file = stdout;
    if (!fmt_ptrn_open(template_path, &map)) {
	sprintf(_template_errmsg, "could not open template %s",
		template_path);
	return 0;
    }
    fmt_ptrn_update_kv(&map, strdup("FILE"), basename(strdup(filepath)));
    initialize_fillers(&map);
    if(strlen(mapping_file) > 0)
        initialize_fillers_from_file(&map, mapping_file);
    for(ptr = m; ptr != NULL; ptr = g_list_next(ptr))
	fmt_ptrn_update_kv_p(&map, ptr->data);
    if (!_template_write(&map, output_file))
	return 0;
    while (fmt_ptrn_parse_err(&map))
        fmt_ptrn_parse_perror (&map, NULL);
    fmt_ptrn_close(&map);
    if (output_file != stdout)
        fclose(output_file);
    return 1;
}

/* ============================ template_perror () ========================== */
void template_perror(const char *msg)
{
    fprintf(stderr, "%s: %s\n", msg, _template_errmsg);
}

/* ============================ template_strerror () ======================== */
char *template_strerror(void)
{
    return _template_errmsg;
}
