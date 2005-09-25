/*   FILE: common.c -- 
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 01 MAY 1 999
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
#include <new/template.h>
#include <glib.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <config.h>
#include <sys/stat.h>
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
#include <pwdb/pwdb_public.h>
#else
#include <pwd.h>
#endif				/* HAVE_PWDB_PWDB_PUBLIC_H */

static char *_firstname(void);
static void shift_str(char *, char *);
static char *_middlename(void);
static char *_lastname(void);

/* FIXME: the code in these functions needs to be checked for:
 * 1.  a consistent interface for memory management
 * 2.  memory leaks
 * 3.  use of g_free/g_strdup/etc. instead of free/strdup/etc.
 * 4.  does (ie) g_get_real_name() ever return NULL and is this a problem
 *     for g_strdup?
 */

/* ============================ firstname () ================================ */
static char *_firstname(void)
{
	char *name, *ptr;
	if (! (name = g_strdup(g_get_real_name())))
		return NULL;
	ptr = strchr(name, ' ');
	if (ptr)
		*ptr = '\0';
	return name;
}

/* ============================ shift_str () =============================== */
static void shift_str (char *ptr_0, char *ptr_1)
{
    while (*ptr_1)
        *ptr_0++ = *ptr_1++;
    *ptr_0 = '\0';
}

/* ============================ middlename () =============================== */
static char *_middlename(void)
{
	char *name, *ptr_0, *ptr_1;
	if (! (name = g_strdup(g_get_real_name())))
		return NULL;
	ptr_0 = strchr (name, ' ');
	if (! ptr_0)
		return NULL;
	ptr_1 = strchr (++ptr_0, ' ');	
	if (! ptr_1)
		return NULL;
	*ptr_1 = '\0';
	shift_str (name, ptr_0);
        return name;
}

/* ============================ lastname () =============================== */
static char *_lastname(void)
{
	char *name, *ptr_0, *ptr_1;
	if (! (name = g_strdup(g_get_real_name())))
		return NULL;
	ptr_0 = strchr (name, ' ');
	if (! ptr_0)
		return NULL;
	ptr_1 = strchr (++ptr_0, ' ');	
	if (! ptr_1)
		return ptr_0;
	shift_str (name, ++ptr_1);
	return name;
}

/* ============================ homedir () ================================== */
char *homedir(char *homedir)
{
    char *hd = g_strdup(g_get_home_dir());
    g_strlcpy(homedir, (hd != NULL) ? hd : "", BUFSIZ + 1);
    g_free(hd);
    return (hd != NULL) ? homedir : NULL;
}

/* ============================ day () ====================================== */
char *day(char *d)
/* Make sure d is at least large enough to hold "10". */
{
    time_t sec_since_1970;
    struct tm *curr_time;
    *d = '\0';
    time(&sec_since_1970);
    curr_time = localtime(&sec_since_1970);
    strftime(d, 3, "%d", curr_time);
    return d;
}

/* ============================ month () ==================================== */
char *month(char *m)
/* Make sure m is at least large enough to hold "September". */
{
    time_t sec_since_1970;
    struct tm *curr_time;
    *m = '\0';
    time(&sec_since_1970);
    curr_time = localtime(&sec_since_1970);
    strftime(m, 10, "%B", curr_time);
    return m;
}

/* ============================ year () ===================================== */
char *year(char *y)
/* Make sure y is at least large enough to hold "1999". */
{
    time_t sec_since_1970;
    struct tm *curr_time;
    *y = '\0';
    time(&sec_since_1970);
    curr_time = localtime(&sec_since_1970);
    strftime(y, 18, "%Y", curr_time);
    return y;
}

/* ============================ print_dir () ================================ */
void print_dir(DIR * dp)
{
    struct dirent *ent;
    while ((ent = readdir(dp))) {
	if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
	    continue;
	printf("  %s\n", ent->d_name);
    }
}

/* ============================= initialize_fillers_from_file () ============ */
void initialize_fillers_from_file(fmt_ptrn_t *x, char *path)
{
    char line[PATH_MAX + 1], *key, *value, *ptr;
    FILE *input = fopen (path, "r");
    ptr = line;
    while (fgets(ptr, PATH_MAX + 1, input)) {
        key = strsep(&ptr, "=");
	value = ptr;
        fmt_ptrn_update_kv(x, g_strdup(key), g_strdup(value));
    }
}

/* ============================= initialize_fillers () ====================== */
void initialize_fillers(fmt_ptrn_t *x)
{
    int i;
    char b[BUFSIZ + 1], *key, *val;
    for(i = 0; environ[i] != NULL; i++)
        if (parse_kv (environ[i], &key, &val))
	    fmt_ptrn_update_kv(x, key, val);
    fmt_ptrn_update_kv(x, g_strdup("DAY"), g_strdup(day(b)));
    fmt_ptrn_update_kv(x, g_strdup("MONTH"), g_strdup(month(b)));
    fmt_ptrn_update_kv(x, g_strdup("YEAR"), g_strdup(year(b)));
    fmt_ptrn_update_kv(x, g_strdup("FULLNAME"), g_strdup(g_get_real_name()));
    fmt_ptrn_update_kv(x, g_strdup("FIRSTNAME"), _firstname());
    fmt_ptrn_update_kv(x, g_strdup("MIDDLENAME"), _middlename());
    fmt_ptrn_update_kv(x, g_strdup("LASTNAME"), _lastname());
    fmt_ptrn_update_kv(x, g_strdup("EMPTY_STR"), g_strdup(""));
}

/* ============================ parse_kv () ================================ */ 
int parse_kv (char *str, char **key, char **val)
{
	/* FIXME: what if NULL pops up? */
        *key = strdup(strsep(&str, "="));
	*val = strdup((str != NULL) ? str : "");
	/* FIXME: *(val - 1) = '='; /* FIXME: Restore original string. */
	return 1;
}
