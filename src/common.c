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

#ifdef HAVE_PWDB_PWDB_PUBLIC_H
/* ============================ _get_pwdb_entry () ========================= */
static const struct pwdb_entry *_get_pwdb_entry(const int id, const char *field)
{
    const struct pwdb *p = NULL;
    const struct pwdb_entry *e = NULL;
    pwdb_locate("user", PWDB_DEFAULT, PWDB_NAME_UNKNOWN, id, &p);
    pwdb_get_entry(p, field, &e);
    return e;
}
#endif				/* HAVE_PWDB_PWDB_PUBLIC_H */

/* ============================ fullname () ================================= */
static char *_fullname(char *buf)
{
    char *comma;
    int uid = getuid();
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
    const struct pwdb_entry *e = _get_pwdb_entry(uid, "gecos");
    strncpy(buf, e && e->value ? e->value : "", BUFSIZ);
#else
    struct passwd *p = getpwuid(uid);
    strncpy(buf, p && p->pw_gecos ? p->pw_gecos : "", BUFSIZ);
#endif				/* HAVE_PWDB_PWDB_PUBLIC_H */
    comma = strchr(buf, ',');
    if (comma)
	*comma = 0x00;
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
    return e && e->value ? buf : NULL;
#else
    return p && p->pw_gecos ? buf : NULL;
#endif				/* HAVE_PWDB_PWDB_PUBLIC_H */
}

/* ============================ firstname () ================================ */
static char *_firstname(char *buf)
{
	char *ptr;
	if (! _fullname (buf))
		return NULL;
	ptr = strchr(buf, ' ');
	if (ptr)
		*ptr = 0x00;
	return buf;
}

/* ============================ shift_str () =============================== */ 
static void shift_str (char *ptr_0, char *ptr_1)
{
    while (*ptr_1)
        *ptr_0++ = *ptr_1++;
    *ptr_0 = 0x00;
}

/* ============================ middlename () =============================== */
static char *_middlename(char *buf)
{
	char *ptr_0, *ptr_1;
	if (! _fullname (buf))
		return NULL;
	ptr_0 = strchr (buf, ' ');
	if (! ptr_0)
		return NULL;
	ptr_1 = strchr (++ptr_0, ' ');	
	if (! ptr_1)
		return NULL;
	*ptr_1 = 0x00;
	shift_str (buf, ptr_0);
	return ptr_0;
}

/* ============================ lastname () =============================== */
static char *_lastname(char *buf)
{
	char *ptr_0, *ptr_1;
	if (! _fullname (buf))
		return NULL;
	ptr_0 = strchr (buf, ' ');
	if (! ptr_0)
		return NULL;
	ptr_1 = strchr (++ptr_0, ' ');	
	if (! ptr_1)
		return ptr_0;
	shift_str (buf, ++ptr_1);
	return ptr_1;
}

/* ============================ homedir () ================================== */
char *homedir(char *homedir)
{
    int uid = getuid();
#ifdef HAVE_PWDB_PWDB_PUBLIC_H
    const struct pwdb_entry *e = _get_pwdb_entry(uid, "dir");
    strncpy(homedir, e && e->value ? e->value : "", PATH_MAX);
    return e && e->value ? homedir : NULL;
#else
    struct passwd *p = getpwuid(uid);
    strncpy(homedir, p && p->pw_dir ? p->pw_dir : "", PATH_MAX);
    return p && p->pw_gecos ? homedir : NULL;
#endif				/* HAVE_PWDB */
}

/* ============================ day () ====================================== */
char *day(char *d)
/* Make sure d is at least large enough to hold "10". */
{
    time_t sec_since_1970;
    struct tm *curr_time;
    *d = 0x00;
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
    *m = 0x00;
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
    *y = 0x00;
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
	if (!(strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")))
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
        fmt_ptrn_update_kv(x, strdup(key), strdup(value));
    }
}

/* ============================= initialize_fillers () ====================== */
void initialize_fillers(fmt_ptrn_t *x)
{
    int i;
    char b[BUFSIZ + 1], *key, *val;
    for (i = 0; environ[i] != 0x00; i++)
        if (parse_kv (environ[i], &key, &val))
	    fmt_ptrn_update_kv(x, key, val);
    fmt_ptrn_update_kv(x, strdup("DAY"), strdup(day(b)));
    fmt_ptrn_update_kv(x, strdup("MONTH"), strdup(month(b)));
    fmt_ptrn_update_kv(x, strdup("YEAR"), strdup(year(b)));
    fmt_ptrn_update_kv(x, strdup("FULLNAME"), strdup(_fullname(b)?b:""));
    fmt_ptrn_update_kv(x, strdup("FIRSTNAME"), strdup(_firstname(b)?b:""));
    fmt_ptrn_update_kv(x, strdup("MIDDLENAME"), strdup(_middlename(b)?b:""));
    fmt_ptrn_update_kv(x, strdup("LASTNAME"), strdup(_lastname(b)?b:""));
    fmt_ptrn_update_kv(x, strdup("EMPTY_STR"), strdup(""));
}

/* ============================ parse_kv () ================================ */ 
int parse_kv (char *str, char **key, char **val)
{
	/* FIXME: what if NULL pops up? */
        *key = strdup(strsep(&str, "="));
	*val = strdup(str ? str : "");
	/* FIXME: *(val - 1) = '='; /* FIXME: Restore original string. */
	return 1;
}
