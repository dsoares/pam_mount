/*=============================================================================
modifiers.c
  Copyright (C) W. Michael Putello <mike@flyn.org>, 1999 - 2001
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
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "buffer.h"
#include "modifiers.h"
#include "fmt_ptrn.h"
#include "template.h"

static int _apply_comment(struct buffer *, char *, char *);
static int _apply_delim(struct buffer *, const char *, const char *);
static int apply_after(struct buffer *, struct fmt_ptrn *, char *);
static int apply_basename(struct buffer *, struct fmt_ptrn *, char *);
static int apply_before(struct buffer *, struct fmt_ptrn *, char *);
static int apply_c_comment(struct buffer *, struct fmt_ptrn *, char *);
static int apply_c_delim(struct buffer *, struct fmt_ptrn *, char *);
static int apply_cpp_comment(struct buffer *, struct fmt_ptrn *, char *);
static int apply_cpp_delim(struct buffer *, struct fmt_ptrn *, char *);
static int apply_file(struct buffer *, struct fmt_ptrn *, char *);
static int apply_fn(struct buffer *, struct fmt_ptrn *, char *);
static int apply_lower(struct buffer *, struct fmt_ptrn *, char *);
static int apply_newlines(struct buffer *, struct fmt_ptrn *, char *);
static int apply_no_newlines(struct buffer *, struct fmt_ptrn *, char *);
static int apply_remove_underscore(struct buffer *, struct fmt_ptrn *, char *);
static int apply_sh_comment(struct buffer *, struct fmt_ptrn *, char *);
static int apply_sh_delim(struct buffer *, struct fmt_ptrn *, char *);
static int apply_template(struct buffer *, struct fmt_ptrn *, char *);
static int apply_tex_comment(struct buffer *, struct fmt_ptrn *, char *);
static int apply_tex_delim(struct buffer *, struct fmt_ptrn *, char *);
static int apply_upper(struct buffer *, struct fmt_ptrn *, char *);
static int apply_xml_comment(struct buffer *, struct fmt_ptrn *, char *);

const struct modifier_info mod_fn[] = {
    {"upper", apply_upper, 0},
    {"lower", apply_lower, 0},
    {"basename", apply_basename, 0},
    {"before=\"", apply_before, 1},
    {"after=\"", apply_after, 1},
    {"fn", apply_fn, 0},
    {"c_delim", apply_c_delim, 0},
    {"cpp_delim", apply_cpp_delim, 0},
    {"sh_delim", apply_sh_delim, 0},
    {"tex_delim", apply_tex_delim, 0},
    {"c_comment", apply_c_comment, 0},
    {"cpp_comment", apply_cpp_comment, 0},
    {"sh_comment", apply_sh_comment, 0},
    {"tex_comment", apply_tex_comment, 0},
    {"xml_comment", apply_xml_comment, 0},
    {"sgml_comment", apply_xml_comment, 0},
    {"newlines", apply_newlines, 0},
    {"no_newlines", apply_no_newlines, 0},
    {"template", apply_template, 0},
    {"file", apply_file, 0},
    {"#", NULL, 0},		/* FIXME: This is handled as a special case. */
    {"remove_underscore", apply_remove_underscore, 0},
    {NULL, NULL, 0},
};

//-----------------------------------------------------------------------------
static int apply_upper(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    char *newdata = g_ascii_strup(dest->data, -1);
    free(dest->data);
    dest->data = newdata;
    return 1;
}

static int apply_lower(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    char *newdata = g_ascii_strdown(dest->data, -1);
    free(dest->data);
    dest->data = newdata;
    return 1;
}

static int apply_basename(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    char *ptr = strchr(dest->data, '.');
    if(ptr != NULL)
	*ptr = '\0';
    return 1;
}

static int _apply_delim(struct buffer *str, const char *start_cmnt,
 const char *end_cmnt)
{
    /* This one is a bit ugly, but not very interesting. */
    int i;
    char ptr[81];
    size_t start_cmnt_len = strlen(start_cmnt) + 1;	/* + 1 for ' '. */
    size_t end_cmnt_len = (end_cmnt != NULL) ? strlen(end_cmnt) + 1 : 0;
    size_t len;
    if(str->size < sizeof(ptr)) {
        /* FIXME: use proper buffer interfaces */
	str->data = g_realloc(str->data, 81);
	str->size = sizeof(ptr);
    }
    strcpy(ptr, start_cmnt);
    strcat(ptr, " ");
    for(i = 0; i < 31 - start_cmnt_len - 2; i++)	/* - 2 for spaces. */
	strcat(ptr, "=");
    strcat(ptr, " ");
    len = strlen(ptr);
    strncat(ptr, str->data, sizeof(ptr) - 1 - len - 2 - end_cmnt_len);	/* - 2 for spaces. */
    strcat(ptr, " ");
    len = strlen(ptr);
    for(i = 0; i < sizeof(ptr) - 1 - len - end_cmnt_len; i++)
	strcat(ptr, "=");
    strcat(ptr, (end_cmnt != NULL) ? " " : "");
    strcat(ptr, (end_cmnt != NULL) ? end_cmnt : "");
    strcpy(str->data, ptr);
    return 1;
}

static int apply_c_delim(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    _apply_delim(dest, "/*", "*/");
    return 1;
}

static int apply_cpp_delim(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    _apply_delim(dest, "//", NULL);
    return 1;
}

static int apply_sh_delim(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    _apply_delim(dest, "#", NULL);
    return 1;
}

static int apply_tex_delim(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    _apply_delim(dest, "%", NULL);
    return 1;
}

static int _apply_comment(struct buffer *dest, char *c0, char *c1) {
    int i;
    struct buffer tmp;

    buffer_init(&tmp);
    realloc_n_cat(&tmp, c0);

    for (i = 0; i < strlen(dest->data); i++) {
	if (dest->data[i] == '\n' && c1)
	    realloc_n_cat(&tmp, c1);
	realloc_n_ncat(&tmp, dest->data + i, 1);
	if (dest->data[i] == '\n' && i < strlen(dest->data) - 1)
	    realloc_n_cat(&tmp, c0);
    }

    realloc_n_cpy(dest, tmp.data);
    buffer_clear(&tmp);
    return 1;
}

static int apply_c_comment(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    return _apply_comment(dest, "/* ", " */");
}

static int apply_xml_comment(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    return _apply_comment(dest, "<!-- ", " -->");
}

static int apply_sh_comment(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    return _apply_comment(dest, "# ", NULL);
}

static int apply_cpp_comment(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    return _apply_comment(dest, "// ", NULL);
}

static int apply_tex_comment(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    return _apply_comment(dest, "% ", NULL);
}

static int apply_before(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    /* Done with no malloc'd tmp. */
    size_t i, j, old_len = strlen(dest->data), src_len =
	strlen(arg), new_len = old_len + src_len;
    /* FIXME: use proper buffer interface! */
    if (new_len + 1 > dest->size) {
	dest->size = new_len + 1;
	dest->data = g_realloc(dest->data, dest->size);
    }
    /* Shift dest over to make room for arg. */
    if (old_len > 0)
    /* i is unsigned, so i = old_len - 1 makes no sense if old_len == 0 */
        for (i = old_len - 1, j = new_len - 1; i > 0; i--, j--)
	    dest->data[j] = dest->data[i];
    dest->data[src_len] = dest->data[0];
    dest->data[new_len] = '\0';
    /* Copy arg into dest. */
    for (i = 0; i < src_len; i++)
	dest->data[i] = arg[i];
    return 1;
}

static int apply_no_newlines(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == '\n')
	    dest->data[i] = ' ';
    return 1;
}

static int apply_newlines(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == ' ')
	    dest->data[i] = '\n';
    return 1;
}

static int apply_remove_underscore(struct buffer *dest, struct fmt_ptrn *x,
 char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == '_')
	    dest->data[i] = '-';
    return 1;
}

static int apply_after(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    /* Too easy. */
    realloc_n_cat(dest, arg);
    return 1;
}

static int apply_fn(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
    apply_after(dest, x, " ()");
    return 1;
}

static int apply_file(struct buffer *dest, struct fmt_ptrn *x,
 /* const */ char *arg)
{
/* This function handles the case where the FMT_PTRN_FILE modifier is 
 * used. 
 */
    char b[BUFSIZ];
    gzFile f;
    if((f = gzopen(dest->data, "rb")) == NULL)
	return 0;
    realloc_n_cpy(dest, "");
    while(gzgets(f, b, sizeof(b)) != Z_NULL)
	realloc_n_cat(dest, b);
    gzclose(f);
    return 1;
}

static int apply_template(struct buffer *dest, struct fmt_ptrn *x, char *arg) {
/* This function handles the case where the FMT_PTRN_TEMPLATE modifier is 
 * used. 
 */
    struct fmt_ptrn f;
    char b[BUFSIZ];
    char template_path[PATH_MAX + 1];
    if (!fmt_ptrn_open(dest->data, &f)) {
	if (!template_find(template_path, "", dest->data, 0)) {
	    enqueue_parse_errmsg(x, "%s: %ld: template %s does not exist",
				 x->template_path, x->line_num,
				 dest->data);
	    return 0;
	} else
	    fmt_ptrn_open(template_path, &f);
    }
    f.fillers = x->fillers;
    realloc_n_cpy(dest, "");
    while(fmt_ptrn_gets(b, sizeof(b), &f) != NULL)
	realloc_n_cat(dest, b);
    while (fmt_ptrn_parse_err(&f))
	/* Copy parse error messages into the main struct fmt_ptrn
        data structure. */
	enqueue_parse_errmsg(x, fmt_ptrn_parse_strerror(&f));
    /* Avoid freeing the stolen fillers: */
    /* FIXME: need to port to glib:
    f.fillers.size = 0;		
    f.fillers.root = NULL;
    */
    fmt_ptrn_close(&f);
    return 1;
}
