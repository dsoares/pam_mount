/*   FILE: modifiers.c --
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 26 December 2001
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

#include <new/fmt_ptrn.h>
#include <new/common.h>
#include <new/buffer.h>
#include <new/template.h>
#include <libgen.h>
#include <ctype.h>
#include <string.h>
#include <glib.h>

extern void enqueue_parse_errmsg(fmt_ptrn_t * x, const char *msg, ...);

/* ============================ apply_upper () ============================= */
int apply_upper(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    g_strup(dest->data);
    return 1;
}

/* ============================ apply_lower () ============================= */
int apply_lower(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    g_strdown(dest->data);
    return 1;
}

/* ============================ apply_basename () ========================== */
int apply_basename(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    char *ptr = strchr(dest->data, '.');
    if (ptr)
	*ptr = 0x00;
    return 1;
}

/* ============================ _apply_delim () ============================ */
static int _apply_delim(buffer_t * str, const char *start_cmnt,
			const char *end_cmnt)
{
    /* This one is a bit ugly, but not very interesting. */
    int i;
    char ptr[81];
    size_t start_cmnt_len = strlen(start_cmnt) + 1;	/* + 1 for ' '. */
    size_t end_cmnt_len = end_cmnt ? strlen(end_cmnt) + 1 : 0;
    size_t len;
    if (str->size < 81) {
        /* FIXME: use proper buffer interfaces */
	str->data = g_realloc(str->data, sizeof(char) * 81);
	str->size = 81;
    }
    strcpy(ptr, start_cmnt);
    strcat(ptr, " ");
    for (i = 0; i < (31 - start_cmnt_len - 2); i++)	/* - 2 for spaces. */
	strcat(ptr, "=");
    strcat(ptr, " ");
    len = strlen(ptr);
    strncat(ptr, str->data, 80 - len - 2 - end_cmnt_len);	/* - 2 for spaces. */
    strcat(ptr, " ");
    len = strlen(ptr);
    for (i = 0; i < (80 - len - end_cmnt_len); i++)
	strcat(ptr, "=");
    strcat(ptr, end_cmnt ? " " : "");
    strcat(ptr, end_cmnt ? end_cmnt : "");
    strcpy(str->data, ptr);
    return 1;
}

/* ============================ apply_c_delim () =========================== */
int apply_c_delim(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    _apply_delim(dest, "/*", "*/");
    return 1;
}

/* ============================ apply_cpp_delim () ========================= */
int apply_cpp_delim(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    _apply_delim(dest, "//", NULL);
    return 1;
}

/* ============================ apply_sh_delim () ========================== */
int apply_sh_delim(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    _apply_delim(dest, "#", NULL);
    return 1;
}

/* ============================ apply_tex_delim () ========================= */
int apply_tex_delim(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    _apply_delim(dest, "%", NULL);
    return 1;
}

/* ============================ _apply_comment () ========================== */
static int _apply_comment(buffer_t * dest, char *c0, char *c1)
{
    int i;
    buffer_t tmp = buffer_init();
    realloc_n_cat(&tmp, c0);
    for (i = 0; i < strlen(dest->data); i++) {
	if (dest->data[i] == '\n' && c1)
	    realloc_n_cat(&tmp, c1);
	realloc_n_ncat(&tmp, dest->data + i, 1);
	if (dest->data[i] == '\n' && i < strlen(dest->data) - 1)
	    realloc_n_cat(&tmp, c0);
    }
    realloc_n_cpy(dest, tmp.data);
    buffer_destroy(tmp);
    return 1;
}

/* ============================ apply_c_comment () ========================= */
int apply_c_comment(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    return _apply_comment(dest, "/* ", " */");
}

/* ============================ apply_xml_comment () ======================= */
int apply_xml_comment(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    return _apply_comment(dest, "<!-- ", " -->");
}

/* ============================ apply_sh_comment () ======================== */
int apply_sh_comment(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    return _apply_comment(dest, "# ", NULL);
}

/* ============================ apply_cpp_comment () ======================= */
int apply_cpp_comment(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    return _apply_comment(dest, "// ", NULL);
}

/* ============================ apply_tex_comment () ======================= */
int apply_tex_comment(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    return _apply_comment(dest, "% ", NULL);
}

/* ============================ apply_before () ============================ */
int apply_before(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    /* Done with no malloc'd tmp. */
    size_t i, j, old_len = strlen(dest->data), src_len =
	strlen(arg), new_len = old_len + src_len;
    /* FIXME: use proper buffer_t interface! */
    if (new_len + 1 > dest->size) {
	dest->size = new_len + 1;
	dest->data = g_realloc(dest->data, sizeof(char) * dest->size);
    }
    /* Shift dest over to make room for arg. */
    if (old_len > 0)
    /* i is unsigned, so i = old_len - 1 makes no sense if old_len == 0 */
        for (i = old_len - 1, j = new_len - 1; i > 0; i--, j--)
	    dest->data[j] = dest->data[i];
    dest->data[src_len] = dest->data[0];
    dest->data[new_len] = 0x00;
    /* Copy arg into dest. */
    for (i = 0; i < src_len; i++)
	dest->data[i] = arg[i];
    return 1;
}

/* ============================ apply_no_newlines () ======================= */
int apply_no_newlines(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == '\n')
	    dest->data[i] = ' ';
    return 1;
}

/* ============================ apply_newlines () ========================== */
int apply_newlines(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == ' ')
	    dest->data[i] = '\n';
    return 1;
}

/* ============================ apply_remove_underscore () ================= */
int apply_remove_underscore(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    int i;
    for (i = 0; i < dest->size; i++)
	if (dest->data[i] == '_')
	    dest->data[i] = '-';
    return 1;
}

/* ============================ apply_after () ============================= */
int apply_after(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    /* Too easy. */
    realloc_n_cat(dest, arg);
    return 1;
}

/* ============================ apply_fn () ================================ */
int apply_fn(buffer_t * dest, fmt_ptrn_t * x, char *arg)
{
    apply_after(dest, x, " ()");
    return 1;
}

/* ============================ apply_file () ============================== */
int apply_file(buffer_t * dest, fmt_ptrn_t * x, const char *arg)
/* This function handles the case where the FMT_PTRN_FILE modifier is 
 * used. 
 */
{
    char b[BUFSIZ];
    gzFile f;
    if (!(f = gzopen(dest->data, "rb")))
	return 0;
    realloc_n_cpy(dest, "");
    while (gzgets(f, b, BUFSIZ) != Z_NULL)
	realloc_n_cat(dest, b);
    gzclose(f);
    return 1;
}

/* ============================ apply_template () ========================== */
int apply_template(buffer_t * dest, fmt_ptrn_t * x, char *arg)
/* This function handles the case where the FMT_PTRN_TEMPLATE modifier is 
 * used. 
 */
{
    fmt_ptrn_t f;
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
    while (fmt_ptrn_gets(b, BUFSIZ, &f))
	realloc_n_cat(dest, b);
    while (fmt_ptrn_parse_err(&f))
	/* Copy parse error messages into the main fmt_ptrn_t data structure. */
	enqueue_parse_errmsg(x, fmt_ptrn_parse_strerror(&f));
    /* FIXME: need to port to glib:
    f.fillers.size = 0;		/* Avoid freeing the stolen fillers. */
    /*
    f.fillers.root = NULL;
    */
    fmt_ptrn_close(&f);
    return 1;
}
