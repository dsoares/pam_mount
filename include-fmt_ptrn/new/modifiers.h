/*   FILE: modifiers.h -- 
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 26 December 2001
 */

#ifndef _MODIFIERS_H
#define _MODIFIERS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================ modifier_fns_t ============================= */
typedef struct modifier_fns_t {
    char *id;
    int (*fn) (buffer_t * str, fmt_ptrn_t * x, char *arg);
    int has_arg;
} modifier_fns_t;

/* ============================ modifier_t ================================= */
typedef struct modifier_t {
    modifier_fns_t fn;
    char arg[MODIFIER_ARG_LEN + 1];
} modifier_t;

/* ============================ apply_upper () ============================= */
int apply_upper(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_lower () ============================= */
int apply_lower(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_basename () ========================== */ 
int apply_basename(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_c_delim () =========================== */
int apply_c_delim(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_cpp_delim () ========================= */
int apply_cpp_delim(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_sh_delim () ========================== */
int apply_sh_delim(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_tex_delim () ========================= */
int apply_tex_delim(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_c_comment () ========================= */
int apply_c_comment(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_cpp_comment () ======================= */
int apply_cpp_comment(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_sh_comment () ======================== */
int apply_sh_comment(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_tex_comment () ======================= */
int apply_tex_comment(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_xml_comment () ======================= */
int apply_xml_comment(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_before () ============================ */
int apply_before(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_no_newlines () ======================= */
int apply_no_newlines(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_newlines () ========================== */
int apply_newlines(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_remove_underscore () ================= */
int apply_remove_underscore(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_after () ============================= */
int apply_after(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_fn () ================================ */
int apply_fn (buffer_t *dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_file () ============================== */
int apply_file(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ apply_template () ========================== */
int apply_template(buffer_t * dest, fmt_ptrn_t *x, char *arg);

/* ============================ modifier_fn ================================ */
/* If you wish to add a modifier, create an appropriate function and
 * update this structure.  The functions themselves go in modifiers.c.
 */
const modifier_fns_t mod_fn[] = {
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

#ifdef __cplusplus
}
#endif
#endif				/* _MODIFIERS_H */
