/*   FILE: fmt_ptrn.h -- 
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 08 January 2000
 */

#ifndef _FMT_PTRN_H
#define _FMT_PTRN_H

#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h> /* For BUFSIZ. */
#include <zlib.h>
#include <limits.h>
#include <stdlib.h>
#include <glib.h>
#include <new/pair.h>
#include <new/buffer.h>

/* ============================ fmt_ptrn_t ================================= */
    typedef struct fmt_ptrn_t {
	gzFile template_fp;
	char template_path[PATH_MAX + 1];
	long line_num;
	buffer_t raw_buf; /* Buffer for unfilled data. */
	buffer_t filled_buf; /* Buffer for filled data. */
	buffer_t lookup_buf; /* Lookup buffer; here so it is persistent. */
	char errmsg[BUFSIZ + 1]; /* General errors. */
	GQueue *parse_errmsg; /* Parse errors. */
	GTree *fillers; /* Format pattern / value pairs. */
    } fmt_ptrn_t;

/* ============================ fmt_ptrn_open () =========================== */
/* Open the template at path and prepare to fill it. */
    int fmt_ptrn_open(const char *path, fmt_ptrn_t *x);

/* ============================ fmt_ptrn_init () =========================== */
/* Similar to fmt_ptrn_open but does not open a template file.  call this 
 * before fmt_ptrn_filled to fill a string. 
 */
    int fmt_ptrn_init(fmt_ptrn_t *x);

/* ============================ fmt_ptrn_gets () =========================== */
/* Read a filled line from a template. */
    char *fmt_ptrn_gets(char *buf, size_t size, fmt_ptrn_t *x);

/* ============================ fmt_ptrn_close () ========================== */
/* Close a template. */
    int fmt_ptrn_close(fmt_ptrn_t *x);

/* ============================ fmt_ptrn_update_kv_p () ==================== */
/* Add a key / value mapping for use in filling format patterns. */
    void fmt_ptrn_update_kv_p(fmt_ptrn_t *x, const pair_t *p);

/* ============================ fmt_ptrn_update_kv ()======================= */
/* Add a key / value mapping for use in filling format patterns. */
    void fmt_ptrn_update_kv(fmt_ptrn_t *x, const char *key, const char *val);

/* ============================ fmt_ptrn_filled () ========================= */
/* Takes a string, p, and returns p with its format patterns filled. */
    char *fmt_ptrn_filled(fmt_ptrn_t *x, const char *p);

/* ============================ fmt_ptrn_parse_err () ====================== */
/* Returns true if a parse error has occured while processing. */
    gboolean fmt_ptrn_parse_err(const fmt_ptrn_t *x);

/* ============================ fmt_ptrn_parse_strerror () ================= */
/* Dequeues and returns a parse error. */
    char *fmt_ptrn_parse_strerror(fmt_ptrn_t *x);

/* ============================= fmt_ptrn_parse_perror () ================== */
/* Prints the last parse error. */
    void fmt_ptrn_parse_perror(fmt_ptrn_t *x, const char *msg);

/* ============================ fmt_ptrn_perror () ========================= */
/* Prints the last non-parse error. */
    void fmt_ptrn_perror(const fmt_ptrn_t *x, const char *msg);

/* ============================ fmt_ptrn_strerror () ======================= */
/* Returns the last non-parse error. */
    const char *fmt_ptrn_strerror(const fmt_ptrn_t *x);

/* ============================ fmt_ptrn_t_valid () ======================== */
    gboolean fmt_ptrn_t_valid(const fmt_ptrn_t *x);

#ifdef __cplusplus
}
#endif
#endif				/* _FMT_PTRN_H */
