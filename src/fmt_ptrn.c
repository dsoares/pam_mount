/*=============================================================================
fmt_ptrn.c
  Copyright (C) W. Michael Putello <new@flyn.org>, 1999 - 2000
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
#include <assert.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include "buffer.h"
#include "compiler.h"
#include "modifiers.h"
#include "fmt_ptrn.h"
#include "pair.h"
#include "xstdlib.h"

// Definitions
#define KEY_LEN         80
#define PARSE_ERR_LEN   BUFSIZ
#define STACK_MAX_ITEMS 10

struct mystack {
    struct modifier data[STACK_MAX_ITEMS];
    int size;
};

// Functions
static void     _apply_modifiers(struct fmt_ptrn *, struct buffer *, struct mystack *);
static gint     _cmp(gconstpointer, gconstpointer);
static gboolean _copy_fillers(gpointer, gpointer, gpointer);
static void     _eat_alternate(struct fmt_ptrn *, const char **);
static gboolean _fill_it(struct fmt_ptrn *, const char *);
static int      _fmt_ptrn_copy_fillers(struct fmt_ptrn *, struct fmt_ptrn *);
static gboolean fmt_ptrn_valid(const struct fmt_ptrn *);
static gboolean _free_tree_node(gpointer, gpointer, gpointer);
static void     _handle_fmt_str(struct fmt_ptrn *, const char **);
static gboolean _is_literal(struct fmt_ptrn *, const char *);
static gboolean _lookup(const struct fmt_ptrn *, const char *, struct buffer *);
static char *   _matching_paren(const char *);
static inline gboolean modifier_valid(const struct modifier *);
static void     _read_alternate(struct fmt_ptrn *, const char **, struct buffer *);
static void     _read_key(struct fmt_ptrn *, char *, const char **);
static void     _read_literal(struct fmt_ptrn *, char *, struct buffer *);
static gboolean _read_modifier(struct fmt_ptrn *, const char **, struct mystack *);
static void     _read_modifier_arg(struct fmt_ptrn *, const char **, struct modifier *);
static void     _read_modifiers(struct fmt_ptrn *, const char **, struct mystack *);
static int      _stack_contains(const struct mystack, const char *);
static inline void _stack_init(struct mystack *);
static gboolean _stack_pop(struct mystack *, struct modifier *);
static gboolean _stack_push(struct fmt_ptrn *, struct mystack *, const struct modifier *);
static inline gboolean mystack_valid(const struct mystack *);

/* ============================ fmt_ptrn_valid () ======================= */
static gboolean fmt_ptrn_valid(const struct fmt_ptrn *x) {
	if (x == NULL)
		return FALSE;
	/* FIXME */
	/* gzFile template_fp; */
	/* char template_path[PATH_MAX + 1]; */
	/* long line_num; */
        if(!buffer_valid(&x->raw_buf) || !buffer_valid(&x->filled_buf) ||
         !buffer_valid(&x->lookup_buf))
		return FALSE;
	/* char errmsg[BUFSIZ + 1]; */
	/* GQueue *parse_errmsg; */
	/* GTree *fillers; */
	return TRUE;
}

/* ============================ fmt_ptrn_parse_err () ====================== */
gboolean fmt_ptrn_parse_err(const struct fmt_ptrn *x) {
	assert(fmt_ptrn_valid(x));
	return !g_queue_is_empty(x->parse_errmsg);
}

/* ============================ fmt_ptrn_parse_strerror () ================= */
char *fmt_ptrn_parse_strerror(struct fmt_ptrn *x) {
	char *errmsg;
	char *fnval;

	assert(fmt_ptrn_valid(x));

	if((errmsg = g_queue_pop_tail(x->parse_errmsg)) == NULL)
		fnval = g_strdup("no error"); // leak
	else
		fnval = errmsg; // g_queue_pop_tail: possible leak

	assert(fmt_ptrn_valid(x));
	assert(fnval != NULL);

	return fnval;
}

/* ============================ enqueue_parse_errmsg () =================== */
void enqueue_parse_errmsg(struct fmt_ptrn *x, const char *msg, ...) {
	va_list args;
	char *err;

	assert(fmt_ptrn_valid(x));
	assert(msg != NULL);

	err = xmalloc(PARSE_ERR_LEN + 1);
	va_start(args, msg);
	vsnprintf(err, PARSE_ERR_LEN, msg, args);
	va_end(args);
	g_queue_push_head(x->parse_errmsg, err);

	assert(fmt_ptrn_valid(x));
}

/* ============================ modifier_valid () ======================= */
static inline gboolean modifier_valid(const struct modifier *m) {
	/* FIXME */
	return TRUE;
}

/* ============================ mystack_valid () ========================== */
static inline gboolean mystack_valid(const struct mystack *s) {
    return (s == NULL && s->size != 0) ? FALSE : TRUE;
}

/* ============================ _stack_init () ============================= */
static inline void _stack_init(struct mystack *s) {
	s->size = 0;
	assert(mystack_valid(s));
}

/* ============================ _stack_push () ============================= */
static gboolean _stack_push(struct fmt_ptrn *x, struct mystack *s,
 const struct modifier *data)
{
	gboolean fnval = FALSE;

	assert(fmt_ptrn_valid(x));
	assert(mystack_valid(s));
	assert(modifier_valid(data));
	if (s->size == STACK_MAX_ITEMS) {
		enqueue_parse_errmsg(x, "%s: %ld: more than %d modifiers",
				     x->template_path, x->line_num,
				     STACK_MAX_ITEMS);
		fnval = FALSE;
	} else {
		s->data[s->size++] = *data;
		fnval = TRUE;
	}

	assert(fmt_ptrn_valid(x));
	assert(mystack_valid(s));
	return fnval;
}

/* ============================ _stack_pop () ============================== */
static gboolean _stack_pop(struct mystack *s, struct modifier *data) {
	gboolean fnval = FALSE;
	assert(mystack_valid(s));
	assert(modifier_valid(data));
	if(s->size == 0)
		fnval = FALSE;
	else {
		*data = s->data[--s->size];
		fnval = TRUE;
	}

	assert(mystack_valid(s));
	assert(modifier_valid(data));
	return fnval;
}

/* ============================ _stack_contains () ========================= */
static int _stack_contains(const struct mystack s, const char *n)
{
	int i;
	assert(mystack_valid(&s));
	for (i = 0; i < s.size; i++)
		if (s.data[i].fn.id == n)
			return 1;
	return 0;
}

/* ============================ fmt_ptrn_update_kv () ====================== */
void fmt_ptrn_update_kv(struct fmt_ptrn *x, const char *key, const char *val) {
	assert(fmt_ptrn_valid(x));
	assert(key != NULL);
	assert(val != NULL);
	/* FIXME: getting rid of the const is silly, but I didn't write g_tree_insert */
        // string not duplicated but freed? see above
	g_tree_insert(x->fillers, const_cast(char *, key), const_cast(char *, val));
	assert(fmt_ptrn_valid(x));
}

/* ============================ _matching_paren () ========================= */
static char *_matching_paren(const char *str) {
    /* Feed it a pointer just after a '(' and it will return a pointer to the
    matching ')'. Note that it must return CHAR *, not CONST CHAR *, just as
    strchr() does for example. */
	int count = 1;
	assert(str != NULL);
	while(*str != '\0') {
		if (*str == '(')
			count++;
		else if (*str == ')')
			count--;
		if (count == 0)
			return const_cast(char *, str);
		str++;
	}
	return NULL;
}

/* ============================ _copy_fillers () =========================== */
static gboolean _copy_fillers(gpointer key, gpointer val, gpointer data) {
	assert(key != NULL);
	assert(val != NULL);
	assert(fmt_ptrn_valid(data));

	g_tree_insert(static_cast(struct fmt_ptrn *, data)->fillers,
		      strdup(key), strdup(val));

	assert(fmt_ptrn_valid(data));

	return FALSE;
}

/* ============================ _fmt_ptrn_copy_fillers () ================== */
static int _fmt_ptrn_copy_fillers(struct fmt_ptrn *x, struct fmt_ptrn *y) {
/* Copies fillers from one fmt_ptrn to another. */
	assert(fmt_ptrn_valid(x));
	assert(fmt_ptrn_valid(y));

	/* FIXME: tried using g_node_copy but that did not seem to work */
	g_tree_foreach(y->fillers, _copy_fillers, x);

	assert(fmt_ptrn_valid(x));
	assert(fmt_ptrn_valid(y));

	return 1;
}

/* ============================ _read_alternate () ========================= */
static void _read_alternate(struct fmt_ptrn *x, const char **p,
 struct buffer *buf)
{
	char *alt_end;
	assert(fmt_ptrn_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
	assert(buffer_valid(buf));
	if(**p == '\0')		/* Already queued error, hopefully. */
		return;
	if (**p == ':') {
		++*p;
		if((alt_end = _matching_paren(*p)) != NULL) {
			/* FIXME: clean up? */
			struct fmt_ptrn y;
			char *alt, *filled_alt;
			alt = g_strndup(*p, (alt_end - *p));
			fmt_ptrn_init(&y);
			_fmt_ptrn_copy_fillers(&y, x);
			filled_alt = fmt_ptrn_filled(&y, alt);
			realloc_n_ncat(buf, filled_alt, (alt_end - *p));
			while (fmt_ptrn_parse_err(&y))
				enqueue_parse_errmsg(x,
						     fmt_ptrn_parse_strerror
						     (&y));
			*p += (alt_end - *p);
			free(alt);
			free(filled_alt);
			fmt_ptrn_close(&y);
		} else
			enqueue_parse_errmsg(x, "%s: %ld: end of input",
					     x->template_path,
					     x->line_num);
	} else
		/* We know there is no value for the format string because
		 * this function was called.  There is also no alternate.
		 * Call this a parse error to be safe.
		 */
		enqueue_parse_errmsg(x, "%s: %ld: key has no value",
				     x->template_path, x->line_num);
	assert(fmt_ptrn_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
	assert(buffer_valid(buf));
}

/* ============================ _eat_alternate () ========================== */
static void _eat_alternate(struct fmt_ptrn *x, const char **pattern) {
	char *alt_end;
	assert(fmt_ptrn_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
	if(**pattern == '\0' || **pattern != ':')
		/* No alternate provided to eat. */
		return;
	if((alt_end = _matching_paren(*pattern)) != NULL)
		*pattern += (alt_end - *pattern);
	if(**pattern == '\0')
		enqueue_parse_errmsg(x, "%s: %ld: end of input",
				     x->template_path, x->line_num);
	assert(fmt_ptrn_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
}

/* ============================ _read_modifier_arg () ====================== */
static void _read_modifier_arg(struct fmt_ptrn *x, const char **pattern,
 struct modifier *i)
{
	size_t arg_len;
	char *end_quote, *end_paren;

	assert(fmt_ptrn_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
	assert(modifier_valid(i));

	end_quote = strchr(*pattern, '"');
	end_paren = strchr(*pattern, ')');
	if(end_quote == NULL || (end_paren != NULL && end_quote > end_paren))
		enqueue_parse_errmsg(x, "%s: %ld: no end quote",
				     x->template_path, x->line_num);
	else {
		arg_len = end_quote - *pattern;
		if (arg_len > MODIFIER_ARG_LEN) {
			g_strlcpy(i->arg, *pattern, MODIFIER_ARG_LEN + 1);
			enqueue_parse_errmsg(x,
					     "%s: %ld: modifier arg. too long",
					     x->template_path,
					     x->line_num);
		} else 
			g_strlcpy(i->arg, *pattern, arg_len + 1);
		if (*(*pattern + arg_len + 1) != ' ')
			enqueue_parse_errmsg(x,
					     "%s: %ld: no space after arg",
					     x->template_path,
					     x->line_num);
		*pattern += arg_len + 2;	/* Add 2 for end quote and space. */
	}

	assert(fmt_ptrn_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
	assert(modifier_valid(i));
}

/* ============================ _read_modifier () ========================== */
static gboolean _read_modifier(struct fmt_ptrn *x, const char **ptrn,
 struct mystack *modifier)
{
	int i = 0;
	struct modifier m;
	gboolean fnval = FALSE;

	assert(fmt_ptrn_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(mystack_valid(modifier));

	while(mod_fn[i].id != NULL) {
		if(strncmp(mod_fn[i].id, *ptrn, strlen(mod_fn[i].id)) == 0) {
			*ptrn +=
			    strlen(mod_fn[i].id) +
			    (mod_fn[i].has_arg ? 0 : 1);
			m.fn = mod_fn[i];
			if (mod_fn[i].has_arg)
				_read_modifier_arg(x, ptrn, &m);
			else
				*m.arg = '\0';
			_stack_push(x, modifier, &m);
			fnval = TRUE;
			break;
		}
		i++;
	}

	assert(fmt_ptrn_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(mystack_valid(modifier));

	return fnval;
}

/* ============================ _read_modifiers () ========================= */
static void _read_modifiers(struct fmt_ptrn *x, const char **ptrn,
 struct mystack *modifier)
{
	assert(fmt_ptrn_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(mystack_valid(modifier));

	while(_read_modifier(x, ptrn, modifier)) /* noop */;

	assert(fmt_ptrn_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(mystack_valid(modifier));

	return;
}

/* ============================ _read_key () =============================== */
static void _read_key(struct fmt_ptrn *x, char *key, const char **p) {
	int i;

	assert(fmt_ptrn_valid(x));
	assert(key != NULL);
	assert(p != NULL);
	assert(*p != NULL);

	*key = '\0';
	for(i = 0; i < KEY_LEN && **p != '\0' && strchr(":)", **p) == NULL; i++)
		strncat(key, (*p)++, 1);
	if(**p != '\0' && strchr(":)", **p) == NULL) {
		/* Uh oh, key is too many characters, eat the rest. */
		while(**p != '\0' && **p != ':' && **p != ')')
			++*p;
		enqueue_parse_errmsg(x, "%s: %ld: key too long",
				     x->template_path, x->line_num);
	}
	if(**p == '\0')
		enqueue_parse_errmsg(x, "%s: %ld: end of input",
				     x->template_path, x->line_num);

	assert(fmt_ptrn_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
}

/* ============================ _apply_modifiers () ======================== */
static void _apply_modifiers(struct fmt_ptrn *x, struct buffer *str,
 struct mystack *modifier)
{
	struct modifier m;

	assert(fmt_ptrn_valid(x));
	assert(buffer_valid(str));
	assert(mystack_valid(modifier));

	if (buffer_len(str) > 0)	/* error should have been queued elsewhere */
            while(_stack_pop(modifier, &m))
                if(m.fn.fn != NULL && !m.fn.fn(str, x, m.arg))
                    enqueue_parse_errmsg(x, "%s: %ld: error applying %s modifier to %s",
                      x->template_path, x->line_num, m.fn.id, str->data);

	assert(fmt_ptrn_valid(x));
	assert(buffer_valid(str));
	assert(mystack_valid(modifier));
}

/* ============================ _lookup () ================================= */
static gboolean _lookup(const struct fmt_ptrn *x, const char *key,
 struct buffer *value)
{
	char *tmp;
	gboolean fnval = FALSE;

	assert(fmt_ptrn_valid(x));
	assert(key != NULL);
	assert(buffer_valid(value));

	tmp = g_tree_lookup(x->fillers, key);
	if(tmp != NULL) {
		realloc_n_cpy(value, tmp);
		fnval = TRUE;
	} else {
		if (buffer_len(value) > 0) /* error should have been queue elsewhere */
			*value->data = '\0';	/* Otherwise _read_alternate will append onto garbage. */
		fnval = FALSE;
	}

	assert(buffer_valid(value));

	return fnval;
}

/* ============================ _is_literal () ============================= */
static gboolean _is_literal(struct fmt_ptrn *x, const char *str) {
	gboolean fnval = FALSE;

	assert(fmt_ptrn_valid(x));
	assert(str != NULL);

	if (*str == '"') {
		if(strchr(str + 1, '"') != NULL)
			enqueue_parse_errmsg(x, "%s: %ld: no end quote",
					     x->template_path,
					     x->line_num);
		fnval = TRUE;
	}

	assert(fmt_ptrn_valid(x));

	return fnval;
}

/* ============================ _read_literal () =========================== */
/* FIXME: is this right?  it does not seem to look for closing '"' */
static void _read_literal(struct fmt_ptrn *x, char *str, struct buffer *buf) {
	assert(fmt_ptrn_valid(x));
	assert(str != NULL);
	assert(buffer_valid(buf));

	str++;
	str[strlen(str) - 1] = '\0';
	if(strlen(str) > 0)
		realloc_n_cpy(buf, str);
	else
		enqueue_parse_errmsg(x, "%s: %ld: no literal found in quotes",
					     x->template_path,
					     x->line_num);

	assert(fmt_ptrn_valid(x));
	assert(buffer_valid(buf));
}

/* ============================ _handle_fmt_str () ========================= */
static void _handle_fmt_str(struct fmt_ptrn *x, const char **p) {
	/* format string -> %(<modifier_0> ... <modifier_n> <key>:<alt>) */
	struct mystack modifier;
	char key[KEY_LEN + 1];

	assert(fmt_ptrn_valid(x));
	assert(p != NULL);
	assert(*p != NULL);

	_stack_init(&modifier);
	*p += 2;		/* Skip "%(". */
	_read_modifiers(x, p, &modifier);
	if (_stack_contains(modifier, "#")) {
		/* NOOP. */
	} else {
		_read_key(x, key, p);
		if (_is_literal(x, key)) {
			_read_literal(x, key, &x->lookup_buf);
			_apply_modifiers(x, &x->lookup_buf, &modifier);
		} else if (_lookup(x, key, &x->lookup_buf)) {
			_eat_alternate(x, p);
			_apply_modifiers(x, &x->lookup_buf, &modifier);
		} else
			_read_alternate(x, p, &x->lookup_buf);
		if (buffer_len(&x->lookup_buf))
			/* error should have been queued elsewhere */
			realloc_n_cat(&x->filled_buf, x->lookup_buf.data);
	}
	if(**p != '\0')
		++*p; /* Skip ')'. */

	assert(fmt_ptrn_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
}

/* ============================ _fill_it () ================================ */
static gboolean _fill_it(struct fmt_ptrn *x, const char *p) {
	const char *pattern;
        char *orig_ptr;
	gboolean fnval = TRUE;

	assert(fmt_ptrn_valid(x));
	assert(p != NULL);

	pattern = orig_ptr = g_strdup(p);
	while(*pattern != '\0') {
		if (*pattern == '%' && *(pattern + 1) == '%') {
			/* Handle %%(...), which should be filled as %(...). */
			realloc_n_ncat(&x->filled_buf, pattern, 1);
			pattern += 2;
		} else if(*pattern == '%' && *(pattern + 1) == '(') {
			_handle_fmt_str(x, &pattern);
		} else {
			if (*pattern == '\n')
				x->line_num++;
			realloc_n_ncat(&x->filled_buf, pattern++, 1);
		}
	}
	free(orig_ptr);

	assert(fmt_ptrn_valid(x));

	return fnval;
}

/* ============================ fmt_ptrn_filled () ========================= */
char *fmt_ptrn_filled(struct fmt_ptrn *x, const char *p) {
	char *fnval = NULL;

	assert(fmt_ptrn_valid(x));
	assert(p != NULL);

	buffer_clear(&x->filled_buf);
	if (!_fill_it(x, p))
		return NULL;
	if(buffer_len(&x->filled_buf) > 0)
		/* FIXME: what if len == 0? protected by assert, but... */
		fnval = g_strdup(x->filled_buf.data);

	assert(fmt_ptrn_valid(x));
	/* FIXME: assert(fnval != NULL); WHY DID I THINK THIS WAS NEEDED? */

	return fnval;
}

/* ============================ _cmp () ==================================== */
static gint _cmp(gconstpointer a, gconstpointer b) {
	/* FIXME: why is a and/or b sometimes NULL? */
	if(a == NULL && b == NULL)
		return 0;
	if(a == NULL)
		return -1;
	if(b == NULL)
		return 1;
	return strcmp(a, b);
}

/* ============================ fmt_ptrn_init () =========================== */
int fmt_ptrn_init(struct fmt_ptrn *x) {
/* Alternative to open; does everything but open the file.  This 
 * should be used when filling strings instead of files.
 */
	g_strlcpy(x->errmsg, "no error", sizeof(x->errmsg));
	x->parse_errmsg = g_queue_new();
	x->fillers = g_tree_new(_cmp);
	x->template_fp = NULL;
	x->line_num = 1;
        buffer_init(&x->raw_buf);
        buffer_init(&x->filled_buf);
        buffer_init(&x->lookup_buf);
	g_strlcpy(x->template_path, "string", sizeof(x->template_path));
	
	assert(fmt_ptrn_valid(x));

	return 1;
}

/* ============================ fmt_ptrn_open () =========================== */
gboolean fmt_ptrn_open(const char *path, struct fmt_ptrn *x) {
	gzFile in_file;
	gboolean fnval = TRUE;

	assert(path != NULL);
	assert(fmt_ptrn_valid(x));

	if((in_file = gzopen(path, "rb")) == NULL) {
		fnval = FALSE;
		goto _return;
	} 
	if (!fmt_ptrn_init(x)) {
		fnval = FALSE;
		goto _return;
	}
	x->template_fp = in_file;	/* init sets this to NULL. */
	strcpy(x->template_path, path);	/* init sets this to "string". */
_return:
	assert(fmt_ptrn_valid(x));

	return fnval;
}

/* ============================ fmt_ptrn_gets () =========================== */
char *fmt_ptrn_gets(char *buf, size_t size, struct fmt_ptrn *x) {
	char *fnval = NULL;

	assert(buf != NULL);
	assert(fmt_ptrn_valid(x));

	if (buffer_len(&x->filled_buf) == 0) {
		/* FIXME: potentially, a buffer could be filled with only 
		 * half of a format string. 
		 */
		/* Here buf is used as a temp. buffer. */
		if (gzgets(x->template_fp, buf, size) == Z_NULL) {
			fnval = NULL;
			goto _return;
		}
		if (!_fill_it(x, buf)) {
			fnval = NULL;
			goto _return;
		}
	}
	if (buffer_len(&x->filled_buf) > 0) {
		g_strlcpy(buf, x->filled_buf.data, size);
		buffer_eat(&x->filled_buf, strlen(buf));
		fnval = buf;
	} else {
		fnval = NULL;
		goto _return;
	}
_return:
	assert(fmt_ptrn_valid(x));

	return fnval;
}

/* ============================ _free_tree_node () ========================= */
/* FIXME: this function should take TWO pointers!!!!!! */
static gboolean _free_tree_node(gpointer key, gpointer val, gpointer data) {
/* FIXME: this function may not modify tree.  need to write pointers to a list and then destroy that list outside of this function. */
	return FALSE;
}

/* ============================ fmt_ptrn_close () ========================== */
int fmt_ptrn_close(struct fmt_ptrn *x) {
	gpointer ptr;

	assert(fmt_ptrn_valid(x));

	while ((ptr = g_queue_pop_head(x->parse_errmsg)) != NULL)
		free(ptr);
	g_tree_foreach(x->fillers, _free_tree_node, NULL);
	buffer_clear(&x->raw_buf);
	buffer_clear(&x->filled_buf);
	buffer_clear(&x->lookup_buf);
	/* x->template_fp == NULL if fmt_ptrn_init was used instead of 
	 * fmt_ptrn_open.
	 */
	return (x != NULL && x->template_fp != NULL) ?
            gzclose(x->template_fp) : 1;
}

//=============================================================================
