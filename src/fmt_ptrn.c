/*   FILE: fmt_ptrn.c --
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 08 January 2000
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

#include <assert.h>
#include <new/fmt_ptrn.h>
#include <new/sizes.h>
#include <new/common.h>
#include <new/template.h>
#include <new/modifiers.h>
#include <new/buffer.h>
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

/* ============================ _fmt_ptrn_t_valid () ======================= */
static gboolean _fmt_ptrn_t_valid(const fmt_ptrn_t * x)
{
	if (x == NULL)
		return FALSE;
	/* FIXME */
	/* gzFile template_fp; */
	/* char template_path[PATH_MAX + 1]; */
	/* long line_num; */
	if (buffer_t_valid(&x->raw_buf) == FALSE)
		return FALSE;
	if (buffer_t_valid(&x->filled_buf) == FALSE)
		return FALSE;
	if (buffer_t_valid(&x->lookup_buf) == FALSE)
		return FALSE;
	/* char errmsg[BUFSIZ + 1]; */
	/* GQueue *parse_errmsg; */
	/* GTree *fillers; */
	return TRUE;
}

/* ============================ fmt_ptrn_parse_err () ====================== */
gboolean fmt_ptrn_parse_err(const fmt_ptrn_t * x)
{
	assert(_fmt_ptrn_t_valid(x));
	return !g_queue_is_empty(x->parse_errmsg);
}

/* ============================ fmt_ptrn_parse_strerror () ================= */
char *fmt_ptrn_parse_strerror(fmt_ptrn_t * x)
{
	char *errmsg;
	char *fnval;

	assert(_fmt_ptrn_t_valid(x));

	if (!(errmsg = g_queue_pop_tail(x->parse_errmsg)))
		fnval = g_strdup("no error");
	else
		fnval = errmsg;

	assert(_fmt_ptrn_t_valid(x));
	assert(fnval != NULL);

	return fnval;
}

/* ============================ fmt_ptrn_parse_perror () =================== */
void fmt_ptrn_parse_perror(fmt_ptrn_t * x, const char *msg)
{
	char *errmsg;

	assert(_fmt_ptrn_t_valid(x));

	errmsg = fmt_ptrn_parse_strerror(x);
	if (msg)
		fprintf(stderr, "%s: %s\n", msg, errmsg);
	else
		fprintf(stderr, "%s\n", errmsg);
	g_free(errmsg);

	assert(_fmt_ptrn_t_valid(x));
}

/* ============================ enqueue_parse_errmsg () =================== */
void enqueue_parse_errmsg(fmt_ptrn_t * x, const char *msg, ...)
{
	char *err;

	assert(_fmt_ptrn_t_valid(x));
	assert(msg != NULL);

	err = (char *) g_new0(char, PARSE_ERR_LEN + 1);
	va_list args;
	va_start(args, msg);
	vsnprintf(err, PARSE_ERR_LEN, msg, args);
	va_end(args);
	g_queue_push_head(x->parse_errmsg, err);

	assert(_fmt_ptrn_t_valid(x));
}

/* ============================ stack_t ==================================== */
typedef struct stack_t {
	modifier_t data[STACK_MAX_ITEMS];
	int size;
} stack_t;

/* ============================ _modifier_t_valid () ======================= */
static gboolean _modifier_t_valid(const modifier_t * m)
{
	/* FIXME */
	return TRUE;
}

/* ============================ _stack_t_valid () ========================== */
static gboolean _stack_t_valid(const stack_t * s)
{
	if (s == NULL && s->size != 0)
		return FALSE;
	return TRUE;
}

/* ============================ _stack_init () ============================= */
static void _stack_init(stack_t * s)
{
	s->size = 0;
	assert(_stack_t_valid(s));
}

/* ============================ _stack_push () ============================= */
static gboolean _stack_push(fmt_ptrn_t * x, stack_t * s,
			    const modifier_t data)
{
	gboolean fnval = FALSE;

	assert(_fmt_ptrn_t_valid(x));
	assert(_stack_t_valid(s));
	assert(_modifier_t_valid(&data));
	if (s->size == STACK_MAX_ITEMS) {
		enqueue_parse_errmsg(x, "%s: %ld: more than %d modifiers",
				     x->template_path, x->line_num,
				     STACK_MAX_ITEMS);
		fnval = FALSE;
	} else {
		s->data[s->size++] = data;
		fnval = TRUE;
	}

	assert(_fmt_ptrn_t_valid(x));
	assert(_stack_t_valid(s));
	return fnval;
}

/* ============================ _stack_pop () ============================== */
static gboolean _stack_pop(stack_t * s, modifier_t * data)
{
	gboolean fnval = FALSE;
	assert(_stack_t_valid(s));
	assert(_modifier_t_valid(data));
	if (!s->size)
		fnval = FALSE;
	else {
		*data = s->data[--s->size];
		fnval = TRUE;
	}

	assert(_stack_t_valid(s));
	assert(_modifier_t_valid(data));
	return fnval;
}

/* ============================ _stack_contains () ========================= */
static int _stack_contains(const stack_t s, const char *n)
{
	int i;
	assert(_stack_t_valid(&s));
	for (i = 0; i < s.size; i++)
		if (s.data[i].fn.id == n)
			return 1;
	return 0;
}

/* ============================ fmt_ptrn_update_kv_p () ==================== */
void fmt_ptrn_update_kv_p(fmt_ptrn_t * x, const pair_t * p)
{
	assert(_fmt_ptrn_t_valid(x));
	assert(pair_t_valid(p));
	/* FIXME: this strdups here but other fn requires malloced strs! */
	g_tree_insert(x->fillers, strdup(p->key), strdup(p->val));
	assert(_fmt_ptrn_t_valid(x));
}

/* ============================ fmt_ptrn_update_kv () ====================== */
void fmt_ptrn_update_kv(fmt_ptrn_t * x, const char *key, const char *val)
{
	assert(_fmt_ptrn_t_valid(x));
	assert(key != NULL);
	assert(val != NULL);
	/* FIXME: getting rid of the const is silly, but I didn't write g_tree_insert */
	g_tree_insert(x->fillers, (char *) key, (char *) val);
	assert(_fmt_ptrn_t_valid(x));
}

/* ============================ _matching_paren () ========================= */
static char *_matching_paren(char *str)
/* feed it a pointer just after a '(' and it will return a pointer to the
 * matching ')'
 */
{
	int count = 1;
	assert(str != NULL);
	while (*str) {
		if (*str == '(')
			count++;
		else if (*str == ')')
			count--;
		if (count == 0)
			return str;
		str++;
	}
	return NULL;
}

/* ============================ _copy_fillers () =========================== */
gboolean _copy_fillers(gpointer key, gpointer val, gpointer data)
{
	assert(key != NULL);
	assert(val != NULL);
	assert(_fmt_ptrn_t_valid(data));

	g_tree_insert(((fmt_ptrn_t *) data)->fillers,
		      strdup(key), strdup(val));

	assert(_fmt_ptrn_t_valid(data));

	return FALSE;
}

/* ============================ _fmt_ptrn_copy_fillers () ================== */
int _fmt_ptrn_copy_fillers(fmt_ptrn_t * x, fmt_ptrn_t * y)
/* Copies fillers from one fmt_ptrn to another. */
{
	assert(_fmt_ptrn_t_valid(x));
	assert(_fmt_ptrn_t_valid(y));

	/* FIXME: tried using g_node_copy but that did not seem to work */
	g_tree_foreach(y->fillers, _copy_fillers, x);

	assert(_fmt_ptrn_t_valid(x));
	assert(_fmt_ptrn_t_valid(y));

	return 1;
}

/* ============================ _read_alternate () ========================= */
static void _read_alternate(fmt_ptrn_t * x, char **p, buffer_t * buf)
{
	char *alt_end;
	assert(_fmt_ptrn_t_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
	assert(buffer_t_valid(buf));
	if (!**p)		/* Already queued error, hopefully. */
		return;
	if (**p == ':') {
		(*p)++;
		if ((alt_end = _matching_paren(*p))) {
			/* FIXME: clean up? */
			fmt_ptrn_t y;
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
			g_free(alt);
			g_free(filled_alt);
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
	assert(_fmt_ptrn_t_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
	assert(buffer_t_valid(buf));
}

/* ============================ _eat_alternate () ========================== */
static void _eat_alternate(fmt_ptrn_t * x, char **pattern)
{
	char *alt_end;
	assert(_fmt_ptrn_t_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
	if (!**pattern || **pattern != ':')
		/* No alternate provided to eat. */
		return;
	if ((alt_end = _matching_paren(*pattern)))
		*pattern += (alt_end - *pattern);
	if (!**pattern)
		enqueue_parse_errmsg(x, "%s: %ld: end of input",
				     x->template_path, x->line_num);
	assert(_fmt_ptrn_t_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
}

/* ============================ _read_modifier_arg () ====================== */
static void _read_modifier_arg(fmt_ptrn_t * x,
			       char **pattern, modifier_t * i)
{
	size_t arg_len;
	char *end_quote, *end_paren;

	assert(_fmt_ptrn_t_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
	assert(_modifier_t_valid(i));

	end_quote = strchr(*pattern, '"');
	end_paren = strchr(*pattern, ')');
	if (!end_quote || (end_paren && end_quote > end_paren))
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

	assert(_fmt_ptrn_t_valid(x));
	assert(pattern != NULL);
	assert(*pattern != NULL);
	assert(_modifier_t_valid(i));
}

/* ============================ _read_modifier () ========================== */
static gboolean _read_modifier(fmt_ptrn_t * x, char **ptrn,
			       stack_t * modifier)
{
	int i = 0;
	modifier_t m;
	gboolean fnval = FALSE;

	assert(_fmt_ptrn_t_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(_stack_t_valid(modifier));

	while (mod_fn[i].id) {
		if (!strncmp(mod_fn[i].id, *ptrn, strlen(mod_fn[i].id))) {
			*ptrn +=
			    strlen(mod_fn[i].id) +
			    (mod_fn[i].has_arg ? 0 : 1);
			m.fn = mod_fn[i];
			if (mod_fn[i].has_arg)
				_read_modifier_arg(x, ptrn, &m);
			else
				*m.arg = 0x00;
			_stack_push(x, modifier, m);
			fnval = TRUE;
			break;
		}
		i++;
	}

	assert(_fmt_ptrn_t_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(_stack_t_valid(modifier));

	return fnval;
}

/* ============================ _read_modifiers () ========================= */
static void _read_modifiers(fmt_ptrn_t * x,
			    char **ptrn, stack_t * modifier)
{
	assert(_fmt_ptrn_t_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(_stack_t_valid(modifier));

	while (_read_modifier(x, ptrn, modifier)) {
		/* NOOP. */
	}

	assert(_fmt_ptrn_t_valid(x));
	assert(ptrn != NULL);
	assert(*ptrn != NULL);
	assert(_stack_t_valid(modifier));

	return;
}

/* ============================ _read_key () =============================== */
static void _read_key(fmt_ptrn_t * x, char *key, char **p)
{
	int i;

	assert(_fmt_ptrn_t_valid(x));
	assert(key != NULL);
	assert(p != NULL);
	assert(*p != NULL);

	*key = 0x00;
	for (i = 0; i < KEY_LEN && **p && !strchr(":)", **p); i++)
		strncat(key, (*p)++, 1);
	if (**p && !strchr(":)", **p)) {
		/* Uh oh, key is too many characters, eat the rest. */
		while (**p && **p != ':' && **p != ')')
			(*p)++;
		enqueue_parse_errmsg(x, "%s: %ld: key too long",
				     x->template_path, x->line_num);
	}
	if (!**p)
		enqueue_parse_errmsg(x, "%s: %ld: end of input",
				     x->template_path, x->line_num);

	assert(_fmt_ptrn_t_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
}

/* ============================ _apply_modifiers () ======================== */
static void _apply_modifiers(fmt_ptrn_t * x,
			     buffer_t * str, stack_t * modifier)
{
	modifier_t m;

	assert(_fmt_ptrn_t_valid(x));
	assert(buffer_t_valid(str));
	assert(_stack_t_valid(modifier));

	if (buffer_len(str) > 0)	/* error should have been queued elsewhere */
		while (_stack_pop(modifier, &m))
			if (m.fn.fn)
				if (!m.fn.fn(str, x, m.arg))
					enqueue_parse_errmsg(x,
							     "%s: %ld: error applying %s modifier to %s",
							     x->
							     template_path,
							     x->line_num,
							     m.fn.id,
							     str->data);

	assert(_fmt_ptrn_t_valid(x));
	assert(buffer_t_valid(str));
	assert(_stack_t_valid(modifier));
}

/* ============================ _lookup () ================================= */
gboolean _lookup(const fmt_ptrn_t * x, const char *key, buffer_t * value)
{
	char *tmp;
	gboolean fnval = FALSE;

	assert(_fmt_ptrn_t_valid(x));
	assert(key != NULL);
	assert(buffer_t_valid(value));

	tmp = g_tree_lookup(x->fillers, key);
	if (tmp) {
		realloc_n_cpy(value, tmp);
		fnval = TRUE;
	} else {
		if (buffer_len(value) > 0) /* error should have been queue elsewhere */
			*value->data = 0x00;	/* Otherwise _read_alternate will append onto garbage. */
		fnval = FALSE;
	}

	assert(buffer_t_valid(value));

	return fnval;
}

/* ============================ _is_literal () ============================= */
static gboolean _is_literal(fmt_ptrn_t * x, char *str)
{
	gboolean fnval = FALSE;

	assert(_fmt_ptrn_t_valid(x));
	assert(str != NULL);

	if (*str == '"') {
		if (strchr(str + 1, '"'))
			enqueue_parse_errmsg(x, "%s: %ld: no end quote",
					     x->template_path,
					     x->line_num);
		fnval = TRUE;
	}

	assert(_fmt_ptrn_t_valid(x));

	return fnval;
}

/* ============================ _read_literal () =========================== */
/* FIXME: is this right?  it does not seem to look for closing '"' */
static void _read_literal(fmt_ptrn_t *x, char *str, buffer_t * buf)
{
	assert(_fmt_ptrn_t_valid(x));
	assert(str != NULL);
	assert(buffer_t_valid(buf));

	str++;
	str[strlen(str) - 1] = 0x00;
	if (strlen(str))
		realloc_n_cpy(buf, str);
	else
		enqueue_parse_errmsg(x, "%s: %ld: no literal found in quotes",
					     x->template_path,
					     x->line_num);

	assert(_fmt_ptrn_t_valid(x));
	assert(buffer_t_valid(buf));
}

/* ============================ _handle_fmt_str () ========================= */
static void _handle_fmt_str(fmt_ptrn_t * x, char **p)
{
	/* format string -> %(<modifier_0> ... <modifier_n> <key>:<alt>) */
	stack_t modifier;
	char key[KEY_LEN + 1];

	assert(_fmt_ptrn_t_valid(x));
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
	if (**p)
		(*p)++;		/* Skip ')'. */

	assert(_fmt_ptrn_t_valid(x));
	assert(p != NULL);
	assert(*p != NULL);
}

/* ============================ _fill_it () ================================ */
static gboolean _fill_it(fmt_ptrn_t * x, const char *p)
{
	char *pattern, *orig_ptr;
	gboolean fnval = TRUE;

	assert(_fmt_ptrn_t_valid(x));
	assert(p != NULL);

	pattern = orig_ptr = g_strdup((char *) p); /* stupid cast */
	while (*pattern != 0x00) {
		if (*pattern == '%' && *(pattern + 1) == '%') {
			/* Handle %%(...), which should be filled as %(...). */
			realloc_n_ncat(&x->filled_buf, pattern, 1);
			pattern += 2;
		} else if (*pattern == '%' && *(pattern + 1) == '(')
			_handle_fmt_str(x, &pattern);
		else {
			if (*pattern == '\n')
				x->line_num++;
			realloc_n_ncat(&x->filled_buf, pattern++, 1);
		}
	}
	g_free(orig_ptr);

	assert(_fmt_ptrn_t_valid(x));

	return fnval;
}

/* ============================ fmt_ptrn_filled () ========================= */
char *fmt_ptrn_filled(fmt_ptrn_t * x, const char *p)
{
	char *fnval = NULL;

	assert(_fmt_ptrn_t_valid(x));
	assert(p != NULL);

	buffer_clear(&x->filled_buf);
	if (!_fill_it(x, p))
		return NULL;
	if (buffer_len(&x->filled_buf))	
		/* FIXME: what if len == 0? protected by assert, but... */
		fnval = g_strdup(x->filled_buf.data);

	assert(_fmt_ptrn_t_valid(x));
	/* FIXME: assert(fnval != NULL); WHY DID I THINK THIS WAS NEEDED? */

	return fnval;
}

/* ============================ _cmp () ==================================== */
gint _cmp(gconstpointer a, gconstpointer b)
{
	/* FIXME: why is a and/or b sometimes NULL? */
	if (!a && !b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	return strcmp(a, b);
}

/* ============================ fmt_ptrn_init () =========================== */
int fmt_ptrn_init(fmt_ptrn_t * x)
/* Alternative to open; does everything but open the file.  This 
 * should be used when filling strings instead of files.
 */
{
	g_strlcpy(x->errmsg, "no error", sizeof(x->errmsg));
	x->parse_errmsg = g_queue_new();
	x->fillers = g_tree_new(_cmp);
	x->template_fp = NULL;
	x->line_num = 1;
	x->raw_buf = buffer_init();
	x->filled_buf = buffer_init();
	x->lookup_buf = buffer_init();
	g_strlcpy(x->template_path, "string", sizeof(x->template_path));
	
	assert(_fmt_ptrn_t_valid(x));

	return 1;
}

/* ============================ fmt_ptrn_open () =========================== */
gboolean fmt_ptrn_open(const char *path, fmt_ptrn_t * x)
{
	gzFile in_file;
	gboolean fnval = TRUE;

	assert(path != NULL);
	assert(_fmt_ptrn_t_valid(x));

	if (!(in_file = gzopen(path, "rb"))) {
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
	assert(_fmt_ptrn_t_valid(x));

	return fnval;
}

/* ============================ fmt_ptrn_gets () =========================== */
char *fmt_ptrn_gets(char *buf, size_t size, fmt_ptrn_t * x)
{
	char *fnval = NULL;

	assert(buf != NULL);
	assert(_fmt_ptrn_t_valid(x));

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
		buffer_eat(x->filled_buf, strlen(buf));
		fnval = buf;
	} else {
		fnval = NULL;
		goto _return;
	}
_return:
	assert(_fmt_ptrn_t_valid(x));

	return fnval;
}

/* ============================ _free_tree_node () ========================= */
/* FIXME: this function should take TWO pointers!!!!!! */
gboolean _free_tree_node(gpointer key, gpointer val, gpointer data)
{
/* FIXME: this function may not modify tree.  need to write pointers to a list and then destroy that list outside of this function. */
	return FALSE;
}

/* ============================ fmt_ptrn_close () ========================== */
int fmt_ptrn_close(fmt_ptrn_t * x)
{
	gpointer ptr;

	assert(_fmt_ptrn_t_valid(x));

	while ((ptr = g_queue_pop_head(x->parse_errmsg)) != NULL)
		g_free(ptr);
	g_tree_foreach(x->fillers, _free_tree_node, NULL);
	buffer_destroy(x->raw_buf);
	buffer_destroy(x->filled_buf);
	buffer_destroy(x->lookup_buf);
	/* x->template_fp == NULL if fmt_ptrn_init was used instead of 
	 * fmt_ptrn_open.
	 */
	return x && x->template_fp ? gzclose(x->template_fp) : 1;
}

/* ============================ fmt_ptrn_perror () ========================= */
void fmt_ptrn_perror(const fmt_ptrn_t * x, const char *msg)
{
	assert(_fmt_ptrn_t_valid(x));
	assert(msg != NULL);

	fprintf(stderr, "%s: %s\n", msg, x->errmsg);
}

/* ============================ fmt_ptrn_strerror () ======================= */
const char *fmt_ptrn_strerror(const fmt_ptrn_t * x)
{
	assert(_fmt_ptrn_t_valid(x));

	return x->errmsg;
}
