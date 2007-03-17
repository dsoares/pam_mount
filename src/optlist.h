#ifndef PMT_OPTLIST_H
#define PMT_OPTLIST_H 1

#include <glib.h>
#include "compiler.h"
#include "pair.h"
#include "xstdlib.h"

#define optlist_next(element)   g_list_next(element)
#define optlist_key(element) \
	static_cast(const struct pair *, (element)->data)->key
#define optlist_val(element) \
	static_cast(const struct pair *, (element)->data)->val
#define optlist_len(list)       g_list_length(list)

typedef GList optlist_t;

/*
 *	OPTLIST.C
 */
extern bool optlist_exists(optlist_t *, const char *);
extern char *optlist_to_str(char *, const optlist_t *);
extern const char *optlist_value(optlist_t *, const char *);
extern bool str_to_optlist(optlist_t **, const char *);

#endif /* PMT_OPTLIST_H */
