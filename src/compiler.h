#ifndef PMT_COMPILER_H
#define PMT_COMPILER_H 1

#include "config.h"
#include <libHX.h>

#ifdef HAVE_VISIBILITY_HIDDEN
#	define EXPORT_SYMBOL __attribute__((visibility("default")))
#else
#	define EXPORT_SYMBOL
#endif

/* These are just code annotations */
#define const_cast(type, expr)          ((type)(expr))
#define signed_cast(type, expr)         ((type)(expr))
#define reinterpret_cast(type, expr)    ((type)(expr))
#define static_cast(type, expr)         ((type)(expr))

/* Short wrappers */
static inline void format_add(struct HXbtree *table, const char *key,
    const char *value)
{
	HXformat_add(table, key, value, HXTYPE_STRING | HXFORMAT_IMMED);
	return;
}

#endif /* PMT_COMPILER_H */
