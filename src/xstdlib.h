#ifndef PMT_XSTDLIB_H
#define PMT_XSTDLIB_H 1

#include <sys/types.h>

typedef int bool;

/*
 *	XSTDLIB.C
 */
extern void *xmalloc(size_t);
extern void *xmemdup(const void *, size_t);
extern void *xrealloc(void *, size_t);
extern char *xstrdup(const char *);
extern char *xstrndup(const char *, size_t);
extern void *xzalloc(size_t);

#endif /* PMT_XSTDLIB_H */
