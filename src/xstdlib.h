#ifndef PMT_XSTDLIB_H
#define PMT_XSTDLIB_H 1

#include <sys/types.h>

/*
 *	XSTDLIB.C
 */
extern void *xmalloc(size_t);
extern void *xrealloc(void *, size_t);
extern char *xstrdup(const char *);

#endif /* PMT_XSTDLIB_H */
