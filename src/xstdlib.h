#ifndef PMT_XSTDLIB_H
#define PMT_XSTDLIB_H 1

#include <sys/types.h>
#include <stdbool.h>

struct HXclist_head;

extern bool kvplist_contains(const struct HXclist_head *, const char *);
extern char *kvplist_get(const struct HXclist_head *, const char *);
extern void kvplist_genocide(struct HXclist_head *);
extern hmc_t *kvplist_to_str(const struct HXclist_head *);

extern void *xmalloc(size_t);
extern void *xrealloc(void *, size_t);
extern char *xstrdup(const char *);

#endif /* PMT_XSTDLIB_H */
