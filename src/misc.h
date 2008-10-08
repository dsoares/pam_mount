#ifndef PMT_MISC_H
#define PMT_MISC_H 1

#include <sys/types.h>
#include <stdbool.h>
#include <libHX/string.h>

#define __STRINGIFY_EXPAND(s) #s
#define __STRINGIFY(s)        __STRINGIFY_EXPAND(s)

struct HXbtree;
struct HXclist_head;
struct HXdeque;
struct config;
struct vol;

/*
 *	MISC.C
 */
/* Note that you will also need to change PMPREFIX in pmvarrun.c then! */
#define l0g(fmt, ...) \
	misc_log(("%s(%s:%u): " fmt), pmtlog_prefix, HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)
#define w4rn(fmt, ...) \
	misc_warn(("%s(%s:%u): " fmt), pmtlog_prefix, HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)

enum {
	/* src */
	PMTLOG_ERR = 0,
	PMTLOG_DBG,
	PMTLOG_SRCMAX,

	/* dst */
	PMTLOG_SYSLOG = 0,
	PMTLOG_STDERR,
	PMTLOG_DSTMAX,
};

/* Variables */
extern const char *pmtlog_prefix;
extern bool pmtlog_path[PMTLOG_SRCMAX][PMTLOG_DSTMAX];

/* Functions */
extern void arglist_add(struct HXdeque *, const char *,
	const struct HXbtree *);
extern struct HXdeque *arglist_build(const struct HXdeque *,
	const struct HXbtree *);
extern void arglist_log(const struct HXdeque *);
extern void arglist_llog(const char *const *);
extern bool kvplist_contains(const struct HXclist_head *, const char *);
extern char *kvplist_get(const struct HXclist_head *, const char *);
extern void kvplist_genocide(struct HXclist_head *);
extern hxmc_t *kvplist_to_str(const struct HXclist_head *);
extern void misc_add_ntdom(struct HXbtree *, const char *);
extern void misc_dump_id(const char *);
extern int misc_log(const char *, ...);
extern int misc_warn(const char *, ...);
extern int pmt_fileop_exists(const char *);
extern int pmt_fileop_owns(const char *, const char *);
extern char *relookup_user(const char *);
extern void set_myuid(const char *);
extern long str_to_long(const char *);
extern void *xmalloc(size_t);
extern void *xrealloc(void *, size_t);
extern char *xstrdup(const char *);

#endif /* PMT_MISC_H */
