#ifndef PMT_MISC_H
#define PMT_MISC_H 1

#include <sys/types.h>
#include <stdbool.h>
#include <libHX/string.h>
#include "compiler.h"

#define __STRINGIFY_EXPAND(s) #s
#define __STRINGIFY(s)        __STRINGIFY_EXPAND(s)

struct HXbtree;
struct config;
struct vol;

/*
 *	MISC.C
 */
/* Note that you will also need to change PMPREFIX in pmvarrun.c then! */
#define PMPREFIX       "pam_mount(%s:%u) "
#define l0g(fmt, ...) \
	misc_log((PMPREFIX fmt), HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)
#define w4rn(fmt, ...) \
	misc_warn((PMPREFIX fmt), HX_basename(__FILE__), \
	__LINE__, ## __VA_ARGS__)

extern void add_to_argv(const char **, int * const, const char * const,
	struct HXbtree *);
extern int config_valid(const struct config *);
extern int exists(const char *);
extern void log_argv(const char * const *);
extern void misc_add_ntdom(struct HXbtree *, const char *);
extern void misc_dump_id(const char *);
extern void misc_log(const char *, ...);
extern void misc_warn(const char *, ...);
extern int owns(const char *, const char *);
extern char *relookup_user(const char *);
extern void set_myuid(const char *);
extern long str_to_long(const char *);
extern int vol_valid(const struct vol *);

#endif /* PMT_MISC_H */
