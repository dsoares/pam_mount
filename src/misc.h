#ifndef PMT_MISC_H
#define PMT_MISC_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <glib.h>
#include "fmt_ptrn.h"
#include "private.h"

extern void add_to_argv(const char **, int * const, const char * const,
    fmt_ptrn_t *);
extern gboolean config_t_valid(const config_t *);
extern int exists(const char *);
extern void l0g(const char *, ...);
extern void log_argv(const char * const *);
extern gboolean owns(const char *, const char *);
extern gboolean pm_command_t_valid(const pm_command_t *);
extern void set_myuid(void *);
extern gboolean static_string_valid(const char *, const size_t);
extern long str_to_long(const char *);
extern gboolean vol_t_valid(const vol_t *);
extern void w4rn(const char *, ...);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MISC_H
