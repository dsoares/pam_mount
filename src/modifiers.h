#ifndef PMT_MODIFIERS_H
#define PMT_MODIFIERS_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "buffer.h"
#include "fmt_ptrn.h"

#define MODIFIER_ARG_LEN 80

typedef struct modifier_fns_t {
    char *id;
    int (*fn)(buffer_t *, fmt_ptrn_t *, char *);
    int has_arg;
} modifier_fns_t;

typedef struct modifier_t {
    modifier_fns_t fn;
    char arg[MODIFIER_ARG_LEN + 1];
} modifier_t;

extern const modifier_fns_t mod_fn[];

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_MODIFIERS_H
