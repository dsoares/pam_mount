#ifndef PMT_PAIR_H
#define PMT_PAIR_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

typedef struct pair_t {
    void *key;
    void *val;
    void (*destroy_k)(void *);
    void (*destroy_v)(void *);
} pair_t;

extern void pair_destroy(pair_t *);
extern void pair_init(pair_t *, void *, void *,
    void (*)(void *), void (*)(void *));
extern gboolean pair_t_valid(const pair_t *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_PAIR_H
