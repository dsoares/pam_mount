#ifndef PMT_OPTLIST_H
#define PMT_OPTLIST_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

#define optlist_next(element) g_list_next(element)
#define optlist_key(element) (((pair_t *)(element)->data)->key)
#define optlist_val(element) (((pair_t *)(element)->data)->val)

//define optlist_len(list) g_list_length(list)
//define optlist_next(element) g_list_next(element)

typedef GList optlist_t;

extern gboolean optlist_exists(optlist_t *, const char *);
extern char *optlist_to_str(char *, const optlist_t *);
extern const char *optlist_value(optlist_t *, const char *);
extern gboolean str_to_oplist(optlist_t **, const char *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_OPTLIST_H
