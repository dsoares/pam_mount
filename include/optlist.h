#ifndef _OPTLIST_H
#define _OPTLIST_H

#include <list.h>
#include <pair.h>

typedef list_t optlist_t;
typedef list_element_t optlist_element_t;

/* ============================ str_to_optlist () ========================== */
int str_to_optlist (optlist_t *optlist, const char *str);

/* ============================ optlist_exists () ========================== */
int optlist_exists (const optlist_t *optlist, const char *str);

/* ============================ optlist_value () =========================== */
char *optlist_value (const optlist_t *optlist, const char *str);

/* ============================ optlist_to_str () ========================== */
char *optlist_to_str (char *str, const optlist_t *optlist);

/* ============================ optlist_len () ============================= */
#define optlist_len(list) ((list)->size)

/* ============================ optlist_free () ============================ */
#define optlist_free(list) list_destroy(list)

/* ============================ optlist_head () ============================ */
#define optlist_head(list) ((list)->head)

/* ============================ optlist_key () ============================= */
#define optlist_key(element) ((pair_t *) (element)->data)->key

/* ============================ optlist_val () ============================= */
#define optlist_val(element) ((pair_t *) (element)->data)->val

/* ============================ optlist_next () ============================ */
#define optlist_next(element) ((element)->next)

#endif /* _OPTLIST_H */
