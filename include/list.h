/*   FILE: list.h --
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 10 Febuary 2000
 *   NOTE: From _Mastering Algorithms with C_ by Kyle Loudon.
 */

#ifndef _LIST_H
#define _LIST_H

#ifdef __cplusplus
extern "C" {
#endif

/* ============================ list_element_t ============================= */
	typedef struct list_element_t {
		void *data;
		struct list_element_t *next;
	} list_element_t;

/* ============================ list_t ===================================== */
	typedef struct list_t {
		int size;
		int (*match) (const void *key_1, const void *key_2);
		void (*destroy) (void *data);
		list_element_t *head;
		list_element_t *tail;
	} list_t;

/* ============================ list_init () =============================== */
	void list_init(list_t * list, void (*destroy) (void *data));

/* ============================ list_destroy () ============================ */
	void list_destroy(list_t * list);

/* ============================ list_ins_next () =========================== */
	int list_ins_next(list_t * list, list_element_t * element,
			  const void *data);

/* ============================ list_rem_next () =========================== */
	int list_rem_next(list_t * list, list_element_t * element,
			  void **data);

/* ============================ list_size () =============================== */
#define list_size(list) ((list)->size)

/* ============================ list_head () =============================== */
#define list_head(list) ((list)->head)

/* ============================ list_tail () =============================== */
#define list_tail(list) ((list)->tail)

/* ============================ list_is_head () ============================ */
#define list_is_head(list, element) ((element) == (list)->head ? 1 : 0)

/* ============================ list_is_tail () ============================ */
#define list_is_tail(element) ((element)->next == NULL ? 1 : 0)

/* ============================ list_data () =============================== */
#define list_data(element) ((element)->data)

/* ============================ list_next () =============================== */
#define list_next(element) ((element)->next)
#ifdef __cplusplus
}
#endif
#endif				/* _BISTREE_H */
