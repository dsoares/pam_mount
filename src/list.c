/*   FILE: list.c --
 * AUTHOR: W. Michael Petullo <new@flyn.org>
 *   DATE: 10 Febuary 2000
 *   NOTE: From _Mastering Algorithms with C_ by Kyle Loudon.
 */

#include <stdlib.h>
#include <string.h>
#include <list.h>

/* ============================ list_init () =============================== */
void list_init(list_t * list, void (*destroy) (void *data))
{
    list->size = 0;
    list->destroy = destroy;
    list->head = NULL;
    list->tail = NULL;
}

/* ============================ list_destroy () ============================ */
void list_destroy(list_t * list)
{
    void *data;
    while (list_size(list) > 0) {
	if (list_rem_next(list, NULL, (void **) &data) == 0
	    && list->destroy != NULL)
	    list->destroy(data);
    }
    memset(list, 0, sizeof(list_t));
}

/* ============================ list_ins_next () =========================== */ 
int list_ins_next (list_t *list, list_element_t *element, const void *data)
{
	list_element_t *new_element;
	if ((new_element = (list_element_t *) malloc (sizeof (list_element_t))) == NULL)
		return -1;
	new_element->data = (void *) data;
	if (element == NULL) {
		if (list_size(list) == 0)
			list->tail = new_element;
		new_element->next = list->head;
		list->head = new_element;
	} else {
		if (element->next == NULL)
			list->tail = new_element;
		new_element->next = element->next;
		element->next = new_element;
	}
	list->size++;
	return 0;
}

/* ============================ list_rem_next () =========================== */ 
int list_rem_next (list_t *list, list_element_t *element, void **data)
{
	list_element_t *old_element;
	if (list_size(list) == 0)
		return -1;
	if (element == NULL) {
		*data = list->head->data;
		old_element = list->head;
		list->head = list->head->next;
		if (list_size(list) == 0)
			list->tail = NULL;
	} else {
		if (element->next == NULL)
			return -1;
		*data = element->next->data;
		old_element = element->next;
		element->next = element->next->next;
		if (element->next == NULL)
			list->tail = element;
	}
	free(old_element);
	list->size--;
	return 0;
}
