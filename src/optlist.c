#include <optlist.h>
#include <stdlib.h>
#include <optlist.h>
#include <pam_mount.h>

/* ============================ _parse_string_opt () ======================= */
/* PRE:    str points to a valid string
 *         len <= strlen(str), should be length up to first ',' or 0x00
 *         optlist points to a valid optlist_t
 * POST:   str[0 - len] has been parsed and placed in optlist
 * FN VAL: if error 0 else 1
 */
static int _parse_string_opt(const char *str, size_t len,
			     optlist_t * optlist)
{
	pair_t *pair;
	char *delim = strchr(str, '='), *key, *val;
	if (!delim)
		return 0;
	if (len > MAX_PAR || len <= 0)
		return 0;
	if (!delim || delim - str >= len)
		return 0;
	pair = (pair_t *) malloc(sizeof(pair_t));
	key = (char *) malloc(sizeof(char) * (delim - str) + 1);
	val = (char *) malloc(sizeof(char) * len - (delim - str));	/* '=' is +1 */
	if (!pair || !key || !val)
		return 0;
	strncpy(key, str, delim - str);
	key[delim - str] = 0x00;
	strncpy(val, delim + 1, len - (delim - str) - 1);
	val[len - (delim - str) - 1] = 0x00;
	pair_init(pair, key, val, free, free);
	list_ins_next(optlist, optlist->tail, pair);
	return 1;
}

/* ============================ _parse_opt () ============================== */
/* PRE:    str points to a valid string
 *         len <= strlen(str), should be length up to first ',' or 0x00
 *         optlist points to a valid optlist_t
 * POST:   str[0 - len] has been parsed and placed in optlist
 * FN VAL: if error 0 else 1
 */
static int _parse_opt(const char *str, size_t len, optlist_t * optlist)
{
	pair_t *pair;
	char *key, *val;
	if (len > MAX_PAR || len <= 0)
		return 0;
	pair = (pair_t *) malloc(sizeof(pair_t));
	key = malloc(sizeof(char) * len + 1);
	val = malloc(1);
	if (!pair || !key || !val)
		return 0;
	strncpy(key, str, len);
	key[len] = 0x00;
	*val = 0x00;
	pair_init(pair, key, val, free, free);
	list_ins_next(optlist, optlist->tail, pair);
	return 1;
}

/* ============================ str_to_optlist () ========================== */
/* PRE:    optlist is a valid optlist_t
 *         str points to a valid string
 * POST:   optlist points to an optlist_t initialized to contain str
 * FN VAL: if error 0 else 1
 */
int str_to_optlist(optlist_t * optlist, const char *str)
{
	list_init(optlist, pair_destroy);
	char *ptr;
	if (!strlen(str))
		return 1;
	while (ptr = strchr(str, ',')) {
		if (!_parse_string_opt(str, ptr - str, optlist))
			if (!_parse_opt(str, ptr - str, optlist))
				return 0;
		str = ptr + 1;
	}
	if (!_parse_string_opt(str, strlen(str), optlist))
		if (!_parse_opt(str, strlen(str), optlist))
			return 0;
	return 1;
}

/* ============================ optlist_exists () ========================== */
/* PRE:    optlist points to a valid optlist_t
 *         str points to a valid string
 * FN VAL: if optlist[str] exists 1 else 0
 */
int optlist_exists(const optlist_t * optlist, const char *str)
{
	optlist_element_t *ptr = optlist_head(optlist);
	do {
		if (!strcmp(((pair_t *) ptr->data)->key, str))
			return 1;
	} while (ptr = optlist_next(ptr));
	return 0;
}

/* ============================ optlist_value () =========================== */
/* PRE:    optlist points to a valid optlist_t
 *         str points to a valid string
 * FN VAL: optlist[str] ("" if no value) else NULL
 */
char *optlist_value(const optlist_t * optlist, const char *str)
{
	optlist_element_t *ptr = optlist_head(optlist);
	do {
		if (!strcmp(((pair_t *) ptr->data)->key, str))
			return ((pair_t *) ptr->data)->val;
	} while (ptr = optlist_next(ptr));
	return NULL;
}

/* ============================ optlist_to_str () ========================== */
/* PRE:    str points to a valid string != NULL
 *         sizeof str >= MAX_PAR + 1
 *         optlist points a valid optlist_t
 * FN VAL: string encapsulating optlist
 */
char *optlist_to_str(char *str, const optlist_t * optlist)
{
	optlist_element_t *ptr = optlist_head(optlist);
	*str = 0x00;
	do {
		strncat(str, ((pair_t *) ptr->data)->key,
			MAX_PAR - strlen(str));
		if (strlen(((pair_t *) ptr->data)->val)) {
			strncat(str, "=", MAX_PAR - strlen(str));
			strncat(str, ((pair_t *) ptr->data)->val,
				MAX_PAR - strlen(str));
		}
		if (ptr = optlist_next(ptr))
			strncat(str, ",", MAX_PAR - strlen(str));
	} while (ptr);
	str[MAX_PAR] = 0x00;
	return str;
}
