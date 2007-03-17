#ifndef PMT_BUFFER_H
#define PMT_BUFFER_H 1

#include <sys/types.h>
#include <stdio.h>

struct buffer {
	char *data;  /* '\0'-terminated string */
	size_t size; /* allocated length, not string length */
};

/*
 *	BUFFER.C
 */
extern void buffer_clear(struct buffer *);
extern void buffer_eat(struct buffer *, size_t);
extern size_t buffer_len(const struct buffer *);
extern int buffer_valid(const struct buffer *);
extern void realloc_n_cat(struct buffer *, const char *);
extern void realloc_n_cpy(struct buffer *, const char *);
extern void realloc_n_ncat(struct buffer *, const char *, size_t);

/*
 *	INLINE FUNCTIONS
 */
static inline void buffer_init(struct buffer *x)
{
	x->size = 0;
	x->data = NULL;
	return;
}

#endif /* PMT_BUFFER_H */
