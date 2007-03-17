#ifndef PMT_PAIR_H
#define PMT_PAIR_H 1

struct pair {
	void *key;
	void *val;
	void (*destroy_k)(void *);
	void (*destroy_v)(void *);
};

/*
 *	PAIR.C
 */
extern void pair_destroy(struct pair *);
extern void pair_init(struct pair *, void *, void *,
	void (*)(void *), void (*)(void *));
extern int pair_valid(const struct pair *);

#endif /* PMT_PAIR_H */
