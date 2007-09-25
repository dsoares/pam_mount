#ifndef PMT_SPAWN_H
#define PMT_SPAWN_H 1

#include <stdbool.h>

/*
 *	SPAWN.C
 */
extern bool spawn_start(const char *const *, pid_t *, int *, int *, int *,
	void (*)(const char *), const char *);
extern int spawn_restore_sigchld(void);
extern int spawn_set_sigchld(void);

#endif /* PMT_SPAWN_H */
