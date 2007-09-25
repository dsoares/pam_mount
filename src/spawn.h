#ifndef PMT_SPAWN_H
#define PMT_SPAWN_H 1

#include <glib.h>
#include <stdbool.h>

/*
 *	SPAWN.C
 */
extern bool spawn_apS(const char *const *, GSpawnChildSetupFunc, void *, int *,
	int *, int *, int *, GError **);
extern int spawn_restore_sigchld(void);
extern int spawn_set_sigchld(void);

#endif /* PMT_SPAWN_H */
