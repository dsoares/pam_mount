#ifndef PMT_SPAWN_H
#define PMT_SPAWN_H 1

#include <glib.h>

/*
 *	SPAWN.C
 */
extern int spawn_apS(const char *, const char *const *, const char *const *,
	GSpawnFlags, GSpawnChildSetupFunc, void *, int *, int *, int *, int *,
	GError **);
extern int spawn_restore_sigchld(void);
extern int spawn_set_sigchld(void);

#endif /* PMT_SPAWN_H */
