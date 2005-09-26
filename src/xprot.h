#ifndef PMT_XPROT_H
#define PMT_XPROT_H 1

#ifdef __cplusplus
extern "C" {
#endif

// The most ugliest file.

#include <glib.h>

static inline gboolean spawn_ap0(const char *wd, const char *const *argv,
 const char *const *envp, GSpawnFlags flags, GSpawnChildSetupFunc cs,
 void *data, int *pid, int *istdin, int *istdout, int *istderr, GError **err)
{
    return g_spawn_async_with_pipes(wd, (char **)argv, (char **)envp, flags,
     cs, data, pid, istdin, istdout, istderr, err);
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_XPROT_H
