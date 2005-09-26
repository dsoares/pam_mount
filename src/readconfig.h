#ifndef PMT_READCONFIG_H
#define PMT_READCONFIG_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include "dotconf.h"
#include "private.h"

extern int expandconfig(const config_t *);
extern void freeconfig(config_t);
extern int initconfig(config_t *);
extern gboolean luserconf_volume_record_sane(const config_t *, int);
extern int readconfig(const char *, const char *, int, config_t *);
extern DOTCONF_CB(read_volume);
extern gboolean volume_record_sane(const config_t *, int);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_READCONFIG_H
