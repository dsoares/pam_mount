#ifndef PMT_READCONFIG_H
#define PMT_READCONFIG_H 1

#include <stdbool.h>

struct config;

/*
 *	RDCONF1.C
 */
extern bool expandconfig(const struct config *);
extern void initconfig(struct config *);
extern bool readconfig(const char *, bool, struct config *);
extern void freeconfig(struct config *);

/*
 *	RDCONF2.C
 */
extern bool luserconf_volume_record_sane(const struct config *, const struct vol *);
extern bool volume_record_sane(const struct config *, const struct vol *);

#endif /* PMT_READCONFIG_H */
