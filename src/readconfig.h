#ifndef PMT_READCONFIG_H
#define PMT_READCONFIG_H 1

#include <stdbool.h>

struct config;

/*
 *	RDCONF1.C
 */
extern int expandconfig(const struct config *);
extern void initconfig(struct config *);
extern int readconfig(const char *, int, struct config *);
extern void freeconfig(struct config *);

/*
 *	RDCONF2.C
 */
extern bool luserconf_volume_record_sane(const struct config *, int);
extern bool volume_record_sane(const struct config *, int);

#endif /* PMT_READCONFIG_H */
