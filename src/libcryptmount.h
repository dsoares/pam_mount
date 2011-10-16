#ifndef _CRYPTMOUNT_H
#define _CRYPTMOUNT_H 1

#include <libHX/string.h>
#ifndef __cplusplus
#	include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Result codes for ehd_cipherdigest_security
 * (negative indicates system error code).
 *
 * %EHD_SECURITY_BLACKLISTED:	cipher/digest classified as absolute no-go
 * %EHD_SECURITY_SUBPAR:	use of cipher/digest is disrecommended
 * %EHD_SECURITY_UNSPEC:	no verdict
 * %EHD_SECURITY_ADEQUATE:	cipher/digest passes
 *
 * Ordering is supported, x < %EHD_SECURITY_* may be used.
 */
enum {
	EHD_SECURITY_BLACKLISTED = 0,
	EHD_SECURITY_SUBPAR,
	EHD_SECURITY_UNSPEC,
	EHD_SECURITY_ADEQUATE,
};

extern int cryptmount_init(void);
extern void cryptmount_exit(void);

extern int ehd_cipherdigest_security(const char *);
extern hxmc_t *ehd_get_password(const char *);

/*
 *	loop.c
 */
enum {
	EHD_LOSETUP_RW = 0,
	EHD_LOSETUP_RO = 1,
};

extern int ehd_loop_setup(const char *, char **, bool);
extern int ehd_loop_release(const char *);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _CRYPTMOUNT_H */
