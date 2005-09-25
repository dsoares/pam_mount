#ifndef PMT_COMMON_H
#define PMT_COMMON_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <dirent.h>
#include "fmt_ptrn.h"

extern void initialize_fillers(fmt_ptrn_t *);
extern void initialize_fillers_from_file(fmt_ptrn_t *, char *);
extern void print_dir(DIR *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_COMMON_H
