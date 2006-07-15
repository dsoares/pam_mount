/*=============================================================================
dotconf.h
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2006

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to:
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
  Boston, MA  02110-1301  USA

  -- For details, see the file named "LICENSE.LGPL2"
=============================================================================*/
#ifndef PMT_DOTCONF_H
#define PMT_DOTCONF_H 1

#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DOTCONF_CB(__name) const char *__name(const command_t *cmd, context_t *ctx)
#define CTX_ALL 0 // context: option can be used anywhere
#define LAST_OPTION              {"", 0, NULL, NULL}
#define FUNC_ERRORHANDLER(_name) int _name(struct configfile *configfile, \
                                 int type, long dc_errno, const char *msg)

// constants for type of option
enum {
    ARG_TOGGLE = 0,
    ARG_INT,
    ARG_STR,
    ARG_LIST,
    ARG_NAME,
    ARG_RAW,
    ARG_NONE,
};

struct configfile;

typedef void info_t;
typedef void context_t;
typedef struct command command_t;
typedef const char *(*dotconf_callback_t)(const command_t *, context_t *);
typedef int (*dotconf_errorhandler_t)(const struct configfile *, int, unsigned long, const char *);
typedef const char *(*dotconf_contextchecker_t)(command_t *, unsigned long);

struct command {
    const char *name;             		/* name of the command */
    struct configoption *option;		/* the option as given in the app; READ ONLY */

    // argument data filled in for each line / command
    struct {
        long value;     // ARG_INT, ARG_TOGGLE
        char *str;      // ARG_STR
        char **list;    // ARG_LIST
    } data;
    int arg_count;      // number of arguments (in data.list)

    // misc context information
    const struct configfile *configfile;
    context_t *context;
};

struct configfile {
    /* ------ the fields in struct configfile are provided to the app
    via command_t's ; READ ONLY! --- */

    FILE *stream;
    char eof;           // end of file reached?
    size_t size;        // file size; cached on-demand for here-documents

    context_t *context;

    const struct configoption **config_options;
    int config_option_count;

    // misc read-only fields
    char *filename;             // name of file this option was found in
    unsigned long line;         // line number we're currently at
    unsigned long flags;        // runtime flags given to dotconf_open

    char *includepath;

    // some callbacks for interactivity
    dotconf_errorhandler_t errorhandler;
    dotconf_contextchecker_t contextchecker;
    int (*cmp_func)(const char *, const char *, size_t);
};

struct configoption {
    const char *name;								/* name of configuration option */
    int type;										/* for possible values, see above */
    dotconf_callback_t callback;        // callback function
    info_t *info;									/* additional info for multi-option callbacks */
    unsigned long context;              // context sensitivity flags
};

extern void dotconf_cleanup(struct configfile *);
extern int dotconf_command_loop(struct configfile *);
extern struct configfile *dotconf_create(const char *,
    const struct configoption *, context_t *, unsigned long);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_DOTCONF_H

//=============================================================================
