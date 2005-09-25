/* dot.conf - configuration file parser library
 * Copyright (C) 1999,2000,2001,2002 Lukas Schroeder <lukas@azzit.de>,
 *   and others.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 *
 */

/* -- dotconf.c - this code is responsible for the input, parsing and dispatching of options  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Added by Stephen W. Boyer <sboyer@caldera.com>
 * for wildcard support in Include file paths
 */
/* -- AIX 4.3 compile time fix
 * by Eduardo Marcel Macan <macan@colband.com.br>
 * modified by Stephen W. Boyer <sboyer@caldera.com>
 * for Unixware and OpenServer
 */

#include <config.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_SYSLOG
#    include <syslog.h>
#endif

#include "dotconf.h"

// some buffersize definitions
#define CFG_BUFSIZE             4096    // max length of one line */
#define CFG_MAX_OPTION          32	// max length of any option name */
#define CFG_MAX_VALUE           4064    // max length of any options value */
#define CFG_MAX_FILENAME        256     // max length of a filename */
#define CFG_VALUES              16      // max # of arguments an option takes */

#define CFG_INCLUDEPATH_ENV "DC_INCLUDEPATH"
#define WILDCARDS "*?" // list of supported wild-card characters

#define CFG_TOGGLED(_val) ( \
    (*_val == 'Y' || *_val == 'y') || \
    (*_val == '1') || ( \
        (_val[0] == 'o' || _val[0] == 'O') && \
        (_val[1] == 'n' || _val[1] == 'N') \
    ) \
)

// for convenience of terminating the dotconf_options list
#define LAST_CONTEXT_OPTION     {"", 0, NULL, NULL, 0}

// some flags that change the runtime behaviour of dotconf
#define NONE                   0
#define CASE_INSENSITIVE       (1 << 0) // match option names case insensitive
#define DONT_SUBSTITUTE        (1 << 1) // do not call substitute_env after read_arg
#define NO_INLINE_COMMENTS     (1 << 2) // do not allow inline comments
#define DUPLICATE_OPTION_NAMES (1 << 3) // allow for duplicate option names

// syslog style errors as suggested by Sander Steffann <sander@steffann.nl>
#ifdef HAVE_SYSLOG
#    define DCLOG_EMERG         LOG_EMERG
#    define DCLOG_ALERT         LOG_ALERT
#    define DCLOG_CRIT          LOG_CRIT
#    define DCLOG_ERR           LOG_ERR
#    define DCLOG_WARNING       LOG_WARNING
#    define DCLOG_NOTICE        LOG_NOTICE
#    define DCLOG_INFO          LOG_INFO
#    define DCLOG_DEBUG         LOG_DEBUG
#    define DCLOG_LEVELMASK     LOG_PRIMASK
#else
    enum {
        DCLOG_EMERG = 0,
        DCLOG_ALERT,
        DCLOG_CRIT,
        DCLOG_ERR,
        DCLOG_WARNING,
        DCLOG_NOTICE,
        DCLOG_INFO,
        DCLOG_DEBUG,
    };
#    define DCLOG_LEVELMASK 7 // mask off the level value
#endif // HAVE_SYSLOG

// error constants
enum {
    ERR_NOERROR = 0,
    ERR_PARSE_ERROR,
    ERR_UNKNOWN_OPTION,
    ERR_WRONG_ARG_COUNT,
    ERR_INCLUDE_ERROR,
    ERR_NOACCESS,
    ERR_USER = 0x1000, // base for userdefined errno's
};

enum callback_types
{
	ERROR_HANDLER = 1,
	CONTEXT_CHECKER
};

typedef enum callback_types callback_types;

static const configoption_t *get_argname_fallback(const configoption_t *);
static void copy_word(char **, char **, int, char);
static DOTCONF_CB(dotconf_cb_include);          // internal 'Include'
static DOTCONF_CB(dotconf_cb_includepath);      // internal 'IncludePath'
static int dotconf_continue_line(char *, size_t);
static int dotconf_find_wild_card(char *, char *, char **, char **, char **);
static void dotconf_free_command(command_t *);
static char *dotconf_get_here_document(configfile_t *, const char *);
static int dotconf_get_next_line(char *, size_t, configfile_t *);
static const char *dotconf_handle_command(configfile_t *, char *);
static int dotconf_handle_star(command_t *, char *, char *, char *);
static int dotconf_handle_question_mark(command_t *, char *, char *, char *);
static int dotconf_handle_wild_card(command_t *, char, char *, char *, char *);
static const char *dotconf_invoke_command(configfile_t *, command_t *);
static int dotconf_is_wild_card(char);
static int dotconf_question_mark_match(char *, char *, char *);
static char *dotconf_read_arg(configfile_t *, char **);
static void dotconf_register_options(configfile_t *, const configoption_t *);
static void dotconf_set_command(configfile_t *, const configoption_t *,
    char *, command_t *);
static int dotconf_star_match(char *, char *, char *);
static int dotconf_strcmp_from_back(const char *, const char *);
static char *dotconf_substitute_env(configfile_t *, char *);
static int dotconf_warning(configfile_t *, int, unsigned long, const char *, ...);
static void dotconf_wild_card_cleanup(char *, char *);
static void skip_whitespace(char **, int, char);
static inline long MIN(long, long);

static configoption_t dotconf_options[] =
{
	{ "Include", ARG_STR, dotconf_cb_include, NULL, CTX_ALL },
	{ "IncludePath", ARG_STR, dotconf_cb_includepath, NULL, CTX_ALL },
	LAST_CONTEXT_OPTION
};

static char name[CFG_MAX_OPTION + 1]; // option name

static void skip_whitespace(char **cp, int n, char term)
{
	char *cp1 = *cp;
	while(isspace(*cp1) && *cp1 != term && n--)
		cp1++;
	*cp = cp1;
}

static void copy_word(char **dest, char **src, int max, char term)
{
	char *cp1 = *src;
	char *cp2 = *dest;
	while(max-- && !isspace(*cp1) && *cp1 != term)
		*cp2++ = *cp1++;
	*cp2 = '\0';

	*src = cp1;
	*dest = cp2;
}

static const configoption_t *get_argname_fallback(const configoption_t *options)
{
	int i;

	for(i = 0; options[i].name != NULL && options[i].name[0] != '\0'; i++);
	if(options[i].type == ARG_NAME && options[i].callback != NULL)
		return &options[i];
	return NULL;
}

static char *dotconf_substitute_env(configfile_t *configfile, char *str) {
	char *cp1, *cp2, *cp3, *eos, *eob;
	char *env_value;
	char env_name[CFG_MAX_VALUE + 1];
	char env_default[CFG_MAX_VALUE + 1];
	char tmp_value[CFG_MAX_VALUE + 1];

	memset(env_name, 0, sizeof(env_name));
	memset(env_default, 0, sizeof(env_default));
	memset(tmp_value, 0, sizeof(tmp_value));

	cp1 = str;
	eob = cp1 + strlen(str) + 1;
	cp2 = tmp_value;
	eos = cp2 + sizeof(tmp_value);

	while(cp1 < eob && cp2 < eos && *cp1 != '\0') {
		/* substitution needed ?? */
		if (*cp1 == '$' && *(cp1 + 1) == '{')
		{
			cp1 += 2;			/* skip ${ */
			cp3 = env_name;
			while(cp1 < eob && !(*cp1 == '}' || *cp1 == ':'))
				*cp3++ = *cp1++;
			*cp3 = '\0';		/* terminate */

			/* default substitution */
			if (*cp1 == ':' && *(cp1 + 1) == '-')
			{
				cp1 += 2;		/* skip :- */
				cp3 = env_default;
				while(cp1 < eob && *cp1 != '}')
					*cp3++ = *cp1++;
				*cp3 = '\0';	/* terminate */
			}
			else
			{
				while(cp1 < eob && *cp1 != '}')
					cp1++;
			}

			if (*cp1 != '}')
			{
				dotconf_warning(configfile, DCLOG_WARNING, ERR_PARSE_ERROR,
					"Unbalanced '{'");
			}
			else
			{
				cp1++;			/* skip } */
				if ((env_value = getenv(env_name)) != NULL)
				{
					strncat(cp2, env_value, eos - cp2);
					cp2 += strlen(env_value);
				}
				else
				{
					strncat(cp2, env_default, eos - cp2);
					cp2 += strlen(env_default);
				}
			}

		}

		*cp2++ = *cp1++;
	}
	*cp2 = '\0';				/* terminate buffer */

	free(str);
	return strdup(tmp_value);
}

static int dotconf_warning(configfile_t *configfile, int type,
 unsigned long errnum, const char *fmt, ...)
{
	va_list args;
	int retval = 0;

	va_start(args, fmt);
	if(configfile->errorhandler != NULL) {	/* an errorhandler is registered */
		char msg[CFG_BUFSIZE];
		vsnprintf(msg, sizeof(msg), fmt, args);
		retval = configfile->errorhandler(configfile, type, errnum, msg);
	}
	else						/* no errorhandler, do-it-yourself */
	{
		retval = 0;
		fprintf(stderr, "%s:%ld: ", configfile->filename, configfile->line);
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
	}
	va_end(args);

	return retval;
}

static void dotconf_register_options(configfile_t *configfile,
 const configoption_t * options)
{
	int num = configfile->config_option_count;

#define GROW_BY   10

	/* resize memoryblock for options blockwise */
	if (configfile->config_options == NULL)
		configfile->config_options = malloc(sizeof(void *) * (GROW_BY + 1));
	else
	{
		if((num % GROW_BY) == 0)
			configfile->config_options = realloc(configfile->config_options,
											 sizeof(void *) * (num + GROW_BY + 1));
	}

#undef GROW_BY

	/* append new options */
	configfile->config_options[configfile->config_option_count] = options;
	configfile->config_options[++configfile->config_option_count] = NULL;

}

static int dotconf_continue_line(char *buffer, size_t length) {
	/* ------ match [^\\]\\[\r]\n ------------------------------ */
	char *cp1 = buffer + length - 1;

	if (length < 2)
		return 0;

	if (*cp1-- != '\n')
		return 0;

	if (*cp1 == '\r')
		cp1--;

	if (*cp1-- != '\\')
		return 0;

	cp1[1] = '\0'; /* strip escape character and/or newline */
	return *cp1 != '\\';
}

static int dotconf_get_next_line(char *buffer, size_t bufsize,
 configfile_t *configfile)
{
	char *cp1, *cp2;
	char buf2[CFG_BUFSIZE];
	int length;

	if (configfile->eof)
		return 1;

	cp1 = fgets(buffer, CFG_BUFSIZE, configfile->stream);

	if(cp1 == NULL) {
		configfile->eof = 1;
		return 1;
	}

	configfile->line++;
	length = strlen(cp1);
	while ( dotconf_continue_line(cp1, length) )
	{
		cp2 = fgets(buf2, sizeof(buf2), configfile->stream);
		if(cp2 == NULL) {
			fprintf(stderr, "[dotconf] Parse error. Unexpected end of file at "
					"line %ld in file %s\n", configfile->line, configfile->filename);
			configfile->eof = 1;
			return 1;
		}
		configfile->line++;
		strcpy(cp1 + length - 2, cp2);
		length = strlen(cp1);
	}

	return 0;
}

static char *dotconf_get_here_document(configfile_t *configfile,
 const char *delimit)
{
	/* it's a here-document: yeah, what a cool feature ;) */
	unsigned int limit_len;
	char here_string;
	char buffer[CFG_BUFSIZE];
	char *here_doc = NULL;
	char here_limit[9];	                       /* max length for here-document delimiter: 8 */
	struct stat finfo;
	int offset = 0;

	if (configfile->size <= 0)
	{
		if(stat(configfile->filename, &finfo) != 0)
		{
			dotconf_warning(configfile, DCLOG_EMERG, ERR_NOACCESS,
						   "[emerg] could not stat currently read file (%s)\n",
							configfile->filename);
			return NULL;
		}
		configfile->size = finfo.st_size;
	}

	/*
	 * allocate a buffer of filesize bytes; should be enough to
	 * prevent buffer overflows
	 */
	here_doc = malloc(configfile->size);	/* allocate buffer memory */
	memset(here_doc, 0, configfile->size);

	here_string = 1;
	limit_len = snprintf(here_limit, 9, "%s", delimit);
	while (!dotconf_get_next_line(buffer, sizeof(buffer), configfile))
	{
		if(strncmp(here_limit, buffer, limit_len - 1) == 0) {
			here_string = 0;
			break;
		}
		offset += snprintf(here_doc + offset, configfile->size - offset - 1, "%s", buffer);
	}
	if (here_string)
		dotconf_warning(configfile, DCLOG_WARNING, ERR_PARSE_ERROR, "Unterminated here-document!");

	here_doc[offset-1] = '\0';	/* strip newline */

	return realloc(here_doc, offset);
}

static const char *dotconf_invoke_command(configfile_t *configfile,
 command_t *cmd)
{
	return cmd->option->callback(cmd, configfile->context);
}

static char *dotconf_read_arg(configfile_t *configfile, char **line) {
	int sq = 0, dq = 0;							/* single quote, double quote */
	int done = 0;
	char *cp1 = *line;
	char *cp2, *eos;
	char buf[CFG_MAX_VALUE];

	memset(buf, 0, sizeof(buf));
	cp2 = buf;
	eos = cp2 + sizeof(buf) - 1;

	if(*cp1 == '#' || *cp1 == '\0')
		return NULL;

	skip_whitespace(&cp1, CFG_MAX_VALUE, '\0');

	while(*cp1 != '\0' && cp2 != eos && !done) {
		switch (*cp1) {
			case '\'':					/* single quote */
				if (dq)
					break;					/* already double quoting, break out */
				if (sq)
					sq--;					/* already single quoting, clear state */
				else if (!sq)
					sq++;					/* set state for single quoting */
				break;
			case '"':					/* double quote */
				if (sq)
					break;					/* already single quoting, break out */
				if (dq)
					dq--;					/* already double quoting, clear state */
				else if (!dq)
					dq++;					/* set state for double quoting */
				break;
			case '\\':					/* protected chars */
				if(cp1[1] == '\0')			/* dont protect NUL */
					break;
				if (sq) 			/* preserve '\' if in single quote */
					break;
				else {
					*cp2++ = *++cp1;
					cp1++;					/* skip the protected one */
				    continue;
				}
				break;
			default:
				break;
		}

		/* unquoted space: start a new option argument */
		if (isspace(*cp1) && !dq && !sq) {
			*cp2 = '\0';
			break;
		}
		/* unquoted, unescaped comment-hash ; break out, unless NO_INLINE_COMMENTS is set */
		else if (*cp1 == '#' && !dq && !sq && !(configfile->flags & NO_INLINE_COMMENTS)) {
			/* 
			 * NOTE: 1.0.8a got the NO_INLINE_COMMENTS feature wrong: it
             * skipped every argument starting with a #, instead of simply eating it!
			 */

			*cp2 = *cp1 = '\0';
			*line = cp1;
			return NULL;
		}
		/* not space or quoted: eat it; dont take quote if quoting */
		else if((!isspace(*cp1) && !dq && !sq && *cp1 != '"' && *cp1 != '\'')
				   || (dq && *cp1 != '"') || (sq && *cp1 != '\'')) {
			*cp2++ = *cp1;
		}

		cp1++;
	}

	*line = cp1;

	/* FIXME: escaping substitutes does not work
		Subst ${HOME} \$\{HOME\}
		BOTH! will be substituted, which is somewhat wrong, ain't it ?? :-(
	*/
	if(configfile->flags & DONT_SUBSTITUTE)
		return (buf[0] != '\0') ? strdup(buf) : NULL;
 	return (buf[0] != '\0') ? dotconf_substitute_env(configfile, strdup(buf)) : NULL;
}

static void dotconf_set_command(configfile_t *configfile,
 const configoption_t *option, char *args, command_t *cmd)
{
	char *eob = args + strlen(args);

	/* fill in the command_t structure with values we already know */
	cmd->name = (option->type == ARG_NAME) ? name : option->name;
	cmd->option = (configoption_t *)option;
	cmd->context = configfile->context;
	cmd->configfile = configfile;
	cmd->data.list = (char **)calloc(CFG_VALUES, sizeof(char *));
	cmd->data.str = NULL;

	if (option->type == ARG_RAW) {
		/* if it is an ARG_RAW type, save some time and call the
		   callback now */
		cmd->data.str = strdup(args);
	}
	else if (option->type == ARG_STR) {
		char *cp = args;

		/* check if it's a here-document and act accordingly */
		skip_whitespace(&cp, eob - cp, '\0');

		if(strncmp("<<", cp, 2) == 0) {
			cmd->data.str = dotconf_get_here_document(configfile, cp + 2);
			cmd->arg_count = 1;
		}
	}

	if (!(option->type == ARG_STR && cmd->data.str != NULL)) {
		/* we only get here for non-heredocument lines */

		skip_whitespace(&args, eob - args, '\0');

		cmd->arg_count = 0;
		while ( cmd->arg_count < (CFG_VALUES - 1)
				&& (cmd->data.list[cmd->arg_count] = dotconf_read_arg(configfile, &args)) != NULL) {
			cmd->arg_count++;
		}

		skip_whitespace(&args, eob - args, '\0');

		if(cmd->arg_count > 0 && cmd->data.list[cmd->arg_count-1] != NULL && *args != '\0')
			cmd->data.list[cmd->arg_count++] = strdup(args);

		/* has an option entry been found before or do we have to use a fallback? */
		if((option->name != NULL && option->name[0] > ' ') || option->type == ARG_NAME) {
			/* found it, now check the type of args it wants */
			switch (option->type) {
				case ARG_TOGGLE:
					/* the value is true if the argument is Yes, On or 1 */
					if (cmd->arg_count < 1) {
						dotconf_warning(configfile, DCLOG_WARNING, ERR_WRONG_ARG_COUNT,
										"Missing argument to option '%s'", name);
						return;
					}

					cmd->data.value = CFG_TOGGLED(cmd->data.list[0]);
					break;
				case ARG_INT:
					if (cmd->arg_count < 1) {
						dotconf_warning(configfile, DCLOG_WARNING, ERR_WRONG_ARG_COUNT,
										"Missing argument to option '%s'", name);
						return;
					}

					if (sscanf(cmd->data.list[0], "%li", &cmd->data.value) < 1) {
						dotconf_warning(configfile, DCLOG_WARNING, ERR_WRONG_ARG_COUNT,
										"Error parsing '%s'", cmd->data.list[0]);
						return;
					}
					break;
				case ARG_STR:
					if (cmd->arg_count < 1) {
						dotconf_warning(configfile, DCLOG_WARNING, ERR_WRONG_ARG_COUNT,
										"Missing argument to option '%s'", name);
						return;
					}

					cmd->data.str = strdup(cmd->data.list[0]);
					break;
				case ARG_NAME:	/* fall through */
				case ARG_LIST:
				case ARG_NONE:
				case ARG_RAW:	/* this has been handled before */
				default:
					break;
			}
		}
	}
}

static void dotconf_free_command(command_t *command) {
	int i;

	free(command->data.str);
	for (i = 0; i < command->arg_count; i++)
		free(command->data.list[i]);
	free(command->data.list);
}

static const char *dotconf_handle_command(configfile_t *configfile,
 char *buffer)
{
	char *cp1; 
	char *cp2;
	/* generic char pointer      */
	char *eob;									/* end of buffer; end of string  */
	const char *error = NULL;         /* error message we'll return */
	const char *context_error = NULL; /* error message returned by contextchecker */
	command_t command;							/* command structure */
	int mod = 0;
	int next_opt_idx = 0;

	memset(&command, 0, sizeof(command));
	name[0] = '\0';

	cp1 = buffer;
	eob = cp1 + strlen(cp1);

	skip_whitespace(&cp1, eob - cp1, '\0');

	/* ignore comments and empty lines */
	if(cp1 == NULL || *cp1 == '\0' || *cp1 == '#' || *cp1 == '\n' || *cp1 == EOF)
		return NULL;

	/* skip line if it only contains whitespace */
	if (cp1 == eob)
		return NULL;

	/* get first token: read the name of a possible option */
	cp2 = name;
	copy_word(&cp2, &cp1, MIN(eob - cp1, CFG_MAX_OPTION), '\0');

	while (1) {
		const configoption_t *option;
		int done = 0;
		int opt_idx = 0;

		for(option = 0; configfile->config_options[mod] != NULL && !done; mod++) {
			for(opt_idx = next_opt_idx; configfile->config_options[mod][opt_idx].name[0] != '\0'; opt_idx++) {
				if(configfile->cmp_func(name, configfile->config_options[mod][opt_idx].name, CFG_MAX_OPTION) == 0) {
					/* TODO: this could be flagged: option overwriting by modules */
					option = (configoption_t *) &configfile->config_options[mod][opt_idx];
					done = 1;
					break;		/* found one; break out */
				}
			}
		}

		if(option == NULL)
			option = get_argname_fallback(configfile->config_options[1]);
		
		if(option == NULL || option->callback == NULL) {
			if(error != NULL)
				return error;
			dotconf_warning(configfile, DCLOG_INFO, ERR_UNKNOWN_OPTION,
							"Unknown Config-Option: '%s'", name);
			return NULL;
		}

		/* set up the command structure (contextchecker wants this) */
		dotconf_set_command(configfile, option, cp1, &command);

		if(configfile->contextchecker != NULL)
			context_error = configfile->contextchecker(&command, command.option->context);

		if(context_error == NULL)
			error = dotconf_invoke_command(configfile, &command);
		else {
			if(error == NULL) {
				/* avoid returning another error then the first. This makes it easier to
                   reproduce problems. */
				error = context_error;
			}
		}

		dotconf_free_command(&command);

		if(context_error == NULL || !(configfile->flags & DUPLICATE_OPTION_NAMES)) {
			/* don't try more, just quit now. */
			break;
		}
	}

	return error;
}

int dotconf_command_loop(configfile_t *configfile)
{
	/* ------ returns: 0 for failure -- !0 for success ------------------------------------------ */
	char buffer[CFG_BUFSIZE];

	while(!(dotconf_get_next_line(buffer, sizeof(buffer), configfile))) {
		const char *error = dotconf_handle_command(configfile, buffer);
		if ( error != NULL )
		{
			if ( dotconf_warning(configfile, DCLOG_ERR, 0, error) )
				return 0;
		}
	}
	return 1;
}

configfile_t *dotconf_create(const char *fname, const configoption_t *options,
                             context_t *context, unsigned long flags)
{
	configfile_t *new = NULL;
	char *dc_env;

	if (access(fname, R_OK))
	{
		fprintf(stderr, "Error opening configuration file '%s'\n", fname);
		return NULL;
	}

	new = calloc(1, sizeof(configfile_t));
	if((new->stream = fopen(fname, "r")) == NULL) {
		fprintf(stderr, "Error opening configuration file '%s'\n", fname);
		free(new);
		return NULL;
	}

	new->flags = flags;
	new->filename = strdup(fname);

	new->includepath = malloc(CFG_MAX_FILENAME);
	new->includepath[0] = '\0';

	/* take includepath from environment if present */
	if ((dc_env = getenv(CFG_INCLUDEPATH_ENV)) != NULL)
		snprintf(new->includepath, CFG_MAX_FILENAME, "%s", dc_env);

	new->context = context;

	dotconf_register_options(new, dotconf_options);
	dotconf_register_options(new, options);

	if ( new->flags & CASE_INSENSITIVE )
		new->cmp_func = strncasecmp;
	else
		new->cmp_func = strncmp;

	return new;
}

void dotconf_cleanup(configfile_t *configfile) {
    fclose(configfile->stream);
    free(configfile->filename);
    free(configfile->config_options);
    free(configfile->includepath);
    free(configfile);
    return;
}

/* ------ internal utility function that verifies if a character is in the WILDCARDS list -- */
static int dotconf_is_wild_card(char value) {
	int retval = 0;
	int i;
	int wildcards_len = strlen(WILDCARDS);

	for (i=0;i<wildcards_len;i++)
	{
		if (value == WILDCARDS[i])
		{
			retval = 1;
			break;
		}
	}

	return retval;
}

/* ------ internal utility function that calls the appropriate routine for the wildcard passed in -- */
static int dotconf_handle_wild_card(command_t *cmd, char wild_card, char *path,
 char *pre, char *ext)
{
	int retval = 0;

	switch (wild_card)
	{
		case '*':

			retval = dotconf_handle_star(cmd,path,pre,ext);

		break;

		case '?':

			retval = dotconf_handle_question_mark(cmd,path,pre,ext);

		break;

		default:
			retval = -1;
	}

	return retval;
}


/* ------ internal utility function that frees allocated memory from dotcont_find_wild_card -- */
static void dotconf_wild_card_cleanup(char *path, char *pre) {
    free(path);
    free(pre);
    return;
}

/* ------ internal utility function to check for wild cards in file path -- */
/* ------ path and pre must be freed by the developer ( dotconf_wild_card_cleanup) -- */
static int dotconf_find_wild_card(char *filename, char *wildcard, char **path,
 char **pre, char **ext)
{
	int retval = -1;
	int prefix_len = 0;
	int tmp_count = 0;
	char *tmp = NULL;
	int found_path = 0;

	int len = strlen(filename);

	if (wildcard != NULL && len > 0 && path != NULL && pre != NULL && ext != NULL )
	{
		prefix_len = strcspn(filename,WILDCARDS); /* find any wildcard in WILDCARDS */

		if ( prefix_len < len ) /* Wild card found */
		{
			tmp = filename + prefix_len;
			tmp_count = prefix_len + 1;

			while(tmp != filename && *tmp != '/') {
				tmp--;
				tmp_count--;
			}

			if(*tmp == '/') {
				*path = malloc(tmp_count+1);
				found_path = 1;

			} else

				*path = malloc(1);

			*pre = malloc(prefix_len - (tmp_count - (found_path ? 0 : 1)) + 1);

			if(*path != NULL && *pre != NULL) {
				if (found_path)
					strncpy(*path,filename,tmp_count);
				(*path)[tmp_count] = '\0';

				strncpy(*pre, tmp + (found_path ? 1 : 0),
				    prefix_len - (tmp_count - (found_path ? 0 : 1)));
				(*pre)[prefix_len - (tmp_count - (found_path ? 0 : 1))] = '\0';

				*ext = filename + prefix_len;
				*wildcard = **ext;
				(*ext)++;

				retval = prefix_len;

			}

		}

	}

	return retval;
}

/* ------ internal utility function that compares two stings from back to front -- */
static int dotconf_strcmp_from_back(const char *s1, const char *s2) {
	int retval = 0;
	int i,j;
	int len_1 = strlen(s1);
	int len_2 = strlen(s2);

	for(i = len_1, j = len_2; i >= 0 && j >= 0; i--, j--) {
		if (s1[i] != s2[j])
		{
			retval = -1;
			break;
		}
	}

	return retval;
}

/* ------ internal utility function that determins if a string matches the '?' criteria -- */
static int dotconf_question_mark_match(char *dir_name, char *pre, char *ext) {
	int retval = -1;
	int dir_name_len = strlen(dir_name);
	int pre_len = strlen(pre);
	int ext_len = strlen(ext);
	int w_card_check = strcspn(ext,WILDCARDS);

	if(w_card_check < ext_len && strncmp(dir_name, pre, pre_len) == 0 &&
	    strcmp(dir_name, ".") != 0 && strcmp(dir_name, "..") != 0)
	{
		retval = 1;    /* Another wildcard found */

	} else {

		if(dir_name_len >= pre_len &&
			 strncmp(dir_name, pre, pre_len) == 0 &&
			 strcmp(dir_name, ".") != 0 &&
			 strcmp(dir_name, "..") != 0)
		{
			retval = 0; /* Matches no other wildcards */
		}

	}

	return retval;
}

/* ------ internal utility function that determins if a string matches the '*' criteria -- */
static int dotconf_star_match(char *dir_name, char *pre, char *ext) {
	int retval = -1;
	int dir_name_len = strlen(dir_name);
	int pre_len = strlen(pre);
	int ext_len = strlen(ext);
	int w_card_check = strcspn(ext,WILDCARDS);

	if(w_card_check < ext_len && strncmp(dir_name, pre, pre_len) == 0 &&
	    strcmp(dir_name, ".") != 0 && strcmp(dir_name, "..") != 0)
	{
		retval = 1;    /* Another wildcard found */

	} else {

		if(dir_name_len >= ext_len + pre_len &&
			dotconf_strcmp_from_back(dir_name, ext) == 0 &&
			strncmp(dir_name, pre, pre_len) == 0 &&
			strcmp(dir_name, ".") != 0 &&
			strcmp(dir_name, "..") != 0)
		{
			retval = 0; /* Matches no other wildcards */
		}

	}

	return retval;
}

/* ------ internal utility function that determins matches for filenames with   -- */
/* ------ a '?' in name and calls the Internal Include function on that filename -- */
static int dotconf_handle_question_mark(command_t *cmd, char *path,
 char *pre, char *ext)
{
	configfile_t *included;
	DIR *dh = NULL;
	struct dirent *dirptr = NULL;
	int i;

	char new_pre[CFG_MAX_FILENAME];
	char already_matched[CFG_MAX_FILENAME];
	char wc = '\0';
        char *new_path = NULL, *wc_path = NULL, *wc_pre = NULL, *wc_ext = NULL;

	int pre_len;
	int new_path_len;
	int name_len = 0;
	int alloced = 0;
	int match_state = 0;

	pre_len = strlen(pre);

	if ((dh = opendir(path)) != NULL)
	{
		while ( (dirptr = readdir(dh)) != NULL )
		{
			match_state = dotconf_question_mark_match(dirptr->d_name,pre,ext);

			if (match_state >= 0)
			{
				name_len = strlen(dirptr->d_name);
				new_path_len = strlen(path) + name_len + strlen(ext) + 1;

				if ( !alloced )
				{
					if((new_path = malloc(new_path_len)) == NULL)
					{
						return -1;
					}

					alloced = new_path_len;

				} else {

						if ( new_path_len > alloced )
						{
							if ( realloc(new_path,new_path_len) == NULL )
							{
								free(new_path);
								return -1;
							}

						}

				}

				if (match_state == 1)
				{

					strncpy(new_pre, dirptr->d_name, (name_len > pre_len) ? pre_len + 1 : pre_len);
					new_pre[(name_len > pre_len) ? pre_len + 1 : pre_len] = '\0';

					sprintf(new_path,"%s%s%s",path,new_pre,ext);

					if (strcmp(new_path,already_matched) == 0)
					{
						continue; /* Already searched this expression */

					} else {

						strcpy(already_matched,new_path);

					}

					if (dotconf_find_wild_card(new_path,&wc,&wc_path,&wc_pre,&wc_ext) >= 0)
					{
						if ( dotconf_handle_wild_card(cmd,wc,wc_path,wc_pre,wc_ext) < 0)
						{
							dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
											"Error occured while processing wildcard %c\n"
											"Filename is '%s'\n", wc, new_path);

							free(new_path);
							dotconf_wild_card_cleanup(wc_path,wc_pre);
							return -1;
						}

						dotconf_wild_card_cleanup(wc_path,wc_pre);
						continue;
					}

				}

				sprintf(new_path,"%s%s",path,dirptr->d_name);

				if (access(new_path, R_OK))
				{
					dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
									"Cannot open %s for inclusion.\n"
									"IncludePath is '%s'\n", new_path, cmd->configfile->includepath);
					return -1;
				}

				included = dotconf_create(new_path, cmd->configfile->config_options[1],
											cmd->configfile->context, cmd->configfile->flags);
				if(included != NULL) {
					for (i = 2; cmd->configfile->config_options[i]; i++)
						dotconf_register_options(included, cmd->configfile->config_options[i]);
					included->errorhandler = cmd->configfile->errorhandler;
					included->contextchecker = cmd->configfile->contextchecker;
					dotconf_command_loop(included);
					dotconf_cleanup(included);
				}

			}

		}

		closedir(dh);
		free(new_path);

	}

	return 0;
}

/* ------ internal utility function that determins matches for filenames with   --- */
/* ------ a '*' in name and calls the Internal Include function on that filename -- */
static int dotconf_handle_star(command_t *cmd, char *path,
 char *pre, char *ext)
{
	configfile_t *included;
	DIR *dh = NULL;
	struct dirent *dirptr = NULL;

	char new_pre[CFG_MAX_FILENAME];
	char new_ext[CFG_MAX_FILENAME];
	char already_matched[CFG_MAX_FILENAME];
	char wc = '\0';
        char *new_path = NULL, *s_ext = NULL, *t_ext = NULL, *sub = NULL,
             *wc_path = NULL, *wc_pre = NULL, *wc_ext = NULL;

	int pre_len;
	int new_path_len;
	int name_len = 0;
	int alloced = 0;
	int match_state = 0;
	int t_ext_count = 0;
	int sub_count = 0;

	pre_len = strlen(pre);
	memset(already_matched, 0, sizeof(already_matched));
	s_ext = ext;

	while (dotconf_is_wild_card(*s_ext)) /* remove trailing wild-cards proceeded by * */
	{
		s_ext++;
	}

	t_ext = s_ext;

	while(t_ext != NULL && !dotconf_is_wild_card(*t_ext) && *t_ext != '\0')
	{
		t_ext++;				/* find non-wild-card string */
		t_ext_count++;
	}

	strncpy(new_ext,s_ext,t_ext_count);
	new_ext[t_ext_count] = '\0';

	if ((dh = opendir(path)) != NULL)
	{
		while ( (dirptr = readdir(dh)) != NULL )
		{
			sub_count = 0;
			t_ext_count = 0;

			match_state = dotconf_star_match(dirptr->d_name,pre,s_ext);

			if (match_state >= 0)
			{
				name_len = strlen(dirptr->d_name);
				new_path_len = strlen(path) + name_len + strlen(s_ext) + 1;

				if ( !alloced )
				{
					if((new_path = malloc(new_path_len)) == NULL)
					{
						return -1;
					}

					alloced = new_path_len;

				} else {

						if ( new_path_len > alloced )
						{
							if ( realloc(new_path,new_path_len) == NULL )
							{
								free(new_path);
								return -1;
							}

						}

				}

				if (match_state == 1)
				{

					if ((sub = strstr((dirptr->d_name+pre_len),new_ext)) == NULL)
					{
						continue;
					}

					while (sub != dirptr->d_name)
					{
						sub--;
						sub_count++;
					}

					if (sub_count + t_ext_count > name_len)
					{
						continue;
					}

					strncpy(new_pre, dirptr->d_name, sub_count + t_ext_count);
					new_pre[sub_count+t_ext_count] = '\0';
					strcat(new_pre,new_ext);

					sprintf(new_path,"%s%s%s",path,new_pre,t_ext);

					if (strcmp(new_path,already_matched) == 0)
					{
						continue; /* Already searched this expression */

					} else {

						strcpy(already_matched,new_path);

					}

					if (dotconf_find_wild_card(new_path,&wc,&wc_path,&wc_pre,&wc_ext) >= 0)
					{
						if ( dotconf_handle_wild_card(cmd,wc,wc_path,wc_pre,wc_ext) < 0)
						{
							dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
											"Error occured while processing wildcard %c\n"
											"Filename is '%s'\n", wc, new_path);

							free(new_path);
							dotconf_wild_card_cleanup(wc_path,wc_pre);
							return -1;
						}

						dotconf_wild_card_cleanup(wc_path,wc_pre);
						continue;
					}

				}

				sprintf(new_path,"%s%s",path,dirptr->d_name);

				if (access(new_path, R_OK))
				{
					dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
									"Cannot open %s for inclusion.\n"
									"IncludePath is '%s'\n", new_path, cmd->configfile->includepath);
					return -1;
				}

				included = dotconf_create(new_path, cmd->configfile->config_options[1],
											cmd->configfile->context, cmd->configfile->flags);
				if(included != NULL) {
					included->errorhandler = cmd->configfile->errorhandler;
					included->contextchecker = cmd->configfile->contextchecker;
					dotconf_command_loop(included);
					dotconf_cleanup(included);
				}

			}

		}

		closedir(dh);
		free(new_path);

	}

	return 0;
}

/* ------ callbacks of the internal option (Include, IncludePath) ------------------------------- */
static DOTCONF_CB(dotconf_cb_include) {
	char *filename = NULL, *path = NULL, *pre = NULL, *ext = NULL;
	configfile_t *included;
	char wild_card;

	if (cmd->configfile->includepath != NULL
		&& cmd->data.str[0] != '/' && cmd->configfile->includepath[0] != '\0')
	{
		/* relative file AND include path is used */
		int len, inclen;
		char *sl;

		inclen = strlen(cmd->configfile->includepath);
		if((len = strlen(cmd->data.str) + inclen + 1) == CFG_MAX_FILENAME)
		{
			dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
							"Absolute filename too long (>%d)", CFG_MAX_FILENAME);
			return NULL;
		}

		if (cmd->configfile->includepath[inclen - 1] == '/')
			sl = "";
		else
		{
			sl = "/";
			len++;
		}

		filename = malloc(len);
		snprintf(filename, len, "%s%s%s",
				 cmd->configfile->includepath, sl, cmd->data.str);
	}
	else						/* fully qualified, or no includepath */
		filename = strdup(cmd->data.str);

	/* Added wild card support here */
	if (dotconf_find_wild_card(filename,&wild_card,&path,&pre,&ext) >= 0)
	{
		if ( dotconf_handle_wild_card(cmd,wild_card,path,pre,ext) < 0)
		{
			dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
							"Error occured while attempting to process %s for inclusion.\n"
							"IncludePath is '%s'\n", filename, cmd->configfile->includepath);
		}

		dotconf_wild_card_cleanup(path,pre);
		free(filename);
		return NULL;
	}

	if (access(filename, R_OK))
	{
		dotconf_warning(cmd->configfile, DCLOG_WARNING, ERR_INCLUDE_ERROR,
						"Cannot open %s for inclusion.\n"
						"IncludePath is '%s'\n", filename, cmd->configfile->includepath);
		free(filename);
		return NULL;
	}

	included = dotconf_create(filename, cmd->configfile->config_options[1],
							   cmd->configfile->context, cmd->configfile->flags);
	if(included != NULL) {
		included->contextchecker = (dotconf_contextchecker_t) cmd->configfile->contextchecker;
		included->errorhandler = (dotconf_errorhandler_t) cmd->configfile->errorhandler;

		dotconf_command_loop(included);
		dotconf_cleanup(included);
	}

	free(filename);
	return NULL;
}

static DOTCONF_CB(dotconf_cb_includepath) {
	char *env = getenv(CFG_INCLUDEPATH_ENV);
	/* environment overrides configuration file setting */
	if(env == NULL)
		snprintf(cmd->configfile->includepath, CFG_MAX_FILENAME, "%s", cmd->data.str);
	return NULL;
}

static inline long MIN(long a, long b) {
    return (a < b) ? a : b;
}
