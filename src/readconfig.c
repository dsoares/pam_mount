#include <config.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dotconf.h>
#include <libgen.h>
#include <pwd.h>
#include <pam_mount.h>

extern config_t config;
extern          debug;

pm_command_t    command[] = {
	{SMBMOUNT, "smb", "smbmount"},
	{SMBMOUNT, "smbfs", "smbmount"},
	{CIFSMOUNT, "cifs", "cifsmount"},
	{NCPMOUNT, "ncp", "ncpmount"},
	{NCPMOUNT, "ncpfs", "ncpmount"},
	{LCLMOUNT, "local", "lclmount"},
	{LCLMOUNT, "nfs", "lclmount"},
/* FIXME: PMHELPER no longer needed */
	{PMHELPER, NULL, "pmhelper"},
	{UMOUNT, NULL, "umount"},
	{LSOF, NULL, "lsof"},
	/*
	 * Leave mntcheck available on Linux so I can ship one config file
	 * example
	 */
	{MNTCHECK, NULL, "mntcheck"},
	{-1, NULL, NULL}
};

static          DOTCONF_CB(read_int_param);
static          DOTCONF_CB(read_debug);
static          DOTCONF_CB(read_luserconf);
static          DOTCONF_CB(read_command);
static          DOTCONF_CB(read_options_require);
static          DOTCONF_CB(read_options_allow);
static          DOTCONF_CB(read_options_deny);
static          DOTCONF_CB(read_volume);

static const configoption_t legal_config[] = {
	{"debug", ARG_INT, read_debug, &config.debug, CTX_ALL},
	{"mkmountpoint", ARG_INT, read_int_param, &config.mkmountpoint,
	CTX_ALL},
	{"luserconf", ARG_STR, read_luserconf, &config, CTX_ALL},
/* FIXME: PMHELPER no longer needed */
	{"pmhelper", ARG_LIST, read_command, &config, CTX_ALL},
	{"smbmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"cifsmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"ncpmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"umount", ARG_LIST, read_command, &config, CTX_ALL},
	{"lclmount", ARG_LIST, read_command, &config, CTX_ALL},
	{"lsof", ARG_LIST, read_command, &config, CTX_ALL},
	{"mntcheck", ARG_LIST, read_command, &config, CTX_ALL},
	{"options_require", ARG_STR, read_options_require, &config, CTX_ALL},
	{"options_allow", ARG_STR, read_options_allow, &config, CTX_ALL},
	{"options_deny", ARG_STR, read_options_deny, &config, CTX_ALL},
	{"volume", ARG_LIST, read_volume, &config, CTX_ALL},
	LAST_OPTION
};

/* ============================ log_error () =============================== */
/* NOTE: callback helper function for handling errors
 *       frees msg after logging it! */
static 
FUNC_ERRORHANDLER(log_error)
{
	l0g("pam_mount: %s\n", msg);
	free((char *) msg); /* FIXME: broken? (some users report symptoms) */
	return 0;
}

/* ============================ read_options () ============================ */
/* PRE:    options points to an array of length MAX_PAR + 1, may be uninitialized
 *         opt_str points to a string containing options ("opt1,opt2,...") or NULL
 * POST:   options contains the options listed in opt_str
 * FN VAL: NULL on success or a string representing an error message
 * NOTE:   callback helper function for reading options_require, options_allow,
 *         and options_deny.  ALSO used directly by options_*_ok()
 */
static char    *
read_options(char *options[], const char *opt_str)
{
	int             count = 0;
	const char     *ptr = opt_str;
	memset(options, 0x00, MAX_PAR + 1);
	if (!opt_str)
		return "empty options string";
	w4rn("%s", "pam_mount: options: ");
	while (ptr = strchr(ptr, ',')) {
		if (count >= MAX_PAR)
			/* >= because one last iteration happens outside loop */
			return "too many options";
		else if (ptr - opt_str > MAX_PAR)
			return "option too long";
		if (!(options[count] = (char *) calloc(MAX_PAR + 1, sizeof(char))))
			return "error allocating memory";
		strncpy(options[count], opt_str, ptr - opt_str);
		opt_str = ++ptr;
		w4rn("%s ", options[count++]);
	}
	if (!(options[count] = (char *) calloc(MAX_PAR + 1, sizeof(char))))
		return "error allocating memory";
	strncpy(options[count], opt_str, MAX_PAR);
	w4rn("%s\n", options[count]);
	return NULL;
}

/* ============================ free_options () ============================ */
static void
free_options(char *options[])
/* PRE:  options points to an array of length MAX_PAR + 1, each item must point
 *       to malloc'ed memory or NULL the termination byte
 * POST: each item in options is free'd
 */
{
	int             i = 0;
	while (options[i])
		free(options[i++]);
}

/* ============================ read_options_require () ==================== */
/* NOTE: callback function for reading required options */
static 
DOTCONF_CB(read_options_require)
{
	if (!*((int *) cmd->context))
		return "tried to set options_require from user config";
	w4rn("pam_mount: %s\n", "reading options_require...");
	return read_options(((config_t *) cmd->option->info)->options_require,
			    cmd->data.str);
}

/* ============================ read_options_allow () ====================== */
/* NOTE: callback function for reading required options */
static 
DOTCONF_CB(read_options_allow)
{
	if (!*((int *) cmd->context))
		return "tried to set options_allow from user config";
	w4rn("pam_mount: %s\n", "reading options_allow...");
	return read_options(((config_t *) cmd->option->info)->options_allow,
			    cmd->data.str);
}

/* ============================ read_options_deny () ======================= */
/* NOTE: callback function for reading required options */
static 
DOTCONF_CB(read_options_deny)
{
	if (!*((int *) cmd->context))
		return "tried to set options_deny from user config";
	w4rn("pam_mount: %s\n", "reading options_deny...");
	return read_options(((config_t *) cmd->option->info)->options_deny,
			    cmd->data.str);
}

/* ============================ get_command_index () ======================= */
/* PRE:    command is assigned an initialized pm_command_t array
 *         name points to a valid string != NULL
 * FN VAL: if name in command then cooresponding type, else -1 */
static          command_type_t
get_command_index(const pm_command_t command[],
		  const char *name)
{
	int             i;
	for (i = 0; command[i].type != -1; i++)
		if (!strcmp(command[i].command_name, name)) {
			return command[i].type;
		}
	return -1;
}

/* ============================ read_command () ============================ */
/* NOTE: callback function for reading command configurations
 *       command array must be initialized to [ 0x00, ..., 0x00 ]
 *       (see initconfig) */
static 
DOTCONF_CB(read_command)
{
	int             i;
	command_type_t  command_index;
	if (!*((int *) cmd->context))
		return "tried to set command from user config";
	if ((command_index = get_command_index(command, cmd->name)) == -1)
		return "pam_mount: bad command in config";
	if (cmd->arg_count <= 0)
		return "command type specified without definition";
	for (i = 0; i < cmd->arg_count; i++)
		if (strlen(cmd->data.list[i]) > MAX_PAR)
			return "pam_mount: command too long";
	if (!(((config_t *) cmd->option->info)->command[0][command_index] =
	      (char *) calloc(MAX_PAR + 1, sizeof(char))))
		return "error allocating memory";
	strncpy(((config_t *) cmd->option->info)->command[0][command_index],
		cmd->data.list[0], MAX_PAR + 1);
	w4rn("pam_mount: adding to command: %s ", cmd->data.list[0]);
	if (!(((config_t *) cmd->option->info)->command[1][command_index] =
	      (char *) calloc(MAX_PAR + 1, sizeof(char))))
		return "error allocating memory";
	strncpy(((config_t *) cmd->option->info)->command[1][command_index],
		basename(cmd->data.list[0]), MAX_PAR + 1);
	w4rn("%s ", basename(cmd->data.list[0]));
	for (i = 1; i < cmd->arg_count; i++) {
		if (i > MAX_PAR)
			return "pam_mount: command line configured to be too long";
		if (!(((config_t *) cmd->option->info)->command[i + 1][command_index] =
		      (char *) calloc(MAX_PAR + 1, sizeof(char))))
			return "error allocating memory";
		w4rn("%s ", cmd->data.list[i]);
		strncpy(((config_t *) cmd->option->info)->
			command[i + 1][command_index], cmd->data.list[i],
			MAX_PAR + 1);
	}
	w4rn("%s", "\n");
	return NULL;
}

/* ============================ luserconf_volume_record_sane () ============ */
/* PRE:    config points to a valid config_t structure
 * FN VAL: if error a string error message else NULL */
static char    *
luserconf_volume_record_sane(config_t * config)
{
	if (!strcmp(config->volume[config->volcount].user, "*"))
		return "pam_mount: wildcard used in user-defined volume";
	return NULL;
}

/* ============================ volume_record_sane () ====================== */
/* PRE:    config points to a valid config_t structure
 * FN VAL: if error string error message else NULL */
static char    *
volume_record_sane(config_t * config)
{
	w4rn("pam_mount: %s\n", "checking sanity of volume record");
	if (!config->command[0][config->volume[config->volcount].type])
		return "pam_mount: mount command not defined for this type";
	else if ((config->volume[config->volcount].type == SMBMOUNT || config->volume[config->volcount].type == NCPMOUNT || config->volume[config->volcount].type == CIFSMOUNT) && !strlen(config->volume[config->volcount].server))
		return "pam_mount: remote mount type specified without server";
	else if (!config->command[0][UMOUNT])
		return "pam_mount: umount command not defined";
	else if (!config->volume[config->volcount].globalconf
		 && config->volume[config->volcount].type == LCLMOUNT
	    && !owns(config->user, config->volume[config->volcount].volume))
		return "pam_mount: user-defined volume, volume not owned by user";
	/*
	 * If it does not already exist then its okay, pam_mount will mkdir
	 * it (if configured to do so)
	 */
	else if (!config->volume[config->volcount].globalconf
		 && config->volume[config->volcount].type == LCLMOUNT
		 && exists(config->volume[config->volcount].mountpoint) 
                 && !owns(config->user, config->volume[config->volcount].mountpoint))
		return
			"pam_mount: user-defined volume, mountpoint not owned by user";
	else if (strlen(config->volume[config->volcount].fs_key_cipher) && !strlen(config->volume[config->volcount].fs_key_path))
		return "pam_mount: fs_key_cipher defined without fs_key_path";
	else if (!strlen(config->volume[config->volcount].fs_key_cipher) && strlen(config->volume[config->volcount].fs_key_path))
		return "pam_mount: fs_key_path defined without fs_key_cipher";
	return NULL;
}

/* ============================ read_luserconf () ========================== */
/* NOTE: callback function for reading configuration parameters */
static 
DOTCONF_CB(read_luserconf)
{
	char           *home_dir;
	struct passwd  *passwd_ent;
	if (!*((int *) cmd->context))
		return "tried to set luserconf from user config";
	passwd_ent = getpwnam(((config_t *) cmd->option->info)->user);
	if (!passwd_ent) {
		home_dir = "~";
	} else {
		home_dir = passwd_ent->pw_dir;
	}
	if (strlen(home_dir) + strlen("/") + strlen(cmd->data.str) >
	    FILENAME_MAX)
		return "pam_mount: expanded luserconf path too long";
	strcpy(((config_t *) cmd->option->info)->luserconf, home_dir);
	strcat(((config_t *) cmd->option->info)->luserconf, "/");
	strcat(((config_t *) cmd->option->info)->luserconf, cmd->data.str);
	w4rn("pam_mount: path to luserconf set to %s\n",
	     ((config_t *) cmd->option->info)->luserconf);
	return NULL;
}

/* ============================ read_int_param () ========================== */
/* NOTE: callback function for reading configuration parameters */
static 
DOTCONF_CB(read_int_param)
{
	if (!*((int *) cmd->context))
		return "tried to set int param from user config";
	*((int *) cmd->option->info) = cmd->data.value;
	return NULL;
}

/* ============================ read_debug () ============================== */
/* NOTE: callback function for reading debug parameter */
static 
DOTCONF_CB(read_debug)
{
	/* debug is handled as a special case so global debug can be set ASAP */
	debug = cmd->data.value;
	return read_int_param(cmd, ctx);
}

/* ============================ read_volume () ============================= */
/* NOTE: callback function for reading volume parameters */
static 
DOTCONF_CB(read_volume)
{
#define VOL ((config_t *)cmd->option->info)->volume
#define VOLCOUNT ((config_t *)cmd->option->info)->volcount
	int             i;
	char           *errmsg;
	if (cmd->arg_count != 8)
		return "pam_mount: bad number of args for volume";
	else if (*((int *) cmd->context) && strcmp
		 (cmd->data.list[0], ((config_t *) cmd->option->info)->user)
		 && strcmp(cmd->data.list[0], "*"))
		/*
		 * user may use other usernames to mount volumes using
		 * luserconf
		 */
		return "pam_mount: ignoring volume record (not for me)";
	else if (!strcmp(cmd->data.list[0], "*") && !strcmp(config.user, "root"))
		/* FIXME: should use uid == 0, not "root" */
		return "pam_mount: volume wildcard ignored for root";
	for (i = 0; i < cmd->arg_count; i++)
		if (strlen(cmd->data.list[i]) > MAX_PAR)
			return "pam_mount: command too long";
	if (!(VOL = realloc(VOL, sizeof(vol_t) * (VOLCOUNT + 1))))
		return "error allocating memory";
	memset(&VOL[VOLCOUNT], 0x00, sizeof(vol_t));
	VOL[VOLCOUNT].globalconf = *((int *) cmd->context);
	strncpy(VOL[VOLCOUNT].user, cmd->data.list[0], MAX_PAR);
	VOL[VOLCOUNT].type = -1;
	for (i = 0; command[i].type != -1; i++)
		if (command[i].fs && !strcasecmp(cmd->data.list[1], command[i].fs)) {
			VOL[VOLCOUNT].type = command[i].type;
			break;
		}
	if (VOL[VOLCOUNT].type == -1)
		return "pam_mount: filesystem not supported";
	if (*cmd->data.list[2] == '-')
		*VOL[VOLCOUNT].server = 0x00;
	else
		strncpy(VOL[VOLCOUNT].server, cmd->data.list[2], MAX_PAR);
	strncpy(VOL[VOLCOUNT].volume, cmd->data.list[3], MAX_PAR);
	if (*cmd->data.list[4] == '-')
		*VOL[VOLCOUNT].mountpoint = 0x00;
	else
		strncpy(VOL[VOLCOUNT].mountpoint, cmd->data.list[4], MAX_PAR);
	if (*cmd->data.list[5] == '-')
		*VOL[VOLCOUNT].options = 0x00;
	else
		strncpy(VOL[VOLCOUNT].options, cmd->data.list[5], MAX_PAR);
	if (*cmd->data.list[6] == '-')
		*VOL[VOLCOUNT].fs_key_cipher = 0x00;
	else
		strncpy(VOL[VOLCOUNT].fs_key_cipher, cmd->data.list[6], MAX_PAR);
	if (*cmd->data.list[7] == '-')
		*VOL[VOLCOUNT].fs_key_path = 0x00;
	else
		strncpy(VOL[VOLCOUNT].fs_key_path, cmd->data.list[7], MAX_PAR);
	if ((errmsg = volume_record_sane
	     (((config_t *) cmd->option->info))))
		return errmsg;
	if (!VOL[VOLCOUNT].globalconf
	    && (errmsg = luserconf_volume_record_sane((config_t *) cmd->option->info)))
		return errmsg;
	VOLCOUNT++;
	return NULL;
#undef VOL
#undef VOLCOUNT
}

/* ============================ option_in_list () ========================== */
static int
option_in_list(const char *needle, char *haystack[])
/* PRE:    needle points to a valid sting != NULL
 *         haystack contains valid strings, terminated by NULL
 * FN VAL: 1 if needle exists in haystack, else 0
 */
{
	int             i;
	for (i = 0; haystack[i]; i++)
		if (!strcmp(needle, haystack[i]))
			return 1;
	return 0;
}

/* ============================ options_allow_ok () ======================== */
/* PRE:    conf points to an array of allowed options (first item may be
 *           NULL if no options sepcified)
 *         options points to a string representing a list of options requested
 *           for a volume or ""
 * FN VAL: if options acceptable by conf 1 else 0 with error logged */
static 
options_allow_ok(char *conf[], const char *options)
{
	int             i;
	char           *opt[MAX_PAR + 1], *err;
	if (!strcmp(conf[0], "*") || !strlen(options))
		return 1;
	if ((err = read_options(opt, options))) {
		l0g("pam_mount: %s\n", err);
		return 0;
	}
	for (i = 0; opt[i]; i++)
		if (!option_in_list(opt[i], conf)) {
			l0g("pam_mount: option %s not allowed\n", opt[i]);
			free_options(opt);
			return 0;
		}
	free_options(opt);
	return 1;
}

/* ============================ options_required_ok () ===================== */
/* PRE:    conf points to an array of required options
 *         options points to a string representing a list of options requested
 *           for a volume or ""
 * FN VAL: if options acceptable by conf 1 else 0 with error logged */
static 
options_required_ok(char *conf[], const char *options)
{
	int             i;
	char           *opt[MAX_PAR + 1], *err;
	if ((err = read_options(opt, options))) {
		l0g("pam_mount: %s\n", err);
		return 0;
	}
	for (i = 0; conf[i]; i++)
		if (!option_in_list(conf[i], opt)) {
			l0g("pam_mount: option %s required\n", conf[i]);
			free_options(opt);
			return 0;
		}
	free_options(opt);
	return 1;
}

/* ============================ options_deny_ok () ========================= */
/* PRE:    conf points to an array of denied options (first item may be
 *           NULL if no options sepcified)
 *         options points to a string representing a list of options requested
 *           for a volume or ""
 * FN VAL: if options acceptable by conf 1 else 0 with error logged */
static 
options_deny_ok(char *conf[], const char *options)
{
	int             i;
	char           *opt[MAX_PAR + 1], *err;
	if (!conf[0]) {
		w4rn("pam_mount: %s\n", "no denied options");
		return 1;
	} else if (!strcmp(conf[0], "*") && strlen(options)) {
		l0g("pam_mount: %s\n",
		    "all mount options denied, user tried to specify one");
		return 0;
	}
	if ((err = read_options(opt, options))) {
		l0g("pam_mount: %s\n", err);
		return 0;
	}
	for (i = 0; conf[i]; i++) {
		if (option_in_list(conf[i], opt)) {
			l0g("pam_mount: option %s denied\n", conf[i]);
			free_options(opt);
			return 0;
		}
	}
	free_options(opt);
	return 1;
}

/* ============================ readconfig () ============================== */
/* PRE:    user is a valid string != NULL
 *         file is the path of config file to read
 *         globalconf == 1 if file is a global config, else 0
 *         config points to a valid config_t structure
 * POST:   command is an array containing configured mount command lines
 *         config points to a config_t structure containing configuration read
 * FN VAL: if error 0 else 1, errors are logged */
int
readconfig(const char *user, char *file, int globalconf,
	   config_t * config)
{
	configfile_t   *configfile;
	if (!
	    (configfile =
	     dotconf_create(file, legal_config, &globalconf, NONE))) {
		l0g("pam_mount: error opening %s\n", file);
		return 0;
	}
	configfile->errorhandler = (dotconf_errorhandler_t) log_error;
	if (!dotconf_command_loop(configfile))
		l0g("pam_mount: error reading %s\n", file);	/* may not be fatal */
	if (!globalconf) {
		int             i;
		if (config->options_allow[0] && config->options_deny[0]) {
			l0g("pam_mount: %s\n",
			"possible conflicting option settings, denying all");
			config->options_deny[0] = "*";
		}
		for (i = 0; i < config->volcount; i++) {
			if (config->volume[i].globalconf)
				continue;
			if (config->options_require[0]) {
				w4rn("pam_mount: %s\n", "verifying options required");
				if (!options_required_ok
				    (config->options_require, config->volume[i].options)) {
					dotconf_cleanup(configfile);
					return 0;
				}
			}
			if (config->options_allow[0]) {
				w4rn("pam_mount: %s\n", "verifying options allow");
				if (!options_allow_ok
				    (config->options_allow, config->volume[i].options)) {
					dotconf_cleanup(configfile);
					return 0;
				}
			} else if (config->options_deny[0]) {
				w4rn("pam_mount: %s\n", "verifying options deny");
				if (!options_deny_ok
				    (config->options_deny, config->volume[i].options)) {
					dotconf_cleanup(configfile);
					return 0;
				}
			} else {
				if (*config->volume[i].options) {
					l0g("pam_mount: %s\n",
					    "user specified options denied by default");
					return 0;
				}
			}
		}
	}
	dotconf_cleanup(configfile);
	return 1;
}

/* ============================ initconfig () ============================== */
/* PRE:  config points to a valid config_t structure
 * POST: config is initialized (ie: config.volcount == 0) */
void
initconfig(config_t * config)
{
	int             i;
	config->volcount = 0;
	config->debug = DEBUG_DEFAULT;
	config->mkmountpoint = MKMOUNTPOINT_DEFAULT;
	for (i = 0; i < COMMAND_MAX; i++)
		*config->command[i] = 0x00;
}

/* ============================ freeconfig () ============================== */
/* PRE:  config is a valid, initialized config_t structure
 * POST: all dynamically allocated memory in config is freed */
void
freeconfig(config_t config)
{
	int             i = 0, j = 0;
	free_options(config.options_require);
	free_options(config.options_allow);
	free_options(config.options_deny);
	for (i = 0; i < COMMAND_MAX; i++)
		while (config.command[j][i])
			free(config.command[j++][i]);
}

/* ============================ expand_home () ============================= */
/* PRE:    path points to the path to expand (ie: ~/foo)
 * FN VAL: expanded path (ie: /home/usr/foo) or NULL on error */
static char    *
expand_home(char *path, const char *user)
{
	char           *tmp = NULL;
	struct passwd  *p = getpwnam(user);
	if (p) {
		/* don't need to + 1 len because ~ is dropped from path */
		tmp = (char *) malloc(strlen(p->pw_dir) + strlen(path));
		if (tmp) {
			strcpy(tmp, p->pw_dir);
			strcat(tmp, path + 1);
		} else
			l0g("pam_mount: %s\n", "error allocating memory");
	}
	return tmp;
}

/* ============================ expand_wildcard () ========================= */
/* PRE:    str points to the string to expand (must contain at least one &)
 *         user is the username to expand to
 * FN VAL: str with any &s expanded into user or NULL on error */
static char    *
expand_wildcard(const char *str, const char *user)
{
	char           *result = NULL;
	char           *pos;
	w4rn("pam_mount: expand_wildcard for %s\n", str);
	if (str == NULL) {
		return NULL;
	}
	pos = strchr(str, '&');
	if (pos) {
		char           *next;
		/* don't need to + 1 len because & is dropped from path */
		result = malloc(strlen(str) + strlen(user));
		if (result) {
			strcpy(result, str);
			strcpy(result + (pos - str), user);
			strcat(result, pos + 1);
			next = expand_wildcard(result, user);
			if (next) {
				free(result);
				result = next;
			}
		} else
			l0g("pam_mount %s\n", "error allocating memory");
	}
	return (result);
}

/* ============================ expandconfig () ============================ */
/* PRE:  config points to a valid config_t structure that has been filled
 * POST: any wildcards in config->data are expanded
 * FN VAL: if error 0 else 1, errors are logged */
int
expandconfig(config_t * config)
{
	int             i;
	for (i = 0; i < config->volcount; i++) {
		char           *tmp;
		if (*config->volume[i].mountpoint == '~') {
			if ((tmp = expand_home(config->volume[i].mountpoint, config->user))) {
				strncpy(config->volume[i].mountpoint, tmp, FILENAME_MAX + 1);
				free(tmp);
			} else
				return 0;
		}
		if (!strcmp(config->volume[i].user, "*")) {
			strcpy(config->volume[i].user, config->user);
			if ((tmp = expand_wildcard(config->volume[i].volume, config->user))) {
				strncpy(config->volume[i].volume, tmp, MAX_PAR + 1);
				free(tmp);
			} else
				return 0;
			if ((tmp = expand_wildcard(config->volume[i].mountpoint, config->user))) {
				strncpy(config->volume[i].mountpoint, tmp, FILENAME_MAX + 1);
				free(tmp);
			} else
				return 0;
			if ((tmp = expand_wildcard(config->volume[i].options, config->user))) {
				strncpy(config->volume[i].options, tmp, MAX_PAR + 1);
				free(tmp);
			} else
				return 0;
		}
	}
	return 1;
}
