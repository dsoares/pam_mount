#include <config.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dotconf.h>
#include <libgen.h>
#include <pwd.h>
#include <pam_mount.h>

extern config_t config;
extern debug;

pm_command_t command[] = {
    {SMBMOUNT, "smb", "smbmount"},
    {SMBMOUNT, "smbfs", "smbmount"},
    {NCPMOUNT, "ncp", "ncpmount"},
    {NCPMOUNT, "ncpfs", "ncpmount"},
    {LCLMOUNT, "local", "lclmount"},
    {LCLMOUNT, "nfs", "lclmount"},
    {PMHELPER, NULL, "pmhelper"},
    {UMOUNT, NULL, "umount"},
    {LSOF, NULL, "lsof"},
    {-1, NULL, NULL}
};

DOTCONF_CB(read_int_param);
DOTCONF_CB(read_debug);
DOTCONF_CB(read_luserconf);
DOTCONF_CB(read_command);
DOTCONF_CB(read_options_require);
DOTCONF_CB(read_options_allow);
DOTCONF_CB(read_options_deny);
DOTCONF_CB(read_volume);

static const configoption_t legal_config[] = {
    {"debug", ARG_INT, read_debug, &config.debug, CTX_ALL},
    {"mkmountpoint", ARG_INT, read_int_param, &config.mkmountpoint, CTX_ALL},
    {"luserconf", ARG_STR, read_luserconf, &config, CTX_ALL},
    {"pmhelper", ARG_LIST, read_command, &config, CTX_ALL},
    {"smbmount", ARG_LIST, read_command, &config, CTX_ALL},
    {"ncpmount", ARG_LIST, read_command, &config, CTX_ALL},
    {"umount", ARG_LIST, read_command, &config, CTX_ALL},
    {"pmhelper", ARG_LIST, read_command, &config, CTX_ALL},
    {"lclmount", ARG_LIST, read_command, &config, CTX_ALL},
    {"lsof", ARG_LIST, read_command, &config, CTX_ALL},
    {"options_require", ARG_STR, read_options_require, &config, CTX_ALL},
    {"options_allow", ARG_STR, read_options_allow, &config, CTX_ALL},
    {"options_deny", ARG_STR, read_options_deny, &config, CTX_ALL},
    {"volume", ARG_LIST, read_volume, &config, CTX_ALL},
    LAST_OPTION
};

/* ============================ log_error () =============================== */
/* NOTE: callback helper function for handling errors
 *       frees msg after logging it! */
FUNC_ERRORHANDLER(log_error)
{
    log("pam_mount: %s\n", msg);
    free((char *) msg);
}

/* ============================ read_options () ============================ */
/* NOTE: callback helper function for reading options_require, options_allow,
 *       and options_deny.  options must be initialized to 
 *       [ 0x00, ..., 0x00 ] (see initconfig) opt_str may be NULL */
char *read_options(char *options[], char *opt_str)
{
    int count = 0;
    char *ptr = opt_str;
    if (! opt_str) {
	char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
        strcpy(errmsg, "empty options string");
	return errmsg;
    }
    w4rn("%s", "pam_mount: options (req., allow, or deny): ");
    while (ptr = strchr(ptr, ',')) {
        if (count >= MAX_PAR) {
	    /* >= because one last iteration happens outside loop */
	    char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
	    strcpy(errmsg, "too many options");
	    return errmsg;
	} else if (ptr - opt_str > MAX_PAR) {
	    char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
	    strcpy(errmsg, "option too long");
	    return errmsg;
	} 
        options[count] = (char *) calloc(MAX_PAR + 1, sizeof(char));
        strncpy(options[count], opt_str, ptr - opt_str);
        opt_str = ++ptr;
        w4rn("%s ", options[count++]);
    }
    options[count] = (char *) calloc(MAX_PAR + 1, sizeof(char));
    strncpy(options[count], opt_str, MAX_PAR);
    w4rn("%s\n", options[count]);
    return NULL;
}

/* ============================ read_options_require () ==================== */
/* NOTE: callback function for reading required options */
DOTCONF_CB(read_options_require)
{
    if (!*((int *) cmd->context)) {
	char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
	strcpy(errmsg, "tried to set options_require from user config");
	return errmsg;
    }
    return read_options(((config_t *) cmd->option->info)->options_require,
			cmd->data.str);
}

/* ============================ read_options_allow () ====================== */
/* NOTE: callback function for reading required options */
DOTCONF_CB(read_options_allow)
{
    if (!*((int *) cmd->context)) {
	char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
	strcpy(errmsg, "tried to set options_allow from user config");
	return errmsg;
    }
    return read_options(((config_t *) cmd->option->info)->options_allow,
			cmd->data.str);
}

/* ============================ read_options_deny () ======================= */
/* NOTE: callback function for reading required options */
DOTCONF_CB(read_options_deny)
{
    if (!*((int *) cmd->context)) {
	char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
	strcpy(errmsg, "tried to set options_deny from user config");
	return errmsg;
    }
    return read_options(((config_t *) cmd->option->info)->options_deny,
			cmd->data.str);
}

/* ============================ get_command_index () ======================= */ 
/* PRE:    command is assigned an initialized pm_command_t array
 *         name points to a valid string != NULL
 * FN VAL: if name in command then cooresponding type, else -1 */
command_type_t get_command_index(const pm_command_t command[], const char *name)
{
    int i;
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
DOTCONF_CB(read_command)
{
    int i;
    command_type_t command_index;
    char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
    if ((command_index = get_command_index(command, cmd->name)) == -1) {
	snprintf(errmsg, BUFSIZ + 1,
		 "pam_mount: bad command in config: %s", cmd->name);
	return errmsg;
    }
    for (i = 0; i < cmd->arg_count; i++)
        if (strlen(cmd->data.list[i]) > MAX_PAR) {
	    snprintf(errmsg, BUFSIZ + 1,
		 "pam_mount: command too long: %s", cmd->data.list[0]);
            return errmsg;
    }
    ((config_t *) cmd->option->info)->command[0][command_index] =
	(char *) calloc(MAX_PAR + 1, sizeof(char));
    strncpy(((config_t *) cmd->option->info)->command[0][command_index],
	    cmd->data.list[0], MAX_PAR + 1);
    w4rn("pam_mount: adding to command: %s ", cmd->data.list[0]);
    ((config_t *) cmd->option->info)->command[1][command_index] =
	(char *) calloc(MAX_PAR + 1, sizeof(char));
    strncpy(((config_t *) cmd->option->info)->command[1][command_index],
	    basename(cmd->data.list[0]), MAX_PAR + 1);
    w4rn("%s ", basename(cmd->data.list[0]));
    for (i = 1; i < cmd->arg_count; i++) {
	if (i > MAX_PAR) {
	    strcpy(errmsg,
		   "pam_mount: command line configured to be too long");
	    return errmsg;
	}
	((config_t *) cmd->option->info)->command[i + 1][command_index] =
	    (char *) calloc(MAX_PAR + 1, sizeof(char));
	w4rn("%s ", cmd->data.list[i]);
	strncpy(((config_t *) cmd->option->info)->
		command[i + 1][command_index], cmd->data.list[i],
		MAX_PAR + 1);
    }
    w4rn("%s", "\n");
    return NULL;
}

/* ============================ luserconf_volume_record_sane () ============ */
/* PRE:    volume is an array containing 8 fields from pam_mount.conf
 *         config points to a valid config_t structure
 *         errmsg points to an char array of length >= BUFSIZ + 1
 * FN VAL: if error a pointed to a malloced string error message else NULL */
int luserconf_volume_record_sane(char *volume[], config_t * config,
				 char *errmsg)
{
    if (! strcmp(volume[0], "*")) {
	strcpy(errmsg, "pam_mount: wildcard used in user-defined volume");
	return 0;
    }
    return 1;
}

/* ============================ volume_record_sane () ====================== */
/* PRE:    volume is an array containing 8 fields from pam_mount.conf
 *         config points to a valid config_t structure
 *         errmsg points to an char array of length >= BUFSIZ + 1
 * FN VAL: if error a pointer to a malloced string error message else NULL */
int volume_record_sane(char *volume[], config_t * config, char *errmsg)
{
    w4rn("pam_mount: %s\n", "checking sanity of volume record");
    if (!config->command[0][config->data[config->volcount].type]) {
	snprintf(errmsg, BUFSIZ + 1,
		 "pam_mount: mount command not defined for %s", volume[1]);
	return 0;
    } else if (!config->command[0][UMOUNT]) {
	strcpy(errmsg, "pam_mount: umount command not defined");
	return 0;
    } else if (!config->data[config->volcount].globalconf
	       && config->data[config->volcount].type == LCLMOUNT
	       && !owns(config->user,
			config->data[config->volcount].volume)) {
	strcpy(errmsg,
	       "pam_mount: user-defined volume, volume not owned by user");
	return 0;
    } else if (!config->data[config->volcount].globalconf
	       && config->data[config->volcount].type == LCLMOUNT
	       && !owns(config->user,
			config->data[config->volcount].mountpoint)) {
	strcpy(errmsg,
	       "pam_mount: user-defined volume, mountpoint not owned by user");
	return 0;
    }
    return 1;
}

/* ============================ read_luserconf () ========================== */
/* NOTE: callback function for reading configuration parameters */
DOTCONF_CB(read_luserconf)
{
    char *home_dir;
    char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
    struct passwd *passwd_ent;
    if (!*((int *) cmd->context)) {
	strcpy(errmsg, "tried to set luserconf from user config");
	return errmsg;
    }
    passwd_ent = getpwnam(((config_t *) cmd->option->info)->user);
    if (!passwd_ent) {
	home_dir = "~";
    } else {
	home_dir = passwd_ent->pw_dir;
    }
    if (strlen(home_dir) + strlen("/") + strlen(cmd->data.str) >
	FILENAME_MAX) {
	strcpy(errmsg, "pam_mount: expanded luserconf path too long");
	return errmsg;
    }
    strcpy(((config_t *) cmd->option->info)->luserconf, home_dir);
    strcat(((config_t *) cmd->option->info)->luserconf, "/");
    strcat(((config_t *) cmd->option->info)->luserconf, cmd->data.str);
    w4rn("pam_mount: path to luserconf set to %s\n",
	 ((config_t *) cmd->option->info)->luserconf);
    return NULL;
}

/* ============================ read_int_param () ========================== */
/* NOTE: callback function for reading configuration parameters */
DOTCONF_CB(read_int_param)
{
    if (!*((int *) cmd->context)) {
	char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
	strcpy(errmsg, "tried to set int param from user config");
	return errmsg;
    }
    *((int *) cmd->option->info) = cmd->data.value;
    return NULL;
}

/* ============================ read_debug () ============================== */
/* NOTE: callback function for reading debug parameter */
DOTCONF_CB(read_debug)
{
    /* debug is handled as a special case so global debug can be set ASAP */
    debug = cmd->data.value;
    return read_int_param(cmd, ctx);
}

/* ============================ read_volume () ============================= */
/* NOTE: callback function for reading volume parameters */
DOTCONF_CB(read_volume)
{
#define DATA ((config_t *)cmd->option->info)->data
#define VOLCOUNT ((config_t *)cmd->option->info)->volcount
    int i;
    char *errmsg = (char *) malloc(sizeof(char) * BUFSIZ + 1);
    if (cmd->arg_count != 8) {
	strcpy(errmsg, "pam_mount: bad number of args for volume");
	return errmsg;
    } else
	if (*((int *) cmd->context) && strcmp
	    (cmd->data.list[0], ((config_t *) cmd->option->info)->user)
	    && strcmp(cmd->data.list[0], "*")) {
	/* user may use other usernames to mount volumes using luserconf */
	snprintf(errmsg, BUFSIZ + 1,
		 "pam_mount: ignoring volume record for %s",
		 cmd->data.list[0]);
	return NULL;
    }
    for (i = 0; i < cmd->arg_count; i++)
        if (strlen(cmd->data.list[i]) > MAX_PAR) {
	    snprintf(errmsg, BUFSIZ + 1,
		 "pam_mount: command too long: %s", cmd->data.list[0]);
            return errmsg;
    }
    DATA = realloc(DATA, sizeof(data_t) * (VOLCOUNT + 1));
    memset(&DATA[VOLCOUNT], 0x00, sizeof(data_t));
    DATA[VOLCOUNT].globalconf = *((int *) cmd->context);
    strncpy(DATA[VOLCOUNT].user, cmd->data.list[0], MAX_PAR);
    DATA[VOLCOUNT].type = -1;
    for (i = 0; command[i].type != -1; i++)
	if (command[i].fs && !strcasecmp(cmd->data.list[1], command[i].fs)) {
	    DATA[VOLCOUNT].type = command[i].type;
	    break;
	}
    if (DATA[VOLCOUNT].type == -1) {
	snprintf(errmsg, BUFSIZ + 1,
		 "pam_mount: %s filesystem not supported",
		 cmd->data.list[1]);
	return errmsg;
    }
    if (*cmd->data.list[2] == '-')
	*DATA[VOLCOUNT].server = 0x00;
    else
	strncpy(DATA[VOLCOUNT].server, cmd->data.list[2], MAX_PAR);
    strncpy(DATA[VOLCOUNT].volume, cmd->data.list[3], MAX_PAR);
    if (*cmd->data.list[4] == '-')
	*DATA[VOLCOUNT].mountpoint = 0x00;
    else
	strncpy(DATA[VOLCOUNT].mountpoint, cmd->data.list[4], MAX_PAR);
    if (*cmd->data.list[5] == '-')
	*DATA[VOLCOUNT].options = 0x00;
    else
	strncpy(DATA[VOLCOUNT].options, cmd->data.list[5], MAX_PAR);
    if (*cmd->data.list[6] == '-')
	*DATA[VOLCOUNT].fs_key_cipher = 0x00;
    else
	strncpy(DATA[VOLCOUNT].fs_key_cipher, cmd->data.list[6],
		MAX_PAR);
    if (*cmd->data.list[7] == '-')
	*DATA[VOLCOUNT].fs_key_path = 0x00;
    else
	strncpy(DATA[VOLCOUNT].fs_key_path, cmd->data.list[7],
		MAX_PAR);
    strncpy(DATA[VOLCOUNT].password,
	    ((config_t *) cmd->option->info)->system_password,
	    MAX_PAR);
    if (!volume_record_sane
	(cmd->data.list, ((config_t *) cmd->option->info), errmsg))
	return errmsg;
    if (! DATA[VOLCOUNT].globalconf
	&& !luserconf_volume_record_sane(cmd->data.list,
					 ((config_t *) cmd->option->info),
					 errmsg))
	return errmsg;
    VOLCOUNT++;
    return NULL;
#undef DATA
#undef VOLCOUNT
}

/* ============================ option_in_string () ======================== */
/* PRE:    opt points to an option != NULL
 *         str points to list of options (ie: "opt1,opt2,...") != NULL
 * FN VAL: if opt appears in str then 1 else 0 */
int option_in_string(char *opt, char *str)
{
    char *ptr;
    w4rn("pam_mount: %s passed to option_in_string()\n", str);
    while (ptr = strchr(str, ',')) {
	w4rn("pam_mount: checking %s\n", str);
	if (!strncmp(opt, str, ptr - str))
	    return 1;
	str = ptr + 1;
    }
    w4rn("pam_mount: checking %s\n", str);
    if (!strcmp(opt, str))
	return 1;
    return 0;
}

/* ============================ options_allow_ok () ======================== */
/* PRE:    conf points to an array of allowed options (first item may be 
 *           NULL if no options sepcified)
 *         options points to a string representing a list of options requested
 *           for a volume or ""
 * FN VAL: if options acceptable by conf 1 else 0 with error logged */
options_allow_ok(char *conf[], char *options)
{
    int i, ok;
    char *ptr;
    w4rn("pam_mount: checking %s\n", options);
    if (strcmp(options, "*"))
        return 1;
    while (ptr = strchr(options, ',')) {
	ok = 0;
	w4rn("pam_mount: checking %s\n", options);
	for (i = 0; conf[i]; i++) {
	    if (!strncmp(conf[i], options, ptr - options))
		ok = 1;
	}
	options = ptr + 1;
	if (!ok) {
	    log("pam_mount: %s\n", "option not allowed");
	    return 0;
	}
    }
    ok = 0;
    w4rn("pam_mount: checking %s\n", options);
    for (i = 0; conf[i]; i++) {
	if (!strcmp(conf[i], options))
	    ok = 1;
    }
    if (!ok)
	log("pam_mount: %s\n", "option not allowed");
    return ok;
}

/* ============================ options_required_ok () ===================== */
/* PRE:    conf points to an array of required options (first item may not 
 *           be NULL)
 *         options points to a string representing a list of options requested
 *           for a volume or ""
 * FN VAL: if options acceptable by conf 1 else 0 with error logged */
options_required_ok(char *conf[], char *options)
{
    int i;
    for (i = 0; conf[i]; i++) {
	if (!option_in_string(conf[i], options)) {
	    log("pam_mount: option %s required\n", conf[i]);
	    return 0;
	}
    }
    return 1;
}

/* ============================ options_deny_ok () ========================= */
/* PRE:    conf points to an array of denied options (first item may be 
 *           NULL if no options sepcified)
 *         options points to a string representing a list of options requested
 *           for a volume or ""
 * FN VAL: if options acceptable by conf 1 else 0 with error logged */
options_deny_ok(char *conf[], char *options)
{
    int i;
    if (!conf[0]) {
	w4rn("pam_mount: %s\n", "no denied options");
	return 1;
    } else if (!strcmp(conf[0], "*") && strlen(options)) {
	log("pam_mount: %s\n",
	    "all mount options denied, user tried to specify one");
	return 0;
    }
    for (i = 0; conf[i]; i++) {
	if (option_in_string(conf[i], options)) {
	    log("pam_mount: option %s denied\n", conf[i]);
	    return 0;
	}
    }
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
int readconfig(const char *user, char *file, int globalconf,
	       config_t * config)
{
    configfile_t *configfile;
    const char *errmsg;
    if (!
	(configfile =
	 dotconf_create(file, legal_config, &globalconf, NONE))) {
	log("pam_mount: error opening %s\n", file);
	return 0;
    }
    configfile->errorhandler = (dotconf_errorhandler_t) log_error;
    if (!dotconf_command_loop(configfile))
        log("pam_mount: error reading %s\n", file); /* may not be fatal */
    if (!globalconf) {
	int i;
	if (config->options_allow[0] && config->options_deny[0]) {
	    log("pam_mount: %s\n",
		"possible conflicting option settings, denying all");
	    config->options_deny[0] = "*";
	}
	for (i = 0; i < config->volcount; i++) {
	    if (config->data[i].globalconf)
		continue;
	    if (config->options_require[0]) {
		w4rn("pam_mount: %s\n", "verifying options required");
		if (!options_required_ok
		    (config->options_require, config->data[i].options)) {
		    dotconf_cleanup(configfile);
		    return 0;
		}
	    }
	    if (config->options_allow[0]) {
		w4rn("pam_mount: %s\n", "verifying options allow");
		if (!options_allow_ok
		    (config->options_allow, config->data[i].options)) {
		    dotconf_cleanup(configfile);
		    return 0;
		}
	    } else if (config->options_deny[0]) {
		w4rn("pam_mount: %s\n", "verifying options deny");
		if (!options_deny_ok
		    (config->options_deny, config->data[i].options)) {
		    dotconf_cleanup(configfile);
		    return 0;
		}
	    } else {
		if (*config->data[i].options) {
		    log("pam_mount: %s\n",
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
void initconfig(config_t * config)
{
    int i;
    config->volcount = 0;
    config->debug = DEBUG_DEFAULT;
    config->mkmountpoint = MKMOUNTPOINT_DEFAULT;
    for (i = 0; i < COMMAND_MAX; i++)
	*config->command[i] = 0x00;
    memset(config->options_require, 0x00, MAX_PAR + 1);
    memset(config->options_allow, 0x00, MAX_PAR + 1);
    memset(config->options_deny, 0x00, MAX_PAR + 1);
}

/* ============================ freeconfig () ============================== */ 
/* PRE:  config is a valid, initialized config_t structure
 * POST: all dynamically allocated memory in config is freed */
void freeconfig(config_t config)
{
    int i = 0, j = 0;
    while(config.options_require[i])
        free(config.options_require[i++]);
    i = 0;
    while(config.options_allow[i])
        free(config.options_allow[i++]);
    i = 0;
    while(config.options_deny[i])
        free(config.options_deny[i++]);
    i = 0;
    for (i = 0; i < COMMAND_MAX; i++)
        while(config.command[j][i])
	    free(config.command[j++][i]);
}

/* ============================ expand_home () ============================= */
/* PRE:    path points to the path to expand (ie: ~/foo)
 * FN VAL: expanded path (ie: /home/usr/foo) */
char *expand_home(char *path, const char *user)
{
    char *tmp = NULL;
    struct passwd *p = getpwnam(user);
    if (p) {
	/* don't need to + 1 len because ~ is dropped from path */
	tmp = (char *) malloc(strlen(p->pw_dir) + strlen(path));
	if (tmp) {
	    strcpy(tmp, p->pw_dir);
	    strcat(tmp, path + 1);
	}
    }
    return tmp;
}

/* ============================ expand_wildcard () ========================= */
/* PRE:    str points to the string to expand (must contain at least one &)
 *         user is the username to expand to
 * FN VAL: str with any &s expanded into user */
char *expand_wildcard(char *str, const char *user)
{
    char *result = NULL;
    char *pos;
    w4rn("pam_mount: expand_wildcard for %s\n", str);
    if (str == NULL) {
	return NULL;
    }
    pos = strchr(str, '&');
    if (pos) {
	char *next;
	/* don't need to + 1 len because & is dropped from path */
	result = malloc(strlen(str) + strlen(user));
	strcpy(result, str);
	strcpy(result + (pos - str), user);
	strcat(result, pos + 1);
	next = expand_wildcard(result, user);
	if (next) {
	    free(result);
	    result = next;
	}
    }
    return (result);
}

/* ============================ expandconfig () ============================ */
/* PRE:  config points to a valid config_t structure that has been filled
 * POST: any wildcards in config->data are expanded */
void expandconfig(config_t * config)
{
    int i;
    for (i = 0; i < config->volcount; i++) {
	char *tmp;
	if (*config->data[i].mountpoint == '~') {
	    tmp = expand_home(config->data[i].mountpoint, config->user);
	    if (tmp) {
		strncpy(config->data[i].mountpoint, tmp, FILENAME_MAX + 1);
		free(tmp);
	    }
	}
	if (!strcmp(config->data[i].user, "*")) {
	    strcpy(config->data[i].user, config->user);
	    tmp = expand_wildcard(config->data[i].volume, config->user);
	    if (tmp) {
		strncpy(config->data[i].volume, tmp, MAX_PAR + 1);
		free(tmp);
	    }
	    tmp =
		expand_wildcard(config->data[i].mountpoint, config->user);
	    if (tmp) {
		strncpy(config->data[i].mountpoint, tmp, FILENAME_MAX + 1);
		free(tmp);
	    }
	    tmp = expand_wildcard(config->data[i].options, config->user);
	    if (tmp) {
		strncpy(config->data[i].options, tmp, MAX_PAR + 1);
		free(tmp);
	    }
	}
    }
}
