#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include "pam_mount.h"

#define BUFSIZE ( ( ( MAX_PAR + 1 ) * 3 ) + FILENAME_MAX + 1 )

#define MAX_FILTERS	20

#define OPTIONS_UNINIT	0
#define OPTIONS_ALLOW 	1
#define OPTIONS_DENY  	2
#define OPTIONS_ERROR	3

#define FILTERS_OKAY	0
#define FILTERS_TRUNC	1
#define FILTERS_BAD	2
#define FILTERS_WILD	3

extern int debug;

char *opt_allow_filter[MAX_FILTERS];
char *opt_deny_filter[MAX_FILTERS];
char *opt_required[MAX_FILTERS];
int opt_filter_count;
int opt_req_count;
int options_state;

const char *delim = "\t\n ";

void readvolume(const char *user, const char *password, int *volcount, 
		pm_data **data, char *command[], char *argument,
		int luserconf);
void readcommand(char *command[], char *argument, int v);
char *expand_wildcard(const char *value, const char *user);
int read_filters(char **filter_array, int *filter_count, char *opt_list);
int filter_options(const char *options);
int required_options(const char *options);

int readconfig(const char *user, const char *password, char *command[], 
	       int *volcount, pm_data **data)
{
	FILE* conffile;
	char line[BUFSIZE];
	char *parameter;
	char *argument;
	char *luserconf;
	struct passwd *passwd_ent;
	char *home_dir;

	options_state = OPTIONS_UNINIT;
	opt_filter_count = 0;
	opt_req_count = 0;
	
	*volcount = 0;
	*data = (pm_data *) malloc(0);
	luserconf = NULL;
	
	w4rn("pam_mount: trying to open %s", CONFIGFILE);

	conffile = fopen(CONFIGFILE, "r");
	if (! conffile) {
		log("pam_mount: could not open config file: %s", CONFIGFILE);
		return 0;
	}

	while ( fgets(line, BUFSIZE - 1, conffile) ) {

		parameter = strtok(line, delim);
		argument = strtok(NULL, delim);

		if (! parameter || ! argument) continue;
		w4rn("pam_mount: reading %s", parameter);

		if (strchr(parameter, '#')) continue;

		
		if (strcmp(parameter, "debug") == 0) {
			debug = strcmp(argument, "1") == 0 ? 1 : 0;
			continue;
		}

		if (strcmp(parameter, "options_allow") == 0) {
			/* don't allow ambiguity on the options filter.
			   fallback to most restrictive (allow none). */
			if (options_state != OPTIONS_UNINIT) {
				w4rn("%s", "pam_mount: potentially conflicting options filters. disallowing all options.");
				options_state = OPTIONS_ALLOW;
				opt_filter_count = 0;

				continue;
			}
			
			options_state = OPTIONS_ALLOW;

			switch (read_filters(opt_allow_filter, &opt_filter_count,
			argument)) {
				case FILTERS_OKAY:	/* success */
					break;
				case FILTERS_TRUNC:	/* truncated */
					w4rn("%s", "pam_mount: too many allowed options truncating list.");
					break;
				case FILTERS_BAD: /* bad filter */
					w4rn("%s", "pam_mount: bad filter description.");
					options_state = OPTIONS_ALLOW;
					opt_filter_count = 0;
					break;
				case FILTERS_WILD:	/* wildcard */
					/* allow all is same as deny none */
					options_state = OPTIONS_DENY;
					opt_filter_count = 0;
					break;
				default:
					w4rn("%s", "pam_mount: unknown error while reading"
						" filter");
					options_state = OPTIONS_ALLOW;
					opt_filter_count = 0;
					break;
			}

			continue;
		}
		
		if (strcmp(parameter, "options_deny") == 0) {
			/* don't allow ambiguity on the options filter.
			   fallback to most restrictive (allow none). */
			if (options_state != OPTIONS_UNINIT) {
				w4rn("%s", "pam_mount: potentially conflicting options filters. disallowing all options.");

				options_state = OPTIONS_ALLOW;
				opt_filter_count = 0;

				continue;
			}

			options_state = OPTIONS_DENY;

			switch (read_filters(opt_deny_filter, &opt_filter_count,
			argument)) {
				case FILTERS_OKAY:	/* success */
					break;
				case FILTERS_TRUNC:	/* truncated */
					w4rn("%s", "pam_mount: too many denied options -- falling back to deny all.");
					
					options_state = OPTIONS_ALLOW;
					opt_filter_count = 0;
					break;
				case FILTERS_BAD: /* bad filter */
					w4rn("%s", "pam_mount: bad filter description");
					options_state = OPTIONS_ALLOW;
					opt_filter_count = 0;
					break;
				case FILTERS_WILD:	/* wildcard */
					/* deny all is same as allow none */
					options_state = OPTIONS_ALLOW;
					opt_filter_count = 0;
					break;
				default:
					w4rn("%s", "pam_mount: unknown error while reading filter");
					options_state = OPTIONS_ALLOW;
					opt_filter_count = 0;
					break;
			}
			
			continue;
		}

		if (strcmp(parameter, "options_require") == 0) {
			w4rn("pam_mount: options_require: %s", argument);
			/* don't allow multiple directives. if that happens,
			   disable luser configs */
			if (opt_req_count != 0) {
				w4rn("%s", "pam_mount: multiple options_require directives -- disabling luserconf.");
				options_state = OPTIONS_ERROR;
				continue;
			}

			/* if the list is truncated, or contains wildcard,
			   then fallback as above */
			if (read_filters(opt_required, &opt_req_count,
			argument) != 0) {
				w4rn("%s", "pam_mount: too many required options -- disabling luserconf.");
				options_state = OPTIONS_ERROR;
				opt_req_count = 0;
			}
			continue;
		}

		if (strcmp(parameter, "luserconf") == 0) {
			if (strlen(argument) > FILENAME_MAX) {
				w4rn("%s", "pam_mount: strlen(luserconf) > FILENAME_MAX");
				continue;
			}

			passwd_ent = getpwnam(user);
			if (!passwd_ent) {
				home_dir = "~";
			} else {
				home_dir = passwd_ent->pw_dir;
			}
			
			/* home_directory/argument\0 */
			luserconf = (char *) malloc(strlen(home_dir)+1+
				strlen(argument)+1);
			luserconf[0] = '\0';
			strcat(luserconf, home_dir);
			strcat(luserconf, "/");
			strcat(luserconf, argument);

			if (! owns(user, luserconf)) {
				w4rn("%s", "pam_mount: user does not own <luserconf>");
				free(luserconf);
				luserconf = NULL;
				continue;
			}

			continue;
		}

		if (strcmp(parameter, "smbmount") == 0) {
			readcommand(command, argument, SMBMOUNT);
			continue;
		}

		if (strcmp(parameter, "ncpmount") == 0) {
			readcommand(command, argument, NCPMOUNT);
			continue;
		}

		if (strcmp(parameter, "lclmount") == 0) {
			readcommand(command, argument, LCLMOUNT);
		}
		
		if (strcmp(parameter, "umount") == 0) {
			readcommand(command, argument, UMOUNT);
			continue;
		}

		if (strcmp(parameter, "pmhelper") == 0) {
			readcommand(command, argument, PMHELPER);
			continue;
		}

		if (strcmp(parameter, "volume") == 0) {
			readvolume(user, password, volcount, data, command,
			           argument, 0);
			continue;
		}
	}
	fclose(conffile);

	if (! luserconf) {
		return 1;
	}

	/* if the options filters haven't been specified, do
	   the safe thing: don't allow user config files */
	if (options_state == OPTIONS_UNINIT) {
		w4rn("%s", "pam_mount: options filtering not specified -- ignoringluserconf");
		return 0;
	}

	if (options_state == OPTIONS_ERROR) {
		w4rn("%s", "pam_mount: an options error occurred -- ignorning luserconf.");
		return 0;
	}

	conffile = fopen(luserconf, "r");
	if (! conffile) {
		w4rn("%s", "pam_mount: could not open local config file");
		return 0;
	}

	while ( fgets(line, BUFSIZE - 1, conffile) ) {

		parameter = strtok(line, delim);
		argument = strtok(NULL, delim);

		if (! parameter || ! argument) continue;
		if (strchr(parameter, '#')) continue;
		
		if (strcmp(parameter, "debug") == 0) {
			debug = strcmp(argument, "1") == 0;
			continue;
		}

		if (strcmp(parameter, "volume") == 0) {
			readvolume(user, password, volcount, data, command,
			           argument, 1);
			continue;
		}
	}
	fclose(conffile);

	return 1;
}


void readvolume(const char *user, const char *password, int *volcount, 
		pm_data **data, char *command[], char *argument,
		int luserconf)
{
	char *type;
	int ntype;
	char *fuser;
	char *server;
	char *volume;
	char *mountpoint;
	char *options;
	char *automount = NULL;
	char *autovolume = NULL;
	char *autooptions = NULL;

	fuser = argument;
	type = strtok(NULL, "\t\n ");
	server = strtok(NULL, "\t\n ");
	volume = strtok(NULL, "\t\n ");
	mountpoint = strtok(NULL, "\t\n ");
	options = strtok(NULL, "\t\n ");

	w4rn("pam_mount: fuser: %s", fuser);
	w4rn("pam_mount: user: %s", user);
	w4rn("pam_mount: type: %s", type);
	w4rn("pam_mount: server: %s", server);
	w4rn("pam_mount: volume: %s", volume);
	w4rn("pam_mount: mountpoint: %s", mountpoint);
	w4rn("pam_mount: options: %s", options);

	if (strcmp(fuser, "*") == 0) {
		if (luserconf) {
			/* local user config file cannot have wildcards */
			return;
		}
		autovolume = expand_wildcard (volume, user);
		if (autovolume) {
			volume = autovolume;
			w4rn("pam_mount: volume: %s", autovolume);
		}
		automount = expand_wildcard (mountpoint, user);
		if (automount) {
			mountpoint = automount;
			w4rn("pam_mount: automount: %s", automount);
		}
		autooptions = expand_wildcard (options, user);
		if (autooptions) {
			options = autooptions;
			w4rn("pam_mount: autooptions: %s", autooptions);
		}
	} else if (strcmp(fuser, user) != 0) {
		w4rn("%s", "pam_mount: not me");
		return;
	}

	if (! options) {
		options = "";
	} else if (strcmp(options, "-") == 0) {
		options = "";
	}
	if (! mountpoint)
		mountpoint = "";

	/* if we have options, and this is the user config file,
	   check the options against the allow/deny filter from
	   the global config file */
	if (*options!='\0' && luserconf) {
		if (!filter_options(options)) {
			log("%s", "pam_mount: options conflict with filters");
			return;
		}
	}
			
	/* for the user config file, make sure the required options
	   specified in the global config file are present */
	if (luserconf && !required_options(options)) {
		log("%s", "pam_mount: does not contain required options");
		return;
	}
	
	if (!fuser || !server || !volume || !type) {
		log("%s", "pam_mount: missing parameters");
		return;
	}

	if (strlen(server) > MAX_PAR) {
		w4rn("%s", "pam_mount: server parameter too long");
		return;
	}

	if (strlen(volume) > MAX_PAR) {
		log("%s", "pam_mount: volume parameter too long");
		return;
	}

	if (strlen(options) > MAX_PAR) {
		log("%s", "pam_mount: options parameter too long");
		return;
	}

	ntype = -1;
	ntype = strcasecmp(type, "smb") == 0 ? SMBMOUNT : ntype;
	ntype = strcasecmp(type, "smbfs") == 0 ? SMBMOUNT : ntype;
	ntype = strcasecmp(type, "ncp") == 0 ? NCPMOUNT : ntype;
	ntype = strcasecmp(type, "ncpfs") == 0 ? NCPMOUNT : ntype;
	ntype = strcasecmp(type, "local") == 0 ? LCLMOUNT : ntype;

	if (ntype == -1) {
		log("%s", "pam_mount: this filesystem type is not supported");
		return;
	}
	
	if (mountpoint && strlen(mountpoint) > FILENAME_MAX) {
		log("%s", "pam_mount: mount point parameter too long");
		return;
	}

	/* FIXME: mountpoint may be undefined: if (exists(mountpoint) != 1) {
		w4rn("%s", "Mountpoint does not exist");
		return;
	}*/

	/* FIXME: mountpoint may be undefined: if (! automount && ! owns(user, mountpoint)) {
		w4rn("%s", "User does not own the mountpoint");
		return;
	}*/

	/* for local mounts, require that either
		- it's from the global config file
		- or the user owns the (file or device) that is being
		  mounted */
	if ((ntype == LCLMOUNT) && luserconf && ! owns(user, volume)) {
		w4rn("%s", "pam_mount: user does not own mount source");
		return;
	}
	
	if (! command[ntype]) {
		w4rn("pam_mount: mount command not defined for %s", type);
		return;
	}

	if (! command[UMOUNT]) {
		w4rn("%s", "pam_mount: unmount command not defined");
		return;
	}

	*data = realloc(*data, sizeof(pm_data) * (*volcount + 1));

	/* data is a pointer to a flat pm_data array */

	bzero(&((*data)[*volcount]), sizeof(pm_data));
	(*data)[*volcount].type = ntype;
	strcpy((*data)[*volcount].user, user);
	strcpy((*data)[*volcount].password, password);
	strcpy((*data)[*volcount].server, server);
	strcpy((*data)[*volcount].volume, volume);
	strcpy((*data)[*volcount].mountpoint, mountpoint);
	strcpy((*data)[*volcount].options, options);
	(*data)[*volcount].debug = debug;
	strcpy((*data)[*volcount].command, command[ntype]);
	strcpy((*data)[*volcount].ucommand, command[UMOUNT]);
	(*data)[*volcount].unmount = 0;

	w4rn("%s", "pam_mount: added one\n");

	(*volcount)++;

	if (autovolume) {
		free(autovolume);
	}
	if (automount) {
		free(automount);
	}
}

void readcommand(char *command[], char *argument, int v)
{
	command[v] = (char *) malloc(FILENAME_MAX + 1);
	command[v][0] = '\0';

	while (argument) {
		if (strlen(argument)+strlen(command[v])+1 < FILENAME_MAX) {
			w4rn("pam_mount: adding %s to command", argument);
			strcat(command[v], argument);
		}
		if ((argument = strtok(NULL, delim))) {
			strcat(command[v], " ");
		}
	}

	command[v][FILENAME_MAX] = '\0';
	w4rn("pam_mount: complete command is %s.", command[v]);
}

/* Replaces first occurence of & with user.  Returns NULL if no work
   was necessary, or a new copy otherwise. */

char *expand_wildcard(const char *value, const char *user)
{
	char *result = NULL;
	char *pos;

	w4rn ("pam_mount: expand_wildcard for %s", value);

	if (value == NULL) {
		return NULL;
	}
	pos = strchr (value, '&');
	if (pos) {
		char *next;

		result = malloc (strlen (value) + strlen (user));
		strcpy (result, value);
		strcpy (result + (pos - value), user);
		strcat (result, pos + 1);
		next = expand_wildcard (result, user);
		if (next) {
			free (result);
			result = next;
		}
	}

	return (result);
}


int read_filters(char **filter_array, int *filter_count, char *opt_list) {
	int i = 0;
	
	*filter_count = 0;
	w4rn ("pam_mount: read_filters: %s", opt_list);

	filter_array[0] = strtok(opt_list, ","); i=1;
	w4rn ("pam_mount: read_filters: %s", filter_array[0]);

	/* either there was an empty allow/deny line, or the strdup failed.
	   we treat either as a truncated list. */
	if (!filter_array[0] || !(filter_array[0] = strdup(filter_array[0]))) {
		return FILTERS_TRUNC;
	}

	/* read the rest of the filters, unless we got the wildcard filter */
	if (strcmp(filter_array[0], "*")!=0) {
		while (i < MAX_FILTERS && (filter_array[i] = strtok(NULL, ","))) {
			/* wildcard cannot be mixed with others */
			if (strcmp(filter_array[i], "*")==0) {
				return FILTERS_BAD;
			}

			if (!(filter_array[i] = strdup(filter_array[i]))) {
				/* couldn't get this filter... return 1
				   to indicate truncation */
				*filter_count = i;
				return FILTERS_TRUNC;
			}
			w4rn ("pam_mount: read_filters: %s", filter_array[i]);
			++i;
		}
	} else {
		return FILTERS_WILD;
	}

	*filter_count = i;

	/* any remaining tokens? */
	if (strtok(NULL, ",")!=NULL) {
		return FILTERS_TRUNC;
	} else {
		return FILTERS_OKAY;
	}
}

/* not particularly elegant implementations, but they should work anyway */
int filter_allow(char *opts) {
	char *opt;
	int i;
	
	opt = strtok(opts, ",");
	while (opt != NULL) {
		int matched = 0;
		
		for (i=0; i<opt_filter_count && !matched; ++i) {
			matched =
				strcmp(opt_allow_filter[i],opt) ? 0 : 1;
		}

		/* this option not on the allowed list */
		if (!matched) {
			log("pam_mount: option %s not allowed!", opt);
			return 0;
		}
		
		opt = strtok(NULL, ",");
	}

	/* everything we saw was allowed */
	return 1;
}

int filter_deny(char *opts) {
	char *opt;
	int i;
	
	opt = strtok(opts, ",");
	while (opt != NULL) {
		int matched = 0;
		
		for (i=0; i<opt_filter_count && !matched; ++i) {
			matched =
				strcmp(opt_deny_filter[i],opt) ? 0 : 1;
		}

		/* this option is on the deny list */
		if (matched) {
			w4rn("pam_mount: option %s denied!", opt);
			return 0;
		}
		
		opt = strtok(NULL, ",");
	}

	/* nothing we saw was denied */
	return 1;
}

int filter_options(const char *options) {
	char *my_options = strdup(options);
	int retval;
	
	switch (options_state) {
		case OPTIONS_ALLOW:
			retval = filter_allow(my_options);
			break;
		case OPTIONS_DENY:
			retval = filter_deny(my_options);
			break;
		default:
			/* shouldn't happen */
			w4rn("pam_mount: BUG at line %d?", __LINE__);
			retval=0;
			break;
	}
	
	free (my_options);
	return retval;
}

int required_options(const char *opts) {
	char *opt, *my_opts;
	int i;
	int num_matched = 0;

	if ((opts == NULL) && (opt_req_count != 0)) {
		return 0;
	}

	my_opts = strdup(opts);
	opt = strtok(my_opts, ",");
	while (opt != NULL) {
		int matched = 0;
		
		for (i=0; i<opt_req_count && !matched; ++i) {
			matched =
				strcmp(opt_required[i],opt) ? 0 : 1;
		}

		/* this option was required */
		if (matched) {
			w4rn("pam_mount: required option %s found", opt);
			num_matched++;
		}
		
		opt = strtok(NULL, ",");
	}

	free(my_opts);
	return (num_matched==opt_req_count) ? 1 : 0;
}
