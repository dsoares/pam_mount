#include <stdlib.h>
#include <string.h>
#include "pam_mount.h"

#define BUFSIZE ( ( ( MAX_PAR + 1 ) * 3 ) + FILENAME_MAX + 1 )

extern int debug;

const char *delim = "\t\n ";

void readvolume(const char *user, const char *password, int *volcount, 
		pm_data **data, char *command[], char *argument,
		int luserconf);
void readcommand(char *command[], char *argument, int v);
char *expand_wildcard(const char *value, const char *user);

int readconfig(const char *user, const char *password, char *command[], 
	       int *volcount, pm_data **data)
{
	FILE* conffile;
	char line[BUFSIZE];
	char *parameter;
	char *argument;
	char *luserconf;

	*volcount = 0;
	*data = (pm_data *) malloc(0);
	luserconf = NULL;
	
	w4rn("Trying to open %s", CONFIGFILE);

	conffile = fopen(CONFIGFILE, "r");
	if (! conffile) {
		w4rn("%s", "Could not open config file");
		return 0;
	}

	while ( fgets(line, BUFSIZE - 1, conffile) ) {

		parameter = strtok(line, delim);
		argument = strtok(NULL, delim);

		if (! parameter || ! argument) continue;
		w4rn("reading %s", parameter);

		if (strchr(parameter, '#')) continue;

		
		if (strcmp(parameter, "debug") == 0) {
			debug = strcmp(argument, "1") == 0 ? 1 : 0;
			continue;
		}

		if (strcmp(parameter, "luserconf") == 0) {

			if (strlen(argument) > FILENAME_MAX) {
				w4rn("%s", "strlen(luserconf) > FILENAME_MAX");
				continue;
			}

			luserconf = (char *) malloc(strlen(argument)+3);
			luserconf[0] = '\0';
			strcat(luserconf, "~/");
			strcat(luserconf, argument);

			if (! owns(user, luserconf)) {
				w4rn("%s", "User does not own <luserconf>");
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

	conffile = fopen(luserconf, "r");
	if (! conffile) {
		w4rn("%s", "Could not open local config file");
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

	w4rn("Fuser: %s", fuser);
	w4rn("User: %s", user);
	w4rn("Type: %s", type);
	w4rn("Server: %s", server);
	w4rn("Volume: %s", volume);
	w4rn("Mountpoint: %s", mountpoint);
	w4rn("Options: %s", options);

	if (strcmp(fuser, "*") == 0) {
		if (luserconf) {
			/* local user config file cannot have wildcards */
			return;
		}
		autovolume = expand_wildcard (volume, user);
		if (autovolume) {
			volume = autovolume;
			w4rn("Volume: %s", autovolume);
		}
		automount = expand_wildcard (mountpoint, user);
		if (automount) {
			mountpoint = automount;
			w4rn("Automount: %s", automount);
		}
		autooptions = expand_wildcard (options, user);
		if (autooptions) {
			options = autooptions;
			w4rn("Autooptions: %s", autooptions);
		}
	} else if (strcmp(fuser, user) != 0) {
		w4rn("%s", "Not me");
		return;
	}

	if (! options) {
		options = "";
	} else if (strcmp(options, "-") == 0) {
		options = "";
	}

	if (!fuser || !server || !volume || !mountpoint || !type) {
		w4rn("%s", "Missing parameters");
		return;
	}

	if (strlen(server) > MAX_PAR) {
		w4rn("%s", "Server parameter too long");
		return;
	}

	if (strlen(volume) > MAX_PAR) {
		w4rn("%s", "Volume parameter too long");
		return;
	}

	if (strlen(options) > MAX_PAR) {
		w4rn("%s", "Options parameter too long");
		return;
	}

	ntype = -1;
	ntype = strcasecmp(type, "smb") == 0 ? SMBMOUNT : ntype;
	ntype = strcasecmp(type, "smbfs") == 0 ? SMBMOUNT : ntype;
	ntype = strcasecmp(type, "ncp") == 0 ? NCPMOUNT : ntype;
	ntype = strcasecmp(type, "ncpfs") == 0 ? NCPMOUNT : ntype;

	if (ntype == -1) {
		w4rn("%s", "This filesystem type is not supported");
		return;
	}
	
	if (strlen(mountpoint) > FILENAME_MAX) {
		w4rn("%s", "Mount point parameter too long");
		return;
	}

	if (exists(mountpoint) != 1) {
		w4rn("%s", "Mountpoint does not exist");
		return;
	}

	if (! automount && ! owns(user, mountpoint)) {
		w4rn("%s", "User does not own the mountpoint");
		return;
	}

	if (! command[ntype]) {
		w4rn("Mount command not defined for %s", type);
		return;
	}

	if (! command[UMOUNT]) {
		w4rn("%s", "Unmount command not defined");
		return;
	}

	*data = realloc(*data, sizeof(pm_data) * (*volcount + 1));

	// data is a pointer to a flat pm_data array

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

	w4rn("%s", "Added one\n");

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
			w4rn("Adding %s to command", argument);
			strcat(command[v], argument);
		}
		if ((argument = strtok(NULL, delim))) {
			strcat(command[v], " ");
		}
	}

	command[v][FILENAME_MAX] = '\0';
	w4rn("Complete command is %s.", command[v]);
}

/* Replaces first occurence of & with user.  Returns NULL if no work
   was necessary, or a new copy otherwise. */

char *expand_wildcard(const char *value, const char *user)
{
	char *result = NULL;
	char *pos;

	w4rn ("expand_wildcard for %s", value);

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
