#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include "pam_mount.h"

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>

struct pm_data data;
void sigchld(int arg);
void signal_handler(int arg);
void config_signals();
void parsecommand(const char *command, const char* name, char ***parg);
void unmount_volume();

int debug;


int main(int argc, char **argv)
{
	int total,n;
	char *cmdarg[20];
	char **parg;
	int child;

	bzero(&data, sizeof(data));

	config_signals();
	child = -1;

	total = 0;
	while (total < sizeof(data)) {
		n = read(0, ((char *) &data) + total, sizeof(data) - total);
		if (n <= 0) {
			fprintf(stderr, 
				"\npam_mount failed to receive mount data 1\n\n");
			return 0;
		}
		total += n;
	}
	if (total != sizeof(data)) {
		fprintf(stderr,
			"\npam_mount failed to receive mount data 2\n\n");
		return 0;
	}

	debug = data.debug;

	w4rn("%s", "Received");
	w4rn("%s", "--------");
	w4rn("%s", data.server);
	w4rn("%s", data.user);
	// w4rn("%s", data.password);
	w4rn("%s", data.volume);
	w4rn("%s", data.mountpoint);
	w4rn("%s", data.command);

	sleep(1);

	if (data.unmount) {
		w4rn("%s", "Unmounting");
		unmount_volume();
		return 0;
	}

	parg = cmdarg;
	if (data.type == NCPMOUNT) {
		parsecommand(data.command, "ncpmount", &parg);
		*(parg++) = "-S";
		*(parg++) = data.server;
		*(parg++) = "-U";
		*(parg++) = data.user;
		*(parg++) = "-P";
		*(parg++) = data.password;
		*(parg++) = "-V";
		*(parg++) = data.volume;
		*(parg++) = data.mountpoint;
	} else if (data.type == SMBMOUNT) {
		parsecommand(data.command, "smbmount", &parg);
		asprintf(parg++, "//%s/%s", data.server, data.volume);
		w4rn("asprintf %s\n", *(parg-1));
		*(parg++) = data.mountpoint;
		*(parg++) = "-o";
		asprintf(parg++, "username=%s%%%s%s%s",
			 data.user, data.password, 
			 data.options[0] ? "," : "",
			 data.options);
	} else {
		w4rn("%s", "oops... data.type is unkonwn !!");
		return 0;
	}
	*(parg++) = NULL;

	child = fork();
	if (child == -1) {
		w4rn("%s", "pam_mount failed to fork");
		return 0;
	}

	if (child == 0) {
		/* This is the child */
		if (! debug) {
			close(0);
			close(1);
			close(2);
		}

		execv(cmdarg[0], &cmdarg[1]);

		/* should not reach next instruction */
		w4rn("%s", "pam_mount failed to execv mount command");
		return 0;
	}

	/* Clean password so virtual memory does not retain it */
	bzero(&(data.password), sizeof(data.password));

	w4rn ("%s", "Waiting for homedir mount\n");
	waitpid (child, NULL, 0);

	/* Unmounting is PAM module responsability */
	return 0;
}

void config_signals()
{
	signal(SIGCHLD, sigchld);

	// Pipe will be eventually closed by parent
	// but we don't mind

	signal(SIGPIPE, SIG_IGN);
}

/* SIGCHLD handler */

void sigchld(int arg)
{
	wait( (int *) NULL );
	config_signals();
}

/* Unmount function */

void unmount_volume()
{
	char *cmdarg[4];
	cmdarg[0] = data.ucommand;
	cmdarg[1] = "umount";
	cmdarg[2] = data.mountpoint;
	cmdarg[3] = NULL;

	close(0);
	close(1);
	close(2);

	execv(cmdarg[0], &cmdarg[1]);

	/* should not reach next instruction */
	w4rn("%s", "pmhelper failed to execv umount command");
	_exit(1);
}

void parsecommand(const char *command, const char *name, char ***pparg)
{
	char *sprov = strdup(command);
	char *argument;

	w4rn("%s", "Entering parsecommand");

	argument = strtok(sprov, "\t\n ");
	while (argument) {
		w4rn("Adding token %s", argument);
		**pparg = strdup(argument);
		(*pparg)++;
		if (name) {
			w4rn("Adding token %s", name);
			**pparg = strdup(name);
			(*pparg)++;
			name = NULL;
		}
		argument = strtok(NULL, "\t\n ");
	}

	w4rn("%s", "Finishing parsecommand");

	free(sprov);
}
