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
	int fds[2];
	int child_exit;
	int i;

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

	w4rn("%s", "pmhelper: received");
	w4rn("%s", "pmhelper: --------");
	w4rn("pmhelper: %s", data.server);
	w4rn("pmhelper: %s", data.user);
	/* w4rn("pmhelper: %s", data.password); */
	w4rn("pmhelper: %s", data.volume);
	w4rn("pmhelper: %s", data.mountpoint);
	w4rn("pmhelper: %s", data.command);
	w4rn("%s", "pmhelper: --------");

	sleep(1);

	if (data.unmount) {
		w4rn("%s", "pmhelper: unmounting");
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
		w4rn("pmhelper: asprintf %s", *(parg-1));
		*(parg++) = data.mountpoint;
		*(parg++) = "-o";
		asprintf(parg++, "username=%s%%%s%s%s",
			 data.user, data.password, 
			 data.options[0] ? "," : "",
			 data.options);
	} else if (data.type == LCLMOUNT) {
		parsecommand(data.command, "mount", &parg);
		*(parg++) = data.volume;

		if (data.mountpoint[0])
			*(parg++) = data.mountpoint;
		
		if (data.options[0]) {
			*(parg++) = "-o";
			*(parg++) = data.options;
		}

		/* XXX should check that we actually need to send a password
		  before creating the pipe */
		if (pipe(fds) != 0) {
			log("%s", "pmhelper: could not make pipe\n");
			return 0;
		}
	} else {
		log("%s", "pmhelper: data.type is unkonwn");
		return 0;
	}
	*(parg++) = NULL;

	w4rn("%s", "pmhelper: about to fork");
	child = fork();
	if (child == -1) {
		log("%s", "pmhelper: failed to fork");
		return 0;
	}

	if (child == 0) {
		/* This is the child */

		if (data.type == LCLMOUNT) {
			/* XXX want to use same fd as specified in config file
			   (rather than STDIN) */
			/* XXX may want to check that password is actually needed
			   for this mount */
			close(fds[1]);
			dup2(fds[0], STDIN_FILENO);
		}

		for (i=0; cmdarg[i]; i++) {
			w4rn("pmhelper: arg is: %s", cmdarg[i]);
		}
		
		if(setuid(0) == -1)
			w4rn("%s", "pmhelper: could not set uid to 0");
		execv(cmdarg[0], &cmdarg[1]);

		/* should not reach next instruction */
		log("%s", "pmhelper: failed to execv mount command");
		return 0;
	}

	if (data.type == LCLMOUNT) {
		/* XXX might want to check that password is actually needed
		   for this mount */
	
		/* send password down pipe to mount process */
		write(fds[1], data.password, strlen(data.password)+1);
		close(fds[0]);
		close(fds[1]);
	}

	/* Clean password so virtual memory does not retain it */
	bzero(&(data.password), sizeof(data.password));

#if 0
	w4rn ("%s", "pmhelper: waiting for homedir mount\n");
	waitpid (child, NULL, 0);
#endif

	w4rn ("%s", "pmhelper: waiting for homedir mount\n");
	waitpid (child, &child_exit, 0);
	w4rn ("pmhelper: mount returning %d\n", WEXITSTATUS(child_exit));
 
 	/* Unmounting is PAM module responsability */

	/* pass on through the result from the mount process */
	return WEXITSTATUS(child_exit);
}

void config_signals()
{
	signal(SIGCHLD, sigchld);

	/* Pipe will be eventually closed by parent but we don't mind */

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
	int i;
	char *cmdarg[4];
	cmdarg[0] = data.ucommand;
	cmdarg[1] = "umount";
	cmdarg[2] = data.volume;
	cmdarg[3] = NULL;

	for (i=0; cmdarg[i]; i++) {
		w4rn("pmhelper: arg is: %s", cmdarg[i]);
	}

	if(setuid(0) == -1)
		w4rn("%s", "pmhelper: could not set uid to 0");
	execv(cmdarg[0], &cmdarg[1]);

	/* should not reach next instruction */
	log("%s", "pmhelper: failed to execv umount command");
	_exit(1);
}

void parsecommand(const char *command, const char *name, char ***pparg)
{
	char *sprov = strdup(command);
	char *argument;

	w4rn("%s", "pmhelper: entering parsecommand");

	argument = strtok(sprov, "\t\n ");
	while (argument) {
		w4rn("pmhelper: adding token %s", argument);
		**pparg = strdup(argument);
		(*pparg)++;
		if (name) {
			w4rn("pmhelper: adding token %s", name);
			**pparg = strdup(name);
			(*pparg)++;
			name = NULL;
		}
		argument = strtok(NULL, "\t\n ");
	}

	w4rn("%s", "pmhelper: leaving parsecommand");

	free(sprov);
}
