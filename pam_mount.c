/* This is the PAM module */

#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <security/_pam_macros.h>

#define PAM_SM_SESSION
#define _PAM_EXTERN_FUNCTIONS
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include "pam_mount.h"

int debug;
int volcount;
pm_data *data;
char *command[COMMAND_MAX];
const char *user;

int get_volumes(pm_data **data[], const char *user, const char *password);
int invoke_child(pm_data *data, char *command[]);

/*

int pam_start(const char *service_name, const char *username,
	  const struct pam_conv *conv, pam_handle_t **pamh_p)
{
	if (strcmp(service_name, "login")) {
		printf("\nThis module is intended for 'login'\n\n");
		return PAM_SESSION_ERR;
	}
	return PAM_SUCCESS;
}

*/

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	                        int argc, const char **argv)
{
	int ret;
	ret = pam_sm_authenticate(pamh, flags, argc, argv);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	char *password;

	int x;
	int ret;

	debug = DEBUG_DEFAULT;
	w4rn("%s", "pam_mount: beggining");

	for(x = 0; x < COMMAND_MAX; ++x) {
		command[x] = NULL;
	}

	if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return ret;
	
	pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password);
	if (!password) {
		w4rn("%s", "Could not get password");
		return PAM_SUCCESS;
	}

	w4rn("User=%s", user);
	// w4rn("Password=%s", password);

	if (strlen(user) > MAX_PAR || strlen(password) > MAX_PAR) {
		w4rn("%s", "User or password too long");
		return PAM_SUCCESS;
	}

	volcount = 0;

	w4rn("%s", "Going to readconfig");

	if (! readconfig(user, password, command, &volcount, &data)) {
		w4rn("%s", "Could not get mountable volumes for user");
		return PAM_SUCCESS;
	}

	w4rn("%s", "Back from readconfig");
	if (volcount <= 0) {
		w4rn("%s", "No volumes to mount");
	}

	signal(SIGPIPE, SIG_IGN);

	for(x=0; x < volcount; ++x) {
		w4rn("%s", "FATHER> calling child proc");
		if (! (invoke_child(data+x, command))) {
			w4rn("%s", "FATHER> Could not start helper process");
			return PAM_SUCCESS;
		}
	}

	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int x;

	w4rn("%s", "Received order to close thingz");
	sleep(1);
	if (volcount <= 0) {
		w4rn("%s", "Fuck, volcount is zero !!!");
		sleep(2);
	}

	signal(SIGPIPE, SIG_IGN);

	for(x=0; x < volcount; ++x) {
		w4rn("%s", "FATHER> calling child proc to unmount");
		sleep(1);
		data[x].unmount = 1;
		if (! (invoke_child(data+x, command))) {
			w4rn("%s", "FATHER> Could not start helper process");
			return PAM_SUCCESS;
		}
	}

	return PAM_SUCCESS;
}

int invoke_child(pm_data *data, char *command[])
{
	int filedes[2];
	int count, n;
	int child;

	if (pipe(filedes)) {
		w4rn("%s", "Could not create pipe pair");
		return 0;
	}

	if (debug) {
		fprintf(stderr, 
		   "\nBTW our real and effective user ID are %d and %d.\n", 
		   getuid(), geteuid());
	}

	child = fork();

	if (child == -1) {
		w4rn("%s", "Could not invoke helper child");
		return 0;
	}

	if (child == 0) {
		/* We are the child */
		close(filedes[1]);
		dup2(filedes[0], 0);
		execl(command[PMHELPER], "pmhelper", NULL);
		/* could not execl ... */
		w4rn("%s", "CHILD> Could not execl helper child");
		w4rn("CHILD> Command was %s", command[PMHELPER]);
		_exit(1);
	}

	/* Father code */

	w4rn("%s", "*********************** sending data...");

	close(filedes[0]);
	count = 0;
	while (count < sizeof(pm_data)) {
		w4rn("%s", "Inside loop...");
		n = write(filedes[1], 
		          ( (char *) data ) + count, 
		          sizeof(pm_data) - count);
		if (n < 0) {
			w4rn("%s", "Could not write data to child");
			close(filedes[1]);
			kill(child, SIGKILL);
			return 0;
		}
		count += n;
	}

	w4rn("%s", "********************** PAM returning");
	close(filedes[1]);
	waitpid(child, NULL, 0);

	return 1;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
		                   const char **argv)
{
	return PAM_SUCCESS;
}
