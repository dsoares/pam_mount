/* This is the PAM module */

#include <config.h>
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

int get_volumes(pm_data ** data[], const char *user, const char *password);
int invoke_child(pm_data * data, char *command[]);

int read_password(pam_handle_t * pamh, const char *prompt1, char **pass);

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

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
    char *password;
    int x;
    int ret;
    int get_pass = GETPASS_DEFAULT;
    int i;
    debug = DEBUG_DEFAULT;
    for (i = 0; i < argc; i++) {
	if (!strcmp("use_first_pass", argv[i])) {
	    get_pass = 0;
	} else if (!strcmp("try_first_pass", argv[i])) {
	    get_pass = 1;
	}
	w4rn("pam_mount: pam_sm_authenticate args: %s", argv[i]);
    }
    w4rn("%s", "pam_mount: beginning");
    for (x = 0; x < COMMAND_MAX; ++x) {
	command[x] = NULL;
    }
    if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
	return ret;
    pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password);
    if (!password) {
	log("%s", "pam_mount: could not get password");
	return PAM_SUCCESS;
    }
    w4rn("pam_mount: user=%s", user);
    /* w4rn("Password=%s", password); */
    if (strlen(user) > MAX_PAR || strlen(password) > MAX_PAR) {
	log("%s", "pam_mount: user or password too long");
	return PAM_SUCCESS;
    }
    volcount = 0;
    w4rn("%s", "pam_mount: going to readconfig");
    if (!readconfig(user, password, command, &volcount, &data)) {
	log("%s", "pam_mount: could not get mountable volumes for user");
	return PAM_SUCCESS;
    }
    w4rn("%s", "pam_mount: back from readconfig");
    if (volcount <= 0) {
	w4rn("%s", "pam_mount: no volumes to mount");
    }
    signal(SIGPIPE, SIG_IGN);
    for (x = 0; x < volcount; ++x) {
	w4rn("%s", "pam_mount: FATHER calling child proc");
	if (invoke_child(data + x, command) != 1) {
	    w4rn("%s", "pam_mount: FATHER Could not start helper process");
	    if (get_pass) {
		char *passread;
		/* get the password */
		read_password(pamh, "mount password:", &passread);
		/* try with the password read */
		strcpy((data)[x].password, passread);
		invoke_child(data + x, command);
		_pam_overwrite(passread);
		_pam_drop(passread);
	    }
	    return PAM_SUCCESS;
	}
    }
    return PAM_SUCCESS;
}

PAM_EXTERN
    int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
			     const char **argv)
{
    int x;

    w4rn("%s", "pam_mount: received order to close things");
    sleep(1);
    if (volcount <= 0) {
	w4rn("%s", "pam_mount: volcount is zero");
	sleep(2);
    }

    signal(SIGPIPE, SIG_IGN);

    for (x = 0; x < volcount; ++x) {
	w4rn("%s", "pam_mount: FATHER calling child proc to unmount");
	sleep(1);
	data[x].unmount = 1;
	if (invoke_child(data + x, command) != 1) {
	    log("%s",
		"pam_mount: FATHER could not start helper process to umount");
	    return PAM_SUCCESS;
	}
    }

    return PAM_SUCCESS;
}

int invoke_child(pm_data * data, char *command[])
{
    int filedes[2];
    int count, n;
    int child;
    int child_exit;

    if (pipe(filedes)) {
	log("%s", "pam_mount: could not create pipe pair");
	return 0;
    }

    if (debug) {
	fprintf(stderr,
		"pam_mount: BTW our real and effective user ID are %d and %d.\n",
		getuid(), geteuid());
    }

    child = fork();

    if (child == -1) {
	log("%s", "pam_mount: could not invoke helper child");
	return 0;
    }

    if (child == 0) {
	/* We are the child */
	close(filedes[1]);
	dup2(filedes[0], 0);
	execl(command[PMHELPER], "pmhelper", NULL);
	/* could not execl ... */
	log("%s", "pam_mount: CHILD Could not execl helper child");
	log("pam_mount: CHILD command was %s", command[PMHELPER]);
	_exit(1);
    }

    /* Father code */

    w4rn("%s", "pam_mount: sending data...");

    close(filedes[0]);
    count = 0;
    while (count < sizeof(pm_data)) {
	w4rn("%s", "pam_mount: inside loop...");
	n = write(filedes[1],
		  ((char *) data) + count, sizeof(pm_data) - count);
	if (n < 0) {
	    log("%s", "pam_mount: could not write data to child");
	    close(filedes[1]);
	    kill(child, SIGKILL);
	    return 0;
	}
	count += n;
    }

    w4rn("%s", "pam_mount: PAM returning");
    close(filedes[1]);
    waitpid(child, &child_exit, 0);

    /* if child was successful, it will return 0.
       hence return 1 to caller to indicate success. */
    if (WEXITSTATUS(child_exit) == 0)
	return 1;
    else
	return WEXITSTATUS(child_exit);
}

PAM_EXTERN
    int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
		       const char **argv)
{
    return PAM_SUCCESS;
}
