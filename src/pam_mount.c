/* This is the PAM module */

#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <pam_mount.h>
#include <security/_pam_macros.h>

int debug;
int volcount;
pm_data *data;
char *command[COMMAND_MAX];
const char *user;

int invoke_child(pm_data * data, char *command[])
{
    int pipefd[2];
    int count, n;
    int child;
    int child_exit;
    if (pipe(pipefd)) {
	log("pam_mount: %s\n", "could not create pipe pair");
	return 0;
    }
    if (debug) {
	fprintf(stderr,
		"pam_mount: real and effective user ID are %d and %d.\n",
		getuid(), geteuid());
    }
    /* if our CWD is in the home directory, it might not get umounted */
    /* Needed for KDM.  FIXME: Bug in KDM? */
    if (chdir("/"))
	w4rn("pam_mount %s\n", "could not chdir");
    if ((child = fork()) == -1) {
	log("pam_mount: %s\n", "could not invoke helper child");
	return 0;
    }
    if (child == 0) {
	/* Child */
	close(pipefd[1]);
	if (dup2(pipefd[0], 0) == -1) {
	    log("pam_mount: %s\n", "CHILD could not dup stdin");
	    _exit(1);
	}
	execl(command[PMHELPER], "pmhelper", NULL);
	/* could not execl ... */
	log("pam_mount: %s\n", "CHILD Could not execl helper child");
	log("pam_mount: CHILD command was %s\n", command[PMHELPER]);
	_exit(1);
    }
    /* FIXME: security scrub stopped here. */
    /* Parent */
    w4rn("pam_mount: %s\n", "sending data...");
    close(pipefd[0]);
    count = 0;
    while (count < sizeof(pm_data)) {
	w4rn("pam_mount: %s\n", "inside loop...");
	n = write(pipefd[1],
		  ((char *) data) + count, sizeof(pm_data) - count);
	if (n < 0) {
	    log("pam-mount: %s\n", "could not write data to child");
	    close(pipefd[1]);
	    kill(child, SIGKILL);
	    return 0;
	}
	count += n;
    }
    w4rn("pam_mount: %s\n", "PAM returning");
    close(pipefd[1]);
    waitpid(child, &child_exit, 0);
    /* if child was successful, it will return 0.
       hence return 1 to caller to indicate success. */
    if (WEXITSTATUS(child_exit) == 0)
	return 1;
    else
	return WEXITSTATUS(child_exit);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
				int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
    char *password;
    int x;
    int ret;
    int get_pass = GETPASS_DEFAULT;
    int i;
    debug = DEBUG_DEFAULT;
    w4rn("pam_mount: %s\n", "beginning");
    for (i = 0; i < argc; i++) {
	if (!strcmp("use_first_pass", argv[i])) {
	    get_pass = 0;
	} else if (!strcmp("try_first_pass", argv[i])) {
	    get_pass = 1;
	}
	w4rn("pam_mount: pam_sm_open_session args: %s\n", argv[i]);
    }
    for (x = 0; x < COMMAND_MAX; ++x) {
	command[x] = NULL;
    }
    if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
	log("pam_mount: %s\n", "could not get user");
	return ret;
    }
    if ((ret = pam_get_item(pamh, PAM_AUTHTOK, (const void **) &password))
	|| !password) {
	log("pam_mount: %s\n", "could not get password");
	return ret;
    }
    w4rn("pam_mount: user=%s\n", user);
    /* w4rn("pam_mount: password=%s\n", password); */
    if (strlen(user) > MAX_PAR || strlen(password) > MAX_PAR) {
	log("pam_mount: %s\n", "user or password too long");
	return PAM_SERVICE_ERR;
    }
    volcount = 0;
    w4rn("pam_mount %s\n", "going to readconfig");
    if (!readconfig(user, password, command, &volcount, &data)) {
	log("pam_mount %s\n", "could not get mountable volumes for user");
	return PAM_SERVICE_ERR;
    }
    w4rn("pam_mount: %s\n", "back from readconfig");
    if (volcount <= 0) {
	w4rn("pam_mount: %s\n", "no volumes to mount");
    }
    signal(SIGPIPE, SIG_IGN);
    for (x = 0; x < volcount; ++x) {
	w4rn("pam_mount: %s\n", "FATHER calling child proc");
	if (invoke_child(data + x, command) != 1) {
	    w4rn("pam_mount: %s\n", "FATHER helper process failed");
	    if (get_pass) {
		char *passread;
		/* get the password */
		if (read_password(pamh, "mount password:", &passread) == PAM_SUCCESS) {
		    /* try with the password read */
		    strcpy((data)[x].password, passread);
		    if (invoke_child(data + x, command) != 1) {
		        log("pam_mount: %s\n",
		    	"FATHER helper process failed using get_pass");
		        return PAM_SERVICE_ERR;
		    }
		    _pam_overwrite(passread);
		    _pam_drop(passread);
		} else {
		    log("pam_mount: %s\n", "error trying to read password");
                    return PAM_SERVICE_ERR;
		}
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

    w4rn("pam_mount: %s\n", "received order to close things");
    sleep(1);
    if (volcount <= 0) {
	w4rn("pam_mount: %s\n", "volcount is zero");
	sleep(2);
    }

    signal(SIGPIPE, SIG_IGN);

    for (x = 0; x < volcount; ++x) {
	w4rn("pam_mount: %s\n", "FATHER calling child proc to unmount");
	sleep(1);
	data[x].unmount = 1;
	if (invoke_child(data + x, command) != 1) {
	    log("pam_mount:%s\n",
		"FATHER could not start helper process to umount");
	    return PAM_SERVICE_ERR;
	}
    }

    return PAM_SUCCESS;
}

PAM_EXTERN
    int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
		       const char **argv)
{
    return PAM_SUCCESS;
}
