#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <pam_mount.h>
#include <security/_pam_macros.h>

int debug;
config_t config;

/* ============================ invoke_child () ============================ */
/* PRE:    config is a valid config_t structure
 *         data points to a valid data_t structure (for nth volume)
 *         && config.command[PMHELPER] is the pmhelper command
 * POST:   pmhelper has been executed, received data over pipe, and terminated
 * FN VAL: the exit code returned by pmhelper */
int invoke_child(config_t config, data_t * data)
{
    int pipefd[2];
    int count, n;
    int child;
    int child_exit;
    if (pipe(pipefd)) {
	log("pam_mount: %s\n", "could not create pipe pair");
	return 0;
    }
    if (config.debug) {
	fprintf(stderr,
		"pam_mount: real and effective user ID are %d and %d.\n",
		getuid(), geteuid());
    }
    /* if our CWD is in the home directory, it might not get umounted */
    /* Needed for KDM.  FIXME: Bug in KDM? */
    if (chdir("/"))
	w4rn("pam_mount %s\n", "could not chdir");
    if (config.debug)
	setenv("PAM_MOUNT_DEBUG", "true", 1);
    if (config.mkmountpoint)
	setenv("PAM_MOUNT_MKMOUNTPOINT", "true", 1);
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
	execv(config.command[0][PMHELPER], config.command[PMHELPER] + 1);
	log("pam_mount: %s\n", "CHILD Could not execv helper child");
	log("pam_mount: CHILD command was %s\n",
	    config.command[0][PMHELPER]);
	_exit(1);
    }
    /* Parent */
    w4rn("pam_mount: %s\n", "sending data to pmhelper");
    close(pipefd[0]);
    count = 0;
    while (count < sizeof(data_t)) {
	w4rn("pam_mount: %s\n", "inside write loop");
	n = write(pipefd[1],
		  ((char *) data) + count, sizeof(data_t) - count);
	if (n < 0) {
	    log("pam-mount: %s\n", "could not write data to child");
	    close(pipefd[1]);
	    kill(child, SIGKILL);
	    return 0;
	}
	count += n;
    }
    w4rn("pam_mount: %s\n", "waiting for pmhelper to exit");
    close(pipefd[1]);
    waitpid(child, &child_exit, 0);
    /* if child was successful, it will return 0.
       hence return 1 to caller to indicate success. */
    if (WEXITSTATUS(child_exit) == 0)
	return 1;
    else
	return WEXITSTATUS(child_exit);
}

/* ============================ pam_sm_open_session () ===================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN int pam_sm_open_session(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* ============================ pam_sm_chauthtok () ======================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
				int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

/* ============================ pam_sm_authenticate () ===================== */
/* PRE:    this function is called by PAM
 * POST:   user's directories are mounted if pam_mount.conf says they should
 *         be or an error is logged
 * FN VAL: PAM error code on error or PAM_SUCCESS */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
    int x;
    int ret;
    int get_pass = GETPASS_DEFAULT;
    int i;
    
    w4rn("pam_mount: %s\n", "beginning");
    for (i = 0; i < argc; i++) {
	if (!strcmp("use_first_pass", argv[i])) {
	    get_pass = 0;
	} else if (!strcmp("try_first_pass", argv[i])) {
	    get_pass = 1;
	}
	w4rn("pam_mount: pam_sm_open_session args: %s\n", argv[i]);
    }
    if ((ret = pam_get_user(pamh, &config.user, NULL)) != PAM_SUCCESS) {
	log("pam_mount: %s\n", "could not get user");
	return ret;
    }
    if ((ret =
	 pam_get_item(pamh, PAM_AUTHTOK,
		      (const void **) &config.system_password))
	|| !config.system_password) {
	log("pam_mount: %s\n", "could not get password");
	return ret;
    }
    w4rn("pam_mount: user is %s\n", config.user);
    /* w4rn("pam_mount: password=%s\n", config.system_password); */
    if (strlen(config.user) > MAX_PAR
	|| strlen(config.system_password) > MAX_PAR) {
	log("pam_mount: %s\n", "user or password too long");
	return PAM_SUCCESS;
    }
    initconfig(&config);
    w4rn("pam_mount: %s\n", "going to readconfig global");
    if (!readconfig(config.user, CONFIGFILE, 1, &config))
	return PAM_SUCCESS;
    w4rn("pam_mount: %s\n", "back from global readconfig");
    if (exists(config.luserconf) && owns(config.user, config.luserconf)) {
	w4rn("pam_mount: %s\n", "going to readconfig user");
	if (!readconfig(config.user, config.luserconf, 0, &config))
	    return PAM_SUCCESS;
	w4rn("pam_mount: %s\n", "back from user readconfig");
    } else
	w4rn("pam_mount: %s does not exist\n", config.luserconf);
    if (config.volcount <= 0) {
	w4rn("pam_mount: %s\n", "no volumes to mount");
    }
    expandconfig(&config);
    signal(SIGPIPE, SIG_IGN);
    for (x = 0; x < config.volcount; x++) {
	w4rn("pam_mount: %s\n", "executing pmhelper");
	strcpy(config.data[x].lsof, config.command[0][LSOF]);
	config.data[x].argc = 0;
	for (i = 0; config.command[i][config.data[x].type]; i++) {
	    strcpy(config.data[x].argv[i],
		   config.command[i][config.data[x].type]);
	    config.data[x].argc++;
	}
	*config.data[x].argv[i] = 0x00;
	if (invoke_child(config, config.data + x) != 1) {
	    w4rn("pam_mount: %s\n", "FATHER helper process failed");
	    if (get_pass) {
		char *passread;
		/* get the password */
		if (read_password(pamh, "mount password:", &passread) ==
		    PAM_SUCCESS) {
		    /* try with the password read */
		    strcpy(config.data[x].password, passread);
		    if (invoke_child(config, config.data + x) != 1) {
			log("pam_mount: %s\n",
			    "FATHER helper process failed using get_pass");
			return PAM_SUCCESS;
		    }
		    _pam_overwrite(passread);
		    _pam_drop(passread);
		} else {
		    log("pam_mount: %s\n",
			"error trying to read password");
		    return PAM_SUCCESS;
		}
	    }
	    return PAM_SUCCESS;
	}
    }
    return PAM_SUCCESS;
}

/* ============================ pam_sm_close_session () ==================== */
/* PRE:    this function is called by PAM
 * POST:   user's directories are unmounted if pam_mount.conf says they should
 *         be or an error is logged
 * FN VAL: PAM error code on error or PAM_SUCCESS */
PAM_EXTERN
    int pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
			     const char **argv)
{
    int x;

    w4rn("pam_mount: %s\n", "received order to close things");
    sleep(1);
    if (config.volcount <= 0) {
	w4rn("pam_mount: %s\n", "volcount is zero");
	sleep(2);
    }

    signal(SIGPIPE, SIG_IGN);

    for (x = 0; x < config.volcount; ++x) {
	w4rn("pam_mount: %s\n", "FATHER calling child proc to unmount");
	sleep(1);
	config.data[x].unmount = 1;
	strcpy(config.data[x].ucommand, config.command[0][UMOUNT]);
	if (invoke_child(config, config.data + x) != 1) {
	    log("pam_mount:%s\n",
		"FATHER could not start helper process to umount");
	    return PAM_SUCCESS;
	}
    }

    return PAM_SUCCESS;
}

/* ============================ pam_sm_setcred () ========================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN
    int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
		       const char **argv)
{
    return PAM_SUCCESS;
}
