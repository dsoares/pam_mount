#include <errno.h>
#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <pam_mount.h>
#include <security/_pam_macros.h>

int debug;
config_t config;

/* ============================ number_safe () ============================= */
int number_safe(char *n)
/* PRE:    n points to a valid string != NULL
 * FN VAL: if error 0 else 1, errors are logged 
 * NOTE:   this is needed because users own /var/run/pam_mount/<user> and
 *         they could try something sneaky */
{
    char *ptr = n;
    if (!*n || *n == '\n') {
	log("pam_mount: %s\n", "count string has no length");
	return 0;
    }
    do {
        /* "123\n" okay, "1a23" bad, "1\n23" bad, "123" okay */
	if (!(isdigit(*ptr))) {
	    log("pam_mount: %s\n", "count contains non-digits");
	    return 0;
	}
	ptr++;
    }
    while (!(*ptr == '\n' && !*(ptr + 1)) && *ptr);
    if (strlen(n) > (sizeof(int) * 8)) {
	log("pam_mount: %s\n", "count string too long (number too big)");
	return 0;
    }
    return 1;
}

/* ============================ modify_pm_count () ========================= */
/* PRE:    user points to a valid string != NULL
 * POST:   amount is added to /var/run/pam_mount/<user>'s value; if value == 0,
 *         then file is removed.
 * FN VAL: new value else -1 on error, errors are logged
 * NOTE:   code is modified version of pam_console.c's use_count */
int modify_pm_count(const char *user, int amount)
{
    char filename[PATH_MAX + 1];
    int tries = 0;
    int fd, err, val;
    struct stat st;
    struct flock lockinfo;
    char *buf = NULL;
    struct passwd *passwd_ent;
    if (!(passwd_ent = getpwnam(user))) {
	w4rn("pam_mount: could not resolve uid for %s\n", user);
	err = -1;
	goto return_error;
    }
    if (stat("/var/run/pam_mount", &st) == -1) {
	w4rn("pam_mount: %s\n", "creating /var/run/pam_mount");
	if (mkdir("/var/run/pam_mount", 0000) == -1) {
	    w4rn("pam_mount: %s\n",
		 "unable to create /var/run/pam_mount\n");
	    err = -1;
	    goto return_error;
	}
	if (chown("/var/run/pam_mount", 0, 0) == -1) {
	    w4rn("pam_mount: unable to chown %s\n", "/var/run/pam_mount");
	    err = -1;
	    goto return_error;
	}
	/* 0755: su creates file group owned by user and the releases 
	 * root perms.  User needs to be able to access file on logout. */
	/* FIXME: user can modify /var/.../<user> at will; security problem? */
	if (chmod("/var/run/pam_mount", 0755) == -1) {
	    w4rn("pam_mount: unable to chmod %s\n", "/var/run/pam_mount");
	    err = -1;
	    goto return_error;
	}
    }
    snprintf(filename, PATH_MAX + 1, "/var/run/pam_mount/%s", user);
  top:
    tries++;
    if (stat(filename, &st) == -1) {
	if ((fd = open(filename, O_RDWR | O_CREAT, 0000)) == -1) {
	    w4rn("pam_mount: unable to open %s\n", filename);
	    err = -1;
	    goto return_error;
	}
	/* su creates file group owned by user and the releases 
	 * root perms.  User needs to be able to access file on logout. */
	if (fchown(fd, passwd_ent->pw_uid, passwd_ent->pw_uid) == -1) {
	    w4rn("pam_mount: unable to chown %s\n", filename);
	    err = -1;
	    goto return_error;
	}
	if (fchmod(fd, 0600) == -1) {
	    w4rn("pam_mount: unable to chmod %s\n", filename);
	    err = -1;
	    goto return_error;
	}
	if (write(fd, "0", 1) == -1) {
	    w4rn("pam_mount: write error on %s\n", filename);
	    err = -1;
	    goto return_error;
	}
	if (lseek(fd, SEEK_SET, 0) == -1) {
	    w4rn("pam_mount: seek error in %s\n", filename);
	    err = -1;
	    goto return_error;
	}
    } else
	fd = open(filename, O_RDWR);
    if (stat(filename, &st) == -1) {
	w4rn("pam_mount: unable to stat %s\n", filename);
	err = -1;
	goto return_error;
    }
    if (fd < 0) {
	w4rn("pam_mount: could not open count file %s\n", filename);
	perror("foo");
	return 0;
    }
    lockinfo.l_type = F_WRLCK;
    lockinfo.l_whence = SEEK_SET;
    lockinfo.l_start = 0;
    lockinfo.l_len = 0;
    alarm(20);
    err = fcntl(fd, F_SETLKW, &lockinfo);
    alarm(0);
    if (err == EAGAIN) {
	/* if someone has locked the file and not written to it in
	 * at least 20 seconds, we assume they either forgot to unlock
	 * it or are catatonic -- chances are slim that they are in
	 * the middle of a read-write cycle and I don't want to make
	 * us lock users out.  Perhaps I should just return PAM_SUCCESS
	 * instead and log the event?  Kill the process holding the
	 * lock?  Options abound...  For now, we ignore it.
	 */
	fcntl(fd, F_GETLK, &lockinfo);
	/* now lockinfo.l_pid == 0 implies that the lock was released
	 * by the other process between returning from the 20 second
	 * wait and calling fcntl again, not likely to ever happen, and
	 * not a problem other than cosmetics even if it does.
	 */
	w4rn("pam_mount: ignoring stale lock on file %s\n", filename);
    }
    /* it is possible at this point that the file has been removed
     * by a previous login; if this happens, we need to start over.
     * Unfortunately, the only way to do this without potential stack
     * trashing is a goto.
     */
    if (access(filename, F_OK) < 0) {
	if (tries < 10) {
	    w4rn("pam_mount: could not access %s, trying again\n",
		 filename);
	    sleep(1);
	    close(fd);
	    goto top;
	} else {
	    w4rn("pam_mount: %s\n", "tried ten times, quitting");
	    err = -1;
	    goto return_error;
	}
    }

    if (!(buf = malloc(st.st_size + 2))) {	/* size will never grow by more than one */
	w4rn("pam_mount: %s\n", "malloc failed");
	err = -1;
	goto return_error;
    }
    if (st.st_size) {
	if (read(fd, buf, st.st_size) == -1) {
	    w4rn("pam_mount: read error on %s\n", filename);
	    err = -1;
	    goto return_error;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
	    w4rn("pam_mount: lseek error on %s\n", filename);
	    err = -1;
	    goto return_error;
	}
	buf[st.st_size] = '\0';
	if (!number_safe(buf)) {
	    log("pam_mount: %s\n", "session count is corrupt");
	    err = -1;
	    goto return_error;
	}
	val = atoi(buf);
    } else {
	val = 0;
    }
    if (amount) {		/* amount == 0 implies query */
	val += amount;
	if (val <= 0) {
	    if (unlink(filename)) {
		w4rn("pam_mount: unlink error on %s\n", filename);
	    }
	}
	sprintf(buf, "%d", val);
	if (write(fd, buf, strlen(buf)) == -1) {
	    w4rn("pam_mount: write error on %s\n", filename);
	    err = -1;
	    goto return_error;
	}
    }
    err = val;
  return_error:
    close(fd);
    if (buf)
	free(buf);
    return err;
}

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
    modify_pm_count(config.user, 1);
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
    if (config.volcount <= 0) {
	w4rn("pam_mount: %s\n", "volcount is zero");
    }

    signal(SIGPIPE, SIG_IGN);

    if (modify_pm_count(config.user, -1) <= 0)
	for (x = 0; x < config.volcount; ++x) {
	    w4rn("pam_mount: %s\n",
		 "FATHER calling child proc to unmount");
	    config.data[x].unmount = 1;
	    strcpy(config.data[x].ucommand, config.command[0][UMOUNT]);
	    if (invoke_child(config, config.data + x) != 1) {
		log("pam_mount:%s\n",
		    "FATHER could not start helper process to umount");
		return PAM_SUCCESS;
	    }
    } else
	w4rn("pam_mount: %s seems to have other remaining open sessions\n",
	     config.user);
    freeconfig(config);
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
