/*
 *	pam_mount
 *	Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
 *	Copyright © Jan Engelhardt, 2005 - 2008
 *	Copyright © Bastian Kleineidam, 2005
 *
 *	This file is part of pam_mount; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public License
 *	as published by the Free Software Foundation; either version 2.1
 *	of the License, or (at your option) any later version.
 */
#define PAM_SM_SESSION 1
#define PAM_SM_PASSWORD 1

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libHX.h>
#include "compiler.h"
#include "misc.h"
#include "mount.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"
#include "spawn.h"
#include "xstdlib.h"

#ifndef PAM_EXTERN
#	define PAM_EXTERN
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#	define CONFIGFILE "/etc/pam_mount.conf.xml"
#else
#	define CONFIGFILE "/etc/security/pam_mount.conf.xml"
#endif

/* Functions */
static void clean_config(pam_handle_t *, void *, int);
static int converse(pam_handle_t *, int, const struct pam_message **,
	struct pam_response **);
static int modify_pm_count(struct config *, char *, char *);
static void parse_pam_args(int, const char **);
static int read_password(pam_handle_t *, const char *, char **);

/* Variables */
static const char *envpath_saved;
unsigned int Debug = true;
struct config Config = {};
struct pam_args Args = {};

//-----------------------------------------------------------------------------
/**
 * parse_pam_args -
 * @argv:	NULL-terminated argument vector
 * @argc:	number of elements in @argc
 *
 * Global @Args is initialized, based on @argv.
 */
static void parse_pam_args(int argc, const char **argv)
{
	int i;

	assert(argc >= 0);
	for (i = 0; i < argc; i++)
		assert(argv[i] != NULL);

	/* first, set default values */
	Args.auth_type  = GET_PASS;

	for (i = 0; i < argc; ++i) {
		if (strcmp("use_first_pass", argv[i]) == 0)
			Args.auth_type = USE_FIRST_PASS;
		else if (strcmp("try_first_pass", argv[i]) == 0)
			Args.auth_type = TRY_FIRST_PASS;
		else if (strcmp("soft_try_pass", argv[i]) == 0)
			Args.auth_type = SOFT_TRY_PASS;
		else if (strcmp("nullok", argv[i]) == 0)
			Args.nullok = true;
		else if (strcmp("debug", argv[i]) == 0)
			Debug = true;
		else
			w4rn("bad pam_mount option \"%s\"\n", argv[i]);
	}
}

/**
 * clean_config -
 * @pamh:	PAM handle
 * @data:	custom data pointer
 * @err:
 *
 * Free data from a struct config variable.
 * Note: This is registered as a PAM callback function and is called directly.
 */
static void clean_config(pam_handle_t *pamh, void *data, int err)
{
	w4rn("Clean global config (%d)\n", err);
	freeconfig(data);
}

/**
 * clean_system_authtok -
 * @pamh:	PAM handle
 * @data:	custom data pointer
 * @err:
 *
 * Zero and free @data if it is not %NULL.
 * Note: This is registered as a PAM callback function and is called directly.
 *
 * FIXME: Not binary-password safe.
 */
static void clean_system_authtok(pam_handle_t *pamh, void *data, int errcode)
{
	w4rn("clean system authtok=%p (%d)\n", data, errcode);

	if (data != NULL) {
		unsigned int len = strlen(data) + 1;
		memset(data, 0, len);
		munlock(data, len);
		free(data);
	}
}

/**
 * converse -
 * @pamh:	PAM handle
 * @nargs:	number of messages
 * @message:	PAM message array
 * @resp:	user response array
 *
 * Note: Adapted from pam_unix/support.c.
 */
static int converse(pam_handle_t *pamh, int nargs,
    const struct pam_message **message, struct pam_response **resp)
{
	int retval;
	struct pam_conv *conv;

	assert(pamh != NULL);
	assert(nargs >= 0);
	assert(resp != NULL);

	*resp = NULL;
	retval = pam_get_item(pamh, PAM_CONV, static_cast(const void **,
	         static_cast(void *, &conv)));

	if (retval == PAM_SUCCESS) {
		retval = conv->conv(nargs, message, resp, conv->appdata_ptr);
		if (retval != PAM_SUCCESS)
			l0g("conv->conv(...): %s\n", pam_strerror(pamh, retval));
	} else {
		l0g("pam_get_item: %s\n", pam_strerror(pamh, retval));
	}

	if (resp == NULL || *resp == NULL || (*resp)->resp == NULL)
		retval = PAM_AUTH_ERR;

	assert(retval != PAM_SUCCESS || (resp != NULL && *resp != NULL &&
	       (*resp)->resp != NULL));
	return retval; /* propagate error status */
}

/**
 * read_password -
 * @pamh:	PAM handle
 * @prompt:	a prompt message
 * @pass:	space for entered password
 *
 * Returns PAM error code or %PAM_SUCCESS.
 * Note: Adapted from pam_unix/support.c:_unix_read_password().
 */
static int read_password(pam_handle_t *pamh, const char *prompt, char **pass)
{
	int retval;
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;

	assert(pamh != NULL);
	assert(pass != NULL);

	w4rn("enter read_password\n");
	*pass = NULL;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg       = (prompt == NULL) ? "Password: " : prompt;
	retval  = converse(pamh, 1, &pmsg, &resp);
	if (retval == PAM_SUCCESS)
		*pass = xstrdup(resp->resp);

	assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));
	return retval;
}

static int common_init(pam_handle_t *pamh, int argc, const char **argv)
{
	const char *pam_user;
	char buf[8];
	int ret;

	initconfig(&Config);
	parse_pam_args(argc, argv);
	/*
	 * call pam_get_user again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	ret = pam_get_user(pamh, &pam_user, NULL);
	if (ret != PAM_SUCCESS) {
		l0g("could not get user");
		/*
		 * do NOT return %PAM_SERVICE_ERR or root will not be able to
		 * su to other users.
		 */
		return PAM_SUCCESS;
	}
	/*
	 * FIXME: free me! the dup is requried because result of pam_get_user()
	 * disappears (valgrind)
	 */
	Config.user = relookup_user(pam_user);
	if (strlen(Config.user) > MAX_PAR) {
		l0g("username %s is too long\n", Config.user);
		return PAM_SERVICE_ERR;
	}

	if (!readconfig(CONFIGFILE, true, &Config))
		return PAM_SERVICE_ERR;

	snprintf(buf, sizeof(buf), "%u", Debug);
	setenv("_PMT_DEBUG_LEVEL", buf, true);
	return -1;
}

/**
 * pam_sm_authenticate -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * Called by the PAM layer. The user's system password is added to PAM's
 * global module data. This is because pam_sm_open_session() does not allow
 *  access to the user's password. Returns the PAM error code or %PAM_SUCCESS.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	int ret = PAM_SUCCESS;
	char *authtok = NULL;
	const void *tmp = NULL;

	assert(pamh != NULL);

	if ((ret = common_init(pamh, argc, argv)) != -1)
		return ret;

	if (Args.auth_type != GET_PASS) { /* get password from PAM system */
		char *ptr = NULL;
		ret = pam_get_item(pamh, PAM_AUTHTOK, static_cast(const void **,
		      static_cast(void *, &ptr)));
		if (ret != PAM_SUCCESS || ptr == NULL) {
			if (ret == PAM_SUCCESS && ptr == NULL &&
			    !Args.nullok)
				ret = PAM_AUTHINFO_UNAVAIL;
			l0g("could not get password from PAM system\n");
			if (Args.auth_type == USE_FIRST_PASS)
				goto out;
		} else {
			authtok = xstrdup(ptr);
		}
	}
	if (authtok == NULL) {
		if (Args.auth_type == SOFT_TRY_PASS) {
			ret = PAM_AUTHINFO_UNAVAIL;
			goto out;
		}
		/* get password directly */
		ret = read_password(pamh, Config.msg_authpw, &authtok);
		if (ret != PAM_SUCCESS) {
			l0g("error trying to read password\n");
			goto out;
		}
		/* pam_set_item() copies to PAM-internal memory */
		ret = pam_set_item(pamh, PAM_AUTHTOK, authtok);
		if (ret != PAM_SUCCESS) {
			l0g("error trying to export password\n");
			goto out;
		}
	}
	if (strlen(authtok) > MAX_PAR) {
		l0g("password too long\n");
		ret = PAM_AUTH_ERR;
		goto out;
	}
	w4rn("saving authtok for session code (authtok=%p)\n", authtok);
	ret = pam_set_data(pamh, "pam_mount_system_authtok", authtok,
	                   clean_system_authtok);
	if (ret != PAM_SUCCESS) {
		l0g("error trying to save authtok for session code\n");
		goto out;
	}
	if (mlock(authtok, strlen(authtok) + 1) < 0)
		w4rn("mlock authtok: %s\n", strerror(errno));
	assert(ret != PAM_SUCCESS ||
	       pam_get_data(pamh, "pam_mount_system_authtok", &tmp) ==
	       PAM_SUCCESS);
	assert(ret != PAM_SUCCESS || tmp != NULL);
 out:
	return ret;
}

/**
 * On login, $PATH is correctly set to ENV_ROOTPATH (from /etc/login.defs),
 * while on logout, it happens to be ENV_PATH only. This is problematic,
 * since some programs are in /sbin and /usr/sbin which is
 * often not contained in ENV_PATH.
 *
 * In short: Another workaround for coreutils.
 */
static void envpath_init(const char *new_path)
{
	envpath_saved = getenv("PATH");
	setenv("PATH", new_path, true);
}

static void envpath_restore(void)
{
	if (envpath_saved == NULL)
		unsetenv("PATH");
	else
		setenv("PATH", envpath_saved, true);
}

/**
 * modify_pm_count -
 * @config:
 * @user:
 * @operation:	string specifying numerical increment
 *
 * Calls out to the `pmvarrun` helper utility to adjust the mount reference
 * count in /var/run/pam_mount/@user for the specified user.
 * Returns the new reference count value on success, or -1 on error.
 *
 * Note: Modified version of pam_console.c:use_count()
 */
static int modify_pm_count(struct config *config, char *user,
    char *operation)
{
	FILE *fp;
	struct HXbtree *vinfo;
	int _argc = 0, child_exit, cstdout = -1, fnval = -1;
	const char *_argv[MAX_PAR + 1];
	pid_t pid;
	struct sigaction sact, oldsact;
	unsigned int i;

	assert(config_valid(config));
	assert(user != NULL);
	assert(operation != NULL);

	/* avoid bomb on command exiting before count read */
	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = SIG_DFL;
	sigemptyset(&sact.sa_mask);
	if (sigaction(SIGPIPE, &sact, &oldsact) < 0) {
		fnval = -1;
		goto nosigactout;
	}
	if ((vinfo = HXformat_init()) == NULL) {
		fnval = -1;
		goto out;
	}
	format_add(vinfo, "USER", user);
	format_add(vinfo, "OPERATION", operation);
	misc_add_ntdom(vinfo, user);

	for (i = 0; config->command[CMD_PMVARRUN][i] != NULL; ++i)
		add_to_argv(_argv, &_argc,
		            config->command[CMD_PMVARRUN][i], vinfo);
	HXformat_free(vinfo);
	log_argv(_argv);

	if (!spawn_start(_argv, &pid, NULL, &cstdout, NULL, set_myuid, NULL)) {
		l0g("error executing pmvarrun\n");
		fnval = -1;
		goto out;
	}
	if ((fp = fdopen(cstdout, "r")) == NULL) {
		spawn_restore_sigchld();
		w4rn("error opening file: %s\n", strerror(errno));
		fnval = -1;
		goto out;
	}
	if (fscanf(fp, "%d", &fnval) != 1) {
		spawn_restore_sigchld();
		w4rn("error reading login count from pmvarrun\n");
		fnval = -1;
		goto out;
	}
	if (waitpid(pid, &child_exit, 0) < 0) {
		spawn_restore_sigchld();
		l0g("error waiting for child: %s\n", strerror(errno));
		fnval = -1;
		goto out;
	}
	spawn_restore_sigchld();
	if (WEXITSTATUS(child_exit)) {
		l0g("pmvarrun failed\n");
		fnval = -1;
		goto out;
	}
	w4rn("pmvarrun says login count is %d\n", fnval);
 out:
	sigaction(SIGPIPE, &oldsact, NULL);
 nosigactout:

	assert(config_valid(config));
	return fnval;
}

/**
 * pam_sm_open_session -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * Entrypoint from the PAM layer. Starts the wheels and eventually mounts the
 * user's directories according to pam_mount.conf.xml. Returns the PAM error
 * code or %PAM_SUCCESS.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	struct vol *vol;
	int ret;
	unsigned int krb5_set;
	char *system_authtok;
	const void *tmp;
	int getval;

	assert(pamh != NULL);

	if ((ret = common_init(pamh, argc, argv)) != -1)
		return ret;

	w4rn("Entered pam_mount session stage\n");

	/*
	 * Get the Kerberos CCNAME so we can make it available to the
	 * mount command later on.
	 */
	krb5_set = getenv("KRB5CCNAME") != NULL;
	if (setenv("KRB5CCNAME", pam_getenv(pamh, "KRB5CCNAME"), 1) < 0)
		l0g("KRB5CCNAME setenv failed\n");

	/* Store initialized config as PAM data */
	getval = pam_get_data(pamh, "pam_mount_config", &tmp);
	if (getval == PAM_NO_MODULE_DATA) {
		ret = pam_set_data(pamh, "pam_mount_config",
		      &Config, clean_config);
		if (ret != PAM_SUCCESS) {
			l0g("error trying to save config structure\n");
			goto out;
		}
	}

	w4rn("back from global readconfig\n");
	if (strlen(Config.luserconf) == 0)
		w4rn("per-user configurations not allowed by pam_mount.conf.xml\n");
	else if (exists(Config.luserconf) && owns(Config.user, Config.luserconf)) {
		w4rn("going to readconfig user\n");
		if (!readconfig(Config.luserconf, false, &Config)) {
			ret = PAM_SERVICE_ERR;
			goto out;
		}
		w4rn("back from user readconfig\n");
	} else
		w4rn("%s does not exist or is not owned by user\n",
		     Config.luserconf);
	if (Config.volume_list.items == 0) {
		w4rn("no volumes to mount\n");
		ret = PAM_SUCCESS;
		goto out;
	}
	if (!expandconfig(&Config)) {
		l0g("error expanding configuration\n");
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	ret = pam_get_data(pamh, "pam_mount_system_authtok",
	      static_cast(const void **, static_cast(void *, &system_authtok)));
	if (ret != PAM_SUCCESS) {
		if (Args.auth_type == SOFT_TRY_PASS) {
			ret = PAM_AUTHINFO_UNAVAIL;
			goto out;
		}
		l0g("error trying to retrieve authtok from auth code\n");
		ret = read_password(pamh, Config.msg_sessionpw, &system_authtok);
		if (ret != PAM_SUCCESS) {
			l0g("error trying to read password\n");
			goto out;
		}
	}

	misc_dump_id("Session open");

	envpath_init(Config.path);
	HXlist_for_each_entry(vol, &Config.volume_list, list) {
		/*
		 * luserconf_volume_record_sane() is called here so that a user
		 * can nest loopback images. otherwise ownership tests will
		 * fail if parent loopback image not yet mounted. 
		 * volume_record_sane() is here to be consistent.
		 */
		if (!volume_record_sane(&Config, vol))
			continue;
		if (!vol->globalconf &&
		    !luserconf_volume_record_sane(&Config, vol))
			continue;
		w4rn("about to perform mount operations\n");

		if (!mount_op(do_mount, &Config, vol, system_authtok)) {
			l0g("mount of %s failed\n", vol->volume);
			ret = PAM_SERVICE_ERR;
		}
	}
	memset(system_authtok, 0, strlen(system_authtok));
	if (krb5_set)
		unsetenv("KRB5CCNAME");
	modify_pm_count(&Config, Config.user, "1");
	envpath_restore();
 out:
	w4rn("done opening session (ret=%d)\n", ret);
	return ret;
}

/**
 * pam_sm_chauthtok -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * This is a placeholder function so PAM does not get mad.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/**
 * pam_sm_close_session -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * Entrypoint from the PAM layer. Stops all wheels and eventually unmounts the
 * user's directories. Returns the PAM error code or %PAM_SUCCESS.
 *
 * FIXME: This function currently always returns %PAM_SUCCESS. Should it
 * return soemthing else when errors occur and all unmounts have been
 * attempted?
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_close_session(pam_handle_t *pamh,
    int flags, int argc, const char **argv)
{
	int ret = PAM_SUCCESS;
	struct vol *vol;
	const char *pam_user = NULL;

	assert(pamh != NULL);

	w4rn("received order to close things\n");
	if (Config.volume_list.items == 0) {
		w4rn("No volumes to umount\n");
		goto out;
	}

	misc_dump_id("Session close");
	/*
	 * call pam_get_user() again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	ret = pam_get_user(pamh, &pam_user, NULL);
	if (ret != PAM_SUCCESS) {
		l0g("could not get user\n");
		/*
		 * do NOT return %PAM_SERVICE_ERR or root will not be able to
		 * su to other users.
		 */
		goto out;
	}
	/*
	 * FIXME: free me! the dup is requried because result of pam_get_user
	 * disappears (valgrind)
	 */
	Config.user = relookup_user(pam_user);
	/* if our CWD is in the home directory, it might not get umounted */
	if (chdir("/") != 0)
		l0g("could not chdir\n");

	envpath_init(Config.path);
	if (modify_pm_count(&Config, Config.user, "-1") <= 0) {
		HXlist_for_each_entry_rev(vol, &Config.volume_list, list) {
			w4rn("going to unmount\n");
			if (!mount_op(do_unmount, &Config, vol, NULL))
				l0g("unmount of %s failed\n",
				    vol->volume);
		}
	} else {
		w4rn("%s seems to have other remaining open sessions\n",
		     Config.user);
	}
	envpath_restore();
 out:
	/*
	 * Note that PMConfig is automatically freed later in clean_config()
	 */
	w4rn("pam_mount execution complete\n");
	return ret;
}

/**
 * pam_sm_setcred -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * This is a placeholder function so PAM does not get mad.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/**
 * pam_sm_acct_mgmt -
 * @pamh:	PAM handle
 * @flags:	PAM flags
 * @argc:	number of elements in @argv
 * @argv:	NULL-terminated argument vector
 *
 * This is a placeholder function so PAM does not get mad.
 */
PAM_EXTERN EXPORT_SYMBOL int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char **argv)
{
	return PAM_IGNORE;
}

#ifdef PAM_STATIC
/* static module data */

EXPORT_SYMBOL struct pam_module _pam_mount_modstruct = {
	.name                 = "pam_mount",
	.pam_sm_authenticate  = pam_sm_authenticate,
	.pam_sm_setcred       = pam_sm_setcred,
	.pam_sm_acct_mgmt     = pam_sm_acct_mgmt,
	.pam_sm_open_sesion   = pam_sm_open_session,
	.pam_sm_close_session = pam_sm_close_session,
	.pam_sm_chauthtok     = pam_sm_chauthtok,
};

#endif
