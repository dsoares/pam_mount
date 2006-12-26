/*=============================================================================
pam_mount.c
  Copyright (C) Elvis Pfützenreuter <epx@conectiva.com>, 2000
  Copyright © Jan Engelhardt <jengelh [at] gmx de>, 2005 - 2006
  Copyright © Bastian Kleineidam <calvin [at] debian org>, 2005

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, write to:
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
  Boston, MA  02110-1301  USA

  -- For details, see the file named "LICENSE.LGPL2"
=============================================================================*/
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "compiler.h"
#include "fmt_ptrn.h"
#include "misc.h"
#include "mount.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"
#include "spawn.h"
#include "xstdlib.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#    define CONFIGFILE "/etc/pam_mount.conf.xml"
#else
#    define CONFIGFILE "/etc/security/pam_mount.conf.xml"
#endif

// Functions
static void clean_config(pam_handle_t *, void *, int);
static void clean_system_authtok(pam_handle_t *, void *, int);
static int converse(pam_handle_t *, int, const struct pam_message **,
    struct pam_response **);
static int modify_pm_count(struct config *, char *, char *);
static void parse_pam_args(int, const char **);
static int read_password(pam_handle_t *, const char *, char **);

// Variables
int Debug = 0;
struct config Config = {};
struct pam_args Args = {};

//-----------------------------------------------------------------------------
/*  parse_pam_args
    @argv:      NULL-terminated argument vector
    @argc:      number of elements in @argc

    Global @Args is initialized, based on @argv.
*/
static void parse_pam_args(int argc, const char **argv) {
	int i;

	assert(argc >= 0);
	for (i = 0; i < argc; i++)
		assert(argv[i] != NULL);

	/* first, set default values */
	Args.auth_type = GET_PASS;
	for (i = 0; i < argc; i++) {
		w4rn(PMPREFIX "pam_sm_open_session args: %s\n", argv[i]);
		if(strcmp("use_first_pass", argv[i]) == 0)
			Args.auth_type = USE_FIRST_PASS;
		else if(strcmp("try_first_pass", argv[i]) == 0)
			Args.auth_type = TRY_FIRST_PASS;
		else
			w4rn(PMPREFIX "bad pam_mount option\n");
	}
        return;
}


/*  clean_config
    @pamh:      PAM handle
    @data:      custom data pointer
    @err:

    Free data from a struct config variable.
    Note: This is registered as a PAM callback function and is called directly.
*/
static void clean_config(pam_handle_t *pamh, void *data, int err) {
    w4rn(PMPREFIX "Clean global config (%d)\n", err);
    freeconfig(data);
    return;
}


/*  clean_system_authtok
    @pamh:      PAM handle
    @data:      custom data pointer
    @err:

    Zero and free @data if it is not %NULL.
    Note: This is registered as a PAM callback function and is called directly.

    FIXME: Not binary-password safe.
*/
static void clean_system_authtok(pam_handle_t *pamh, void *data, int errcode) {
	w4rn(PMPREFIX "clean system authtok (%d)\n", errcode);
/*
	if (data) {
		memset(data, 0, strlen(data));
		free(data);
	}
*/
    return;
}


/*  converse
    @pamh:      PAM handle
    @nargs:     number of messages
    @message:   PAM message array
    @resp:      user response array

    Note: Adapted from pam_unix/support.c.
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

        if(retval == PAM_SUCCESS) {
            retval = conv->conv(nargs, message, resp, conv->appdata_ptr);
            if(retval != PAM_SUCCESS)
                l0g(PMPREFIX "conv->conv(...): %s\n", pam_strerror(pamh, retval));
        } else {
            l0g(PMPREFIX "pam_get_item: %s\n", pam_strerror(pamh, retval));
        }

        if(resp == NULL || *resp == NULL || (*resp)->resp == NULL)
		retval = PAM_AUTH_ERR;

	assert(retval != PAM_SUCCESS
	       || (resp != NULL && *resp != NULL
		   && (*resp)->resp != NULL));

	return retval;		/* propagate error status */
}


/*  read_password
    @pamh:      PAM handle
    @prompt:    a prompt message
    @pass:      space for entered password

    Returns PAM error code or %PAM_SUCCESS.
    Note: Adapted from pam_unix/support.c:_unix_read_password().
*/
static int read_password(pam_handle_t *pamh, const char *prompt, char **pass) {
	int retval;
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;

	assert(pamh != NULL);
	assert(prompt != NULL);
	assert(pass != NULL);

	w4rn(PMPREFIX "enter read_password\n");
	*pass = NULL;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt;
	retval = converse(pamh, 1, &pmsg, &resp);
	if (retval == PAM_SUCCESS)
		*pass = xstrdup(resp->resp);

	assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));

	return retval;
}


/*  pam_sm_authenticat
    @pamh:      PAM handle
    @flags:     PAM flags
    @argc:      number of elements in @argv
    @argv:      NULL-terminated argument vector

    Called by the PAM layer. The user's system password is added to PAM's
    global module data. This is because pam_sm_open_session() does not allow
    access to the user's password. Returns the PAM error code or %PAM_SUCCESS.
*/
PAM_EXTERN EXPORT_SYMBOL int pam_sm_authenticate(pam_handle_t *pamh, int flags,
 int argc, const char **argv)
{
	int ret = PAM_SUCCESS;
	char *authtok = NULL;
	const void *tmp = NULL;
	const char *pam_user = NULL;

	assert(pamh != NULL);

	/* FIXME: this is called again in pam_sm_open_session.  this is because
         * pam_sm_authenticate is never called when root su's to another user.
	 */
	initconfig(&Config);
	parse_pam_args(argc, argv);
	/* needed because gdm does not prompt for username as login does: */
	if ((ret = pam_get_user(pamh, &pam_user, NULL)) != PAM_SUCCESS) {
		l0g(PMPREFIX "could not get user\n");
		/* do NOT return PAM_SERVICE_ERR or root will not be able
		 * to su to other users */
		goto _return;
	}
        /* FIXME: free me! the dup is required because result of pam_get_user
        disappears (valgrind) */
	Config.user = relookup_user(pam_user);
	if(Args.auth_type != GET_PASS) {	/* get password from PAM system */
		char *ptr = NULL;
                ret = pam_get_item(pamh, PAM_AUTHTOK, static_cast(const void **,
                      static_cast(void *, &ptr)));
                if(ret != PAM_SUCCESS || ptr == NULL) {
                        if (ret == PAM_SUCCESS && ptr == NULL)
                                ret = PAM_AUTHINFO_UNAVAIL;
			l0g(PMPREFIX "could not get password from PAM system\n");
			if(Args.auth_type == USE_FIRST_PASS)
				goto _return;
		} else
			authtok = xstrdup(ptr);
	}
	if (!authtok) {		/* get password directly */
		if((ret = read_password(pamh, "password:", &authtok)) != PAM_SUCCESS) {
			l0g(PMPREFIX "error trying to read password\n");
			goto _return;
		}
		/* p_s_i copies to PAM-internal memory */
		if((ret = pam_set_item(pamh, PAM_AUTHTOK, authtok)) != PAM_SUCCESS) {
			l0g(PMPREFIX "error trying to export password\n");
			goto _return;
		}
	}
	if (strlen(authtok) > MAX_PAR) {
		l0g(PMPREFIX "password too long\n");
		ret = PAM_AUTH_ERR;
		goto _return;
	}
	w4rn(PMPREFIX "saving authtok for session code\n");
        ret = pam_set_data(pamh, "pam_mount_system_authtok", authtok,
                           clean_system_authtok);
        if(ret != PAM_SUCCESS) {
		l0g(PMPREFIX "error trying to save authtok for session code\n");
		goto _return;
	}
      _return:
	assert(ret != PAM_SUCCESS
	       || pam_get_data(pamh, "pam_mount_system_authtok",
			       &tmp) == PAM_SUCCESS);
	assert(ret != PAM_SUCCESS || tmp != NULL);

	return ret;
}


/*  modify_pm_count
    @config:
    @user:
    @operation: string specifying numerical increment

    Calls out to the `pmvarrun` helper utility to adjust the mount reference
    count in /var/run/pam_mount/@user for the specified user.
    Returns the new reference count value on success, or -1 on error.

    Note: Modified version of pam_console.c:use_count()
*/
static int modify_pm_count(struct config *config, char *user,
 char *operation)
{
	FILE *fp;
	GError *err;
	struct fmt_ptrn vinfo;
	int _argc = 0, child_exit, cstdout = -1, fnval = -1, i;
	const char *_argv[MAX_PAR + 1];
	pid_t pid;
	struct sigaction sact, oldsact;

        assert(config_valid(config));
        assert(user != NULL);
        assert(operation != NULL);

	/* avoid bomb on command exiting before count read */
	sact.sa_handler = SIG_DFL;
	sact.sa_flags = 0;
        sigemptyset(&sact.sa_mask);
	if (sigaction(SIGPIPE, &sact, &oldsact) == -1) {
		fnval = -1;
		goto _nosigact_return;
	}
	fmt_ptrn_init(&vinfo);
	fmt_ptrn_update_kv(&vinfo, "USER", user);
	fmt_ptrn_update_kv(&vinfo, "OPERATION", operation);
	for(i = 0; config->command[i][CMD_PMVARRUN] != NULL; i++)
                add_to_argv(_argv, &_argc, config->command[i][CMD_PMVARRUN], &vinfo);
	fmt_ptrn_close(&vinfo);
	log_argv(_argv);

        if(!spawn_apS(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, set_myuid,
         NULL, &pid, NULL, &cstdout, NULL, &err)) {
		l0g(PMPREFIX "error executing /usr/sbin/pmvarrun\n");
		fnval = -1;
		goto _return;
	}
	if ((fp = fdopen(cstdout, "r")) == NULL) {
                spawn_restore_sigchld();
		w4rn(PMPREFIX "error opening file: %s\n", strerror(errno));
		fnval = -1;
		goto _return;
	}
	if (fscanf(fp, "%d", &fnval) == 0) {
                spawn_restore_sigchld();
		w4rn(PMPREFIX "error reading login count from pmvarrun\n");
		fnval = -1;
		goto _return;
	}
	if (waitpid(pid, &child_exit, 0) == -1) {
                spawn_restore_sigchld();
		l0g(PMPREFIX "error waiting for child: %s\n", strerror(errno));
		fnval = -1;
		goto _return;
	}
        spawn_restore_sigchld();
	if (WEXITSTATUS(child_exit)) {
		l0g(PMPREFIX "pmvarrun failed\n");
		fnval = -1;
		goto _return;
	}
	w4rn(PMPREFIX "pmvarrun says login count is %d\n", fnval);
_return:
	sigaction(SIGPIPE, &oldsact, NULL);
_nosigact_return:

        assert(config_valid(config));
	return fnval;
}


/*  pam_sm_open_session
    @pamh:      PAM handle
    @flags:     PAM flags
    @argc:      number of elements in @argv
    @argv:      NULL-terminated argument vector

    Entrypoint from the PAM layer. Starts the wheels and eventually mounts the
    user's directories according to pam_mount.conf.xml. Returns the PAM error
    code or %PAM_SUCCESS.
*/
PAM_EXTERN EXPORT_SYMBOL int pam_sm_open_session(pam_handle_t *pamh, int flags,
 int argc, const char **argv)
{
	int vol;
	int ret = PAM_SUCCESS;
	char *system_authtok;
	const char *pam_user = NULL;
        const void *tmp;
        int getval;

	assert(pamh != NULL);

	initconfig(&Config);
	/* call pam_get_user again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	if ((ret = pam_get_user(pamh, &pam_user, NULL)) != PAM_SUCCESS) {
		l0g(PMPREFIX "could not get user");
                /* do NOT return PAM_SERVICE_ERR or root will not be able
                 * to su to other users */
                goto _return;
	}
	/* FIXME: free me! the dup is requried because result of pam_get_user disappears (valgrind) */
	Config.user = relookup_user(pam_user);
	if(strlen(Config.user) > MAX_PAR) {
		l0g(PMPREFIX "username %s is too long\n", Config.user);
		ret = PAM_SERVICE_ERR;
		goto _return;
	}

        ret = pam_get_data(pamh, "pam_mount_system_authtok",
              static_cast(const void **, static_cast(void *, &system_authtok)));
        if(ret != PAM_SUCCESS) {
		l0g(PMPREFIX "error trying to retrieve authtok from auth code\n");
                ret = read_password(pamh, "reenter password:", &system_authtok);
                if(ret != PAM_SUCCESS) {
                       l0g(PMPREFIX "error trying to read password\n");
                       goto _return;
                }

	}
	if(!readconfig(CONFIGFILE, 1, &Config)) {
		ret = PAM_SERVICE_ERR;
		goto _return;
	}

        /* Get the Kerberos CCNAME so we can make it available to the
        mount command later on. */
        if(setenv("KRB5CCNAME", pam_getenv(pamh, "KRB5CCNAME"), 1) < 0)
            l0g(PMPREFIX "KRB5CCNAME setenv failed\n");

        // Store initialized config as PAM data
        if((getval = pam_get_data(pamh, "pam_mount_config",
         &tmp)) == PAM_NO_MODULE_DATA && (ret = pam_set_data(pamh,
         "pam_mount_config", &Config, clean_config)) != PAM_SUCCESS) {
            l0g(PMPREFIX "error trying to save config structure\n");
            goto _return;
        }

	w4rn(PMPREFIX "back from global readconfig\n");
	if(strlen(Config.luserconf) == 0)
		w4rn(PMPREFIX "per-user configurations not allowed by pam_mount.conf.xml\n");
        else if(exists(Config.luserconf) && owns(Config.user, Config.luserconf)) {
		w4rn(PMPREFIX "going to readconfig user\n");
		if(!readconfig(Config.luserconf, 0, &Config)) {
			ret = PAM_SERVICE_ERR;
			goto _return;
		}
		w4rn(PMPREFIX "back from user readconfig\n");
	} else
		w4rn(PMPREFIX "%s does not exist or is not owned by user\n",
                 Config.luserconf);
	if(Config.volcount <= 0)
		w4rn(PMPREFIX "no volumes to mount\n");
	if(!expandconfig(&Config)) {
		l0g(PMPREFIX "error expanding configuration\n");
		ret = PAM_SERVICE_ERR;
		goto _return;
	}
        w4rn(PMPREFIX "%s: real uid/gid=%ld:%ld, effective uid/gid=%ld:%ld\n",
             __FUNCTION__, static_cast(long, getuid()),
             static_cast(long, getgid()), static_cast(long, geteuid()),
             static_cast(long, getegid()));
/* This code needs root priv. */
	for(vol = 0; vol < Config.volcount; vol++) {
		/* luserconf_volume_record_sane() is called here so that
		 * a user can nest loopback images. otherwise ownership
		 * tests will fail if parent loopback image not yet
		 * mounted.  volume_record_sane() is here to be consistent */
                if(!volume_record_sane(&Config, vol))
			continue;
                if(!Config.volume[vol].globalconf &&
                  !luserconf_volume_record_sane(&Config, vol))
			continue;
		w4rn(PMPREFIX "about to perform mount operations\n");

                if(!mount_op(do_mount, &Config, vol, system_authtok,
                  Config.mkmntpoint)) {
                        l0g(PMPREFIX "mount of %s failed\n",
                          Config.volume[vol].volume);
                        ret = PAM_SERVICE_ERR;
                }
	}
/* end root priv. */
	/* Paranoia? */
	clean_system_authtok(pamh, system_authtok, 0);
/* This code needs root priv. */
	modify_pm_count(&Config, Config.user, "1");
/* end root priv. */

      _return:
	w4rn(PMPREFIX "done opening session\n");
	return ret;
}


/*  pam_sm_chauthtok
    @pamh:      PAM handle
    @flags:     PAM flags
    @argc:      number of elements in @argv
    @argv:      NULL-terminated argument vector

    This is a placeholder function so PAM does not get mad.
*/
PAM_EXTERN EXPORT_SYMBOL int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
 int argc, const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}


/*  pam_sm_close_session
    @pamh:      PAM handle
    @flags:     PAM flags
    @argc:      number of elements in @argv
    @argv:      NULL-terminated argument vector

    Entrypoint from the PAM layer. Stops all wheels and eventually unmounts the
    user's directories. Returns the PAM error code or %PAM_SUCCESS.

    FIXME: This function currently always returns %PAM_SUCCESS. Should it
    return soemthing else when errors occur and all unmounts have been
    attempted?
*/
PAM_EXTERN EXPORT_SYMBOL int pam_sm_close_session(pam_handle_t *pamh,
 int flags, int argc, const char **argv)
{
	int vol;
	int ret = PAM_SUCCESS;
	const char *pam_user = NULL;

	assert(pamh != NULL);

	w4rn(PMPREFIX "received order to close things\n");
	w4rn(PMPREFIX "real and effective user ID are %d and %d.\n",
	     getuid(), geteuid());
	/* call pam_get_user again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	if ((ret = pam_get_user(pamh, &pam_user, NULL)) != PAM_SUCCESS) {
		l0g(PMPREFIX "could not get user\n");
		/* do NOT return PAM_SERVICE_ERR or root will not be able
		 * to su to other users */
		goto _return;
	}
	/* FIXME: free me! the dup is requried because result of pam_get_user disappears (valgrind) */
	Config.user = relookup_user(pam_user);
	/* if our CWD is in the home directory, it might not get umounted */
	if(chdir("/") != 0)
		l0g(PMPREFIX "could not chdir\n");
	if(Config.volcount <= 0)
		w4rn(PMPREFIX "volcount is zero\n");
/* This code needs root priv. */
	if(modify_pm_count(&Config, Config.user, "-1") <= 0) {
		/* Unmount in reverse order to facilitate nested mounting. */
		for(vol = Config.volcount - 1; vol >= 0; vol--) {
			w4rn(PMPREFIX "going to unmount\n");
			if(!mount_op(do_unmount, &Config, vol, NULL, Config.mkmntpoint))
				l0g(PMPREFIX "unmount of %s failed\n", Config.volume[vol].volume);
                }
/* end root priv. */
	} else {
		w4rn(PMPREFIX "%s seems to have other remaining open sessions\n",
                 Config.user);
        }
      _return:
        // Note that PMConfig is automatically freed later in clean_config().
	w4rn(PMPREFIX "pam_mount execution complete\n");
	return ret;
}


/*  pam_sm_setcred
    @pamh:      PAM handle
    @flags:     PAM flags
    @argc:      number of elements in @argv
    @argv:      NULL-terminated argument vector

    This is a placeholder function so PAM does not get mad.
*/
PAM_EXTERN EXPORT_SYMBOL int pam_sm_setcred(pam_handle_t *pamh, int flags,
 int argc, const char **argv)
{
	return PAM_SUCCESS;
}


/*  pam_sm_acct_mgmt
    @pamh:      PAM handle
    @flags:     PAM flags
    @argc:      number of elements in @argv
    @argv:      NULL-terminated argument vector

    This is a placeholder function so PAM does not get mad.
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

//=============================================================================
