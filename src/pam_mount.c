/*   FILE: pam_mount.c
 * AUTHOR: Elvis Pf?tzenreuter <epx@conectiva.com>
 *   DATE: 2000
 *
 * Copyright (C) 2000 Elvis Pf?tzenreuter <epx@conectiva.com>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 2.1 of the 
 * License
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

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
#include <string.h>
#include <unistd.h>

#include "fmt_ptrn.h"
#include "misc.h"
#include "mount.h"
#include "pam_mount.h"
#include "private.h"
#include "readconfig.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__)
#    define CONFIGFILE "/etc/pam_mount.conf"
#else
#    define CONFIGFILE "/etc/security/pam_mount.conf"
#endif

static void clean_system_authtok(pam_handle_t *, void *, int);
static int converse(pam_handle_t *, int, const struct pam_message **,
    struct pam_response **);
static int modify_pm_count(config_t *, char *, char *);
static void parse_pam_args(int, const char **);
static int read_password(pam_handle_t *, const char *, char **);

gboolean debug;
config_t config;
pam_args_t args;

/* ============================ parse_pam_args () ========================== */
/* INPUT: argc and argv, standard main()-type arguments
 * SIDE EFFECTS: gloabl args is initialized, based on argc and argv */
static void parse_pam_args(int argc, const char **argv) {
	int i;

	assert(argc >= 0);
	for (i = 0; i < argc; i++)
		assert(argv[i] != NULL);

	/* first, set default values */
	args.auth_type = GET_PASS;
	for (i = 0; i < argc; i++) {
		w4rn("pam_mount: pam_sm_open_session args: %s\n", argv[i]);
		if(strcmp("use_first_pass", argv[i]) == 0)
			args.auth_type = USE_FIRST_PASS;
		else if(strcmp("try_first_pass", argv[i]) == 0)
			args.auth_type = TRY_FIRST_PASS;
		else
			w4rn("pam_mount: %s\n", "bad pam_mount option");
	}
}

/* ============================ clean_system_authtok () ==================== */
/* INPUT: pamh; data; errcode
 * SIDE EFFECTS: if data does not point to NULL then it is zeroized and freed 
 * NOTE: this is registered as a PAM callback function and called directly */
static void clean_system_authtok(pam_handle_t *pamh, void *data, int errcode) {
	w4rn("pam_mount: clean system authtok (%d)\n", errcode);
/* FIXME: not binary password safe */
/* FIXME: valgrind does not like -- called previously?
	if (data) {
		memset(data, 0, strlen(data));
		free(data);
	}
*/
}

/* ============================ converse () ================================ */
/* INPUT: pamh; nargs; message, a prompt message
 * SIDE EFFECTS: resp points to PAM's (user's) response to message
 * OUTPUT: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c */
static int
converse(pam_handle_t * pamh, int nargs,
	 const struct pam_message **message, struct pam_response **resp)
{
	int retval;
	struct pam_conv *conv;

	assert(pamh != NULL);
	assert(nargs >= 0);
	assert(resp != NULL);

	*resp = NULL;
	retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);
	if (retval == PAM_SUCCESS)
		retval = conv->conv(nargs, message, resp, conv->appdata_ptr);
        else
               l0g("pam_mount: %s\n", pam_strerror(pamh, retval));
	if(*resp == NULL)
		retval = PAM_AUTH_ERR;

	assert(retval != PAM_SUCCESS
	       || (resp != NULL && *resp != NULL
		   && (*resp)->resp != NULL));

	return retval;		/* propagate error status */
}

/* ============================ read_password () =========================== */
/* INPUT: pamh; prompt1, a prompt message
 * SIDE EFFECTS: pass points to PAM's (user's) response to prompt1 (malloc'ed)
 * OUTPUT: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c (_unix_read_password)
 */
static int read_password(pam_handle_t *pamh, const char *prompt, char **pass) {
	int retval;
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;

	assert(pamh != NULL);
	assert(prompt != NULL);
	assert(pass != NULL);

	w4rn("pam_mount: %s\n", "enter read_password");
	*pass = NULL;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt;
	retval = converse(pamh, 1, &pmsg, &resp);
	if (retval == PAM_SUCCESS)
		*pass = strdup(resp->resp);

	assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));

	return retval;
}

/* ============================ pam_sm_authenticate () ===================== */
/* INPUT: this function is called by PAM
 * SIDE EFFECTS: user's system password is added to PAM's global module data
 *               Pam_sm_open_session does the rest.
 * OUTPUT: PAM error code on error or PAM_SUCCESS
 * NOTE: this is here because many PAM implementations don't allow
 *       pam_sm_open_session access to user's system password.
 */
PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags,
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
	initconfig(&config);
	parse_pam_args(argc, argv);
	/* needed because gdm does not prompt for username as login does: */
	if ((ret = pam_get_user(pamh, &pam_user, NULL)) != PAM_SUCCESS) {
		l0g("pam_mount: %s\n", "could not get user");
		/* do NOT return PAM_SERVICE_ERR or root will not be able 
		 * to su to other users */
		goto _return;
	}
	/* FIXME: free me! the dup is requried because result of pam_get_user disappears (valgrind) */
	config.user = g_strdup(pam_user);
	w4rn("pam_mount: user is %s\n", config.user);
	if (args.auth_type != GET_PASS) {	/* get password from PAM system */
		char *ptr = NULL;
		if ((ret =
		     pam_get_item(pamh, PAM_AUTHTOK,
				  (const void **) &ptr)) != PAM_SUCCESS
                    || ptr == NULL) {
                        if (ret == PAM_SUCCESS && ptr == NULL)
                                ret = PAM_AUTHINFO_UNAVAIL;
			l0g("pam_mount: %s\n",
			    "could not get password from PAM system");
			if (args.auth_type == USE_FIRST_PASS)
				goto _return;
		} else
			authtok = strdup(ptr);
	}
	if (!authtok) {		/* get password directly */
		if ((ret = read_password(pamh, "password:",
					 &authtok)) != PAM_SUCCESS) {
			l0g("pam_mount: %s\n",
			    "error trying to read password");
			goto _return;
		}
		/* p_s_i copies to PAM-internal memory */
		if ((ret =
		     pam_set_item(pamh, PAM_AUTHTOK,
				  authtok)) != PAM_SUCCESS) {
			l0g("pam_mount: %s\n",
			    "error trying to export password");
			goto _return;
		}
	}
	if (strlen(authtok) > MAX_PAR) {
		l0g("pam_mount: %s\n", "password too long");
		ret = PAM_AUTH_ERR;
		goto _return;
	}
	w4rn("pam_mount: saving authtok for session code\n");
	if ((ret =
	     pam_set_data(pamh, "pam_mount_system_authtok", authtok,
			  clean_system_authtok)) != PAM_SUCCESS) {
		l0g("pam_mount: %s\n",
		    "error trying to save authtok for session code");
		goto _return;
	}
      _return:
	assert(ret != PAM_SUCCESS
	       || pam_get_data(pamh, "pam_mount_system_authtok",
			       &tmp) == PAM_SUCCESS);
	assert(ret != PAM_SUCCESS || tmp != NULL);

	return ret;
}

/* ============================ modify_pm_count () ========================= */
/* FIXME: use INPUT, SIDE EFFECTS and OUTPUT */
/* FIXME: add PRE/POST assertions */
/* POST:   amount is added to /var/run/pam_mount/<user>'s value
 *         if value == 0, then file is removed.
 * FN VAL: new value else -1 on error, errors are logged
 * NOTE:   code is modified version of pam_console.c's use_count
 * FIXME:  should this be replaced with utmp (man utmp) usage?
 *         Is utmp portable?  This function is nasty and MAY BE INSECURE.
 */
static int modify_pm_count(config_t *config, char *user, char *operation) {
	FILE *fp;
	GError *err;
	fmt_ptrn_t vinfo;
	int _argc = 0, child_exit, cstdout = -1, fnval = -1, i;
	char *_argv[MAX_PAR + 1];
	pid_t pid;
	struct sigaction sact, oldsact;

	/* avoid bomb on command exiting before count read */
	sact.sa_handler = SIG_DFL;
	sact.sa_flags = 0;
	if (sigaction(SIGPIPE, &sact, &oldsact) == -1) {
		fnval = -1;
		goto _nosigact_return;
	}
	fmt_ptrn_init(&vinfo);
	fmt_ptrn_update_kv(&vinfo, "USER", user);
	fmt_ptrn_update_kv(&vinfo, "OPERATION", operation);
	for(i = 0; config->command[i][PMVARRUN] != NULL; i++)
                add_to_argv(_argv, &_argc, config->command[i][PMVARRUN], &vinfo);
	fmt_ptrn_close(&vinfo);
	log_argv(_argv);
	if (g_spawn_async_with_pipes(NULL, _argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, NULL, &cstdout, NULL, &err) == FALSE) {
		l0g("pam_mount: error executing /usr/sbin/pmvarrun\n");
		fnval = -1;
		goto _return;
	}
	if ((fp = fdopen(cstdout, "r")) == NULL) {
		w4rn("pam_mount: error opening file: %s\n", strerror(errno));
		fnval = -1;
		goto _return;
	}
	if (fscanf(fp, "%d", &fnval) == 0) {
		w4rn("pam_mount: error reading login count from pmvarrun\n");
		fnval = -1;
		goto _return;
	}
	if (waitpid(pid, &child_exit, 0) == -1) {
		l0g("pam_mount: error waiting for child\n");
		fnval = -1;
		goto _return;
	}
	if (WEXITSTATUS(child_exit)) {
		l0g("pam_mount: pmvarrun failed\n");
		fnval = -1;
		goto _return;
	}
	w4rn("pam_mount: pmvarrun says login count is %d\n", fnval);
_return:
	sigaction(SIGPIPE, &oldsact, NULL);
_nosigact_return:
	return fnval;
}

/* ============================ pam_sm_open_session () ===================== */
/* INPUT: this function is called by PAM
 * SIDE EFFECTS: user's directories are mounted if pam_mount.conf says they
 *               should be or an error is logged
 * OUTPUT: PAM error code on error or PAM_SUCCESS
 */
PAM_EXTERN int
pam_sm_open_session(pam_handle_t * pamh, int flags,
		    int argc, const char **argv)
{
	int vol;
	int ret = PAM_SUCCESS;
	char *system_authtok;
	const char *pam_user = NULL;

	assert(pamh != NULL);

	initconfig(&config);
	/* call pam_get_user again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	if ((ret = pam_get_user(pamh, &pam_user, NULL)) != PAM_SUCCESS) {
		l0g("pam_mount: %s\n", "could not get user");
                /* do NOT return PAM_SERVICE_ERR or root will not be able
                 * to su to other users */
                goto _return;
	}
	/* FIXME: free me! the dup is requried because result of pam_get_user disappears (valgrind) */
	config.user = g_strdup(pam_user);
	w4rn("pam_mount: user is %s\n", config.user);
	if (strlen(config.user) > MAX_PAR) {
		l0g("pam_mount: username %s is too long\n", config.user);
		ret = PAM_SERVICE_ERR;
		goto _return;
	}
	if ((ret =
	     pam_get_data(pamh, "pam_mount_system_authtok",
			  (const void **) &system_authtok)) != PAM_SUCCESS)
	{
		l0g("pam_mount: %s\n",
		    "error trying to retrieve authtok from auth code");
		if ((ret = read_password(pamh, "reenter password:",
                                        &system_authtok)) != PAM_SUCCESS) {
                       l0g("pam_mount: %s\n",
                           "error trying to read password");
                       goto _return;
               }

	}
	if (!readconfig(config.user, CONFIGFILE, 1, &config)) {
		ret = PAM_SERVICE_ERR;
		goto _return;
	}
	w4rn("pam_mount: %s\n", "back from global readconfig");
	if(strlen(config.luserconf) == 0)
		w4rn("pam_mount: %s\n",
		     "per-user configurations not allowed by pam_mount.conf");
	else if (exists(config.luserconf)
		 && owns(config.user, config.luserconf) == TRUE) {
		w4rn("pam_mount: %s\n", "going to readconfig user");
		if (!readconfig(config.user, config.luserconf, 0, &config)) {
			ret = PAM_SERVICE_ERR;
			goto _return;
		}
		w4rn("pam_mount: %s\n", "back from user readconfig");
	} else
		w4rn("pam_mount: %s does not exist or is not owned by user\n", config.luserconf);
	if (config.volcount <= 0) {
		w4rn("pam_mount: %s\n", "no volumes to mount");
	}
	if (!expandconfig(&config)) {
		l0g("pam_mount: %s\n", "error expanding configuration");
		ret = PAM_SERVICE_ERR;
		goto _return;
	}
/* This code needs root priv. */
	w4rn("pam_mount: real and effective user ID are %d and %d.\n",
	     getuid(), geteuid());
	for (vol = 0; vol < config.volcount; vol++) {
		/* luserconf_volume_record_sane() is called here so that 
		 * a user can nest loopback images. otherwise ownership
		 * tests will fail if parent loopback image not yet 
		 * mounted.  volume_record_sane() is here to be consistent */
		if (volume_record_sane(&config, vol) != TRUE)
			continue;
		if (config.volume[vol].globalconf != TRUE
		    && luserconf_volume_record_sane(&config, vol) != TRUE)
			continue;
		w4rn("pam_mount: %s\n",
		     "about to perform mount operations");
		if (!mount_op
		    (do_mount, &config, vol, system_authtok,
		     config.mkmntpoint))
			l0g("pam_mount: mount of %s failed\n",
			    config.volume[vol].volume);
	}
/* end root priv. */
	/* Paranoia? */
	clean_system_authtok(pamh, system_authtok, 0);
/* This code needs root priv. */
	modify_pm_count(&config, config.user, "1");
/* end root priv. */

      _return:
	w4rn("pam_mount: done opening session\n");
	return ret;
}

/* ============================ pam_sm_chauthtok () ======================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc,
		 const char **argv)
{
	return pam_sm_authenticate(pamh, flags, argc, argv);
}

/* ============================ pam_sm_close_session () ==================== */
/* INPUT: this function is called by PAM
 * SIDE EFFECTS: user's directories are unmounted if pam_mount.conf says they
 *               should be or an error is logged
 * OUTPUT: PAM error code on error or PAM_SUCCESS
 */
PAM_EXTERN int
pam_sm_close_session(pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
	int vol;
	/* FIXME: this currently always returns PAM_SUCCESS should return something else when errors occur but only after all unmounts are attempted??? */
	int ret = PAM_SUCCESS;
	const char *pam_user = NULL;

	assert(pamh != NULL);

	w4rn("pam_mount: %s\n", "received order to close things");
	w4rn("pam_mount: real and effective user ID are %d and %d.\n",
	     getuid(), geteuid());
	/* call pam_get_user again because ssh calls PAM fns from seperate
 	 * processes.
	 */
	if ((ret = pam_get_user(pamh, &pam_user, NULL)) != PAM_SUCCESS) {
		l0g("pam_mount: %s\n", "could not get user");
		/* do NOT return PAM_SERVICE_ERR or root will not be able 
		 * to su to other users */
		goto _return;
	}
	/* FIXME: free me! the dup is requried because result of pam_get_user disappears (valgrind) */
	config.user = g_strdup(pam_user);
	w4rn("pam_mount: user is %s\n", config.user);
	/* if our CWD is in the home directory, it might not get umounted */
	if(chdir("/") != 0)
		l0g("pam_mount %s\n", "could not chdir");
	if (config.volcount <= 0)
		w4rn("pam_mount: %s\n", "volcount is zero");
/* This code needs root priv. */
	if (modify_pm_count(&config, config.user, "-1") <= 0)
		/* Unmount in reverse order to facilitate nested mounting. */
		for (vol = config.volcount - 1; vol >= 0; vol--) {
			w4rn("pam_mount: %s\n", "going to unmount");
			if (!mount_op
			    (do_unmount, &config, vol, NULL,
			     config.mkmntpoint))
				l0g("pam_mount: unmount of %s failed\n",
				    config.volume[vol].volume);
	} else
		w4rn("pam_mount: %s seems to have other remaining open sessions\n", config.user);
/* end root priv. */
      _return:
	freeconfig(config);
	w4rn("pam_mount: pam_mount execution complete\n");
	return ret;
}

/* ============================ pam_sm_setcred () ========================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/* ============================ pam_sm_acct_mgmt () ======================== */
PAM_EXTERN int 
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                    const char **argv) {
    return PAM_IGNORE;
}

#ifdef PAM_STATIC
/* static module data */

struct pam_module _pam_mount_modstruct = {
    .name                 = "pam_mount",
    .pam_sm_authenticate  = pam_sm_authenticate,
    .pam_sm_setcred       = pam_sm_setcred,
    .pam_sm_acct_mgmt     = pam_sm_acct_mgmt,
    .pam_sm_open_sesion   = pam_sm_open_session,
    .pam_sm_close_session = pam_sm_close_session,
    .pam_sm_chauthtok     = pam_sm_chauthtok,
};

#endif
