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

#include <config.h>
#include <glib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <pwd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <pam_mount.h>

gboolean debug;
config_t config;
pam_args_t args;

/* ============================ parse_pam_args () ========================== */
/* INPUT: argc and argv, standard main()-type arguments
 * SIDE AFFECTS: gloabl args is initialized, based on argc and argv */
void parse_pam_args(int argc, const char **argv)
{
	int i;

	assert(argc >= 0);
	for (i = 0; i < argc; i++)
		assert(argv[i]);

	/* first, set default values */
	args.auth_type = GET_PASS;
	for (i = 0; i < argc; i++) {
		w4rn("pam_mount: pam_sm_open_session args: %s\n", argv[i]);
		if (!strcmp("use_first_pass", argv[i]))
			args.auth_type = USE_FIRST_PASS;
		else if (!strcmp("try_first_pass", argv[i]))
			args.auth_type = TRY_FIRST_PASS;
		else
			w4rn("pam_mount: %s\n", "bad pam_mount option");
	}
}

/* ============================ clean_system_authtok () ==================== */
/* INPUT: pamh; data; errcode
 * SIDE AFFECTS: if data does not point to NULL then it is zeroized and freed 
 * NOTE: this is registered as a PAM callback function and called directly */
void clean_system_authtok(pam_handle_t * pamh, void *data, int errcode)
{
/* FIXME: not binary password safe */
/* FIXME: valgrind does not like
	if (data) {
		memset(data, 0x00, strlen(data));
		free(data);
	}
*/
}

/* ============================ converse () ================================ */
/* INPUT: pamh; nargs; message, a prompt message
 * SIDE AFFECTS: resp points to PAM's (user's) response to message
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
		retval =
		    conv->conv(nargs, message, resp, conv->appdata_ptr);
	if (!*resp)
		retval = PAM_AUTH_ERR;

	assert(retval != PAM_SUCCESS
	       || (resp != NULL && *resp != NULL
		   && (*resp)->resp != NULL));

	return retval;		/* propagate error status */
}

/* ============================ read_password () =========================== */
/* INPUT: pamh; prompt1, a prompt message
 * SIDE AFFECTS: pass points to PAM's (user's) response to prompt1 (malloc'ed)
 * OUTPUT: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c (_unix_read_password)
 */
int read_password(pam_handle_t * pamh, const char *prompt1, char **pass)
{
	int retval;
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;

	assert(pamh != NULL);
	assert(prompt1 != NULL);
	assert(pass != NULL);

	w4rn("pam_mount: %s\n", "enter read_password");
	*pass = NULL;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt1;
	retval = converse(pamh, 1, &pmsg, &resp);
	if (retval == PAM_SUCCESS)
		*pass = strdup(resp->resp);

	assert(retval != PAM_SUCCESS || (pass != NULL && *pass != NULL));

	return retval;
}

/* ============================ pam_sm_authenticate () ===================== */
/* INPUT: this function is called by PAM
 * SIDE AFFECTS: user's system password is added to PAM's global module data
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

	assert(pamh);

	initconfig(&config);
	parse_pam_args(argc, argv);
	/* needed because gdm does not prompt for username as login does: */
	//if ((ret = pam_get_user(pamh, &config.user, NULL)) != PAM_SUCCESS) {
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
		    || !ptr) {
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
	assert(ret != PAM_SUCCESS || tmp);

	return ret;
}

/* ============================ modify_pm_count () ========================= */
/* FIXME: use INPUT, SIDE AFFECTS and OUTPUT */
/* FIXME: add PRE/POST assertions */
/* POST:   amount is added to /var/run/pam_mount/<user>'s value
 *         if value == 0, then file is removed.
 * FN VAL: new value else -1 on error, errors are logged
 * NOTE:   code is modified version of pam_console.c's use_count
 * FIXME:  should this be replaced with utmp (man utmp) usage?
 *         Is utmp portable?  This function is nasty and MAY BE INSECURE.
 */
int modify_pm_count(config_t *config, char *user, char *operation)
{
	FILE *fp;
	fmt_ptrn_t vinfo;
	int _argc = 0, child_exit, cstdout = -1, fnval = -1, i;
	char *_argv[MAX_PAR + 1];
	pid_t pid;
	struct sigaction sact, oldsact;

	/* avoid bomb on command exiting before count read */
	sact.sa_handler = SIG_DFL;
	sact.sa_flags = 0;
	if (sigaction(SIGPIPE, &sact, &oldsact) < 0) {
		fnval = -1;
		goto _nosigact_return;
	}
	fmt_ptrn_init(&vinfo);
	fmt_ptrn_update_kv(&vinfo, "USER", user);
	fmt_ptrn_update_kv(&vinfo, "OPERATION", operation);
	for (i = 0; config->command[i][PMVARRUN]; i++)
                add_to_argv(_argv, &_argc, config->command[i][PMVARRUN], &vinfo);
	fmt_ptrn_close(&vinfo);
	if ((pid =
	     procopen(_argv[0], &_argv[1], 1, NULL, &cstdout, NULL)) == -1) {
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
 * SIDE AFFECTS: user's directories are mounted if pam_mount.conf says they
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

	assert(pamh);

	/* if our CWD is in the home directory, it might not get umounted */
	/* Needed for KDM.  FIXME: Bug in KDM? */
	if (chdir("/"))
		l0g("pam_mount %s\n", "could not chdir");
	if (config.user == NULL) {
		l0g("pam_mount: username not read: pam_mount not conf. for auth?\n");
		/* do NOT return PAM_SERVICE_ERR or root will not be able 
		 * to su to other users */
		goto _return;
	}
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
		goto _return;
	}
	if (!readconfig(config.user, CONFIGFILE, 1, &config)) {
		ret = PAM_SERVICE_ERR;
		goto _return;
	}
	w4rn("pam_mount: %s\n", "back from global readconfig");
	if (!strlen(config.luserconf))
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
		     config.mkmountpoint))
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
 * SIDE AFFECTS: user's directories are unmounted if pam_mount.conf says they
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

	assert(pamh);

	w4rn("pam_mount: %s\n", "received order to close things");
	w4rn("pam_mount: real and effective user ID are %d and %d.\n",
	     getuid(), geteuid());
	if (config.user == NULL) {
		l0g("pam_mount: username not read: pam_mount not conf. for auth?\n");
		/* do NOT return PAM_SERVICE_ERR or root will not be able 
		 * to su to other users */
		goto _return;
	}
	if (config.volcount <= 0)
		w4rn("pam_mount: %s\n", "volcount is zero");
/* This code needs root priv. */
	if (modify_pm_count(&config, config.user, "-1") <= 0)
		/* Unmount in reverse order to facilitate nested mounting. */
		for (vol = config.volcount - 1; vol >= 0; vol--) {
			w4rn("pam_mount: %s\n", "going to unmount");
			if (!mount_op
			    (do_unmount, &config, vol, NULL,
			     config.mkmountpoint))
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
