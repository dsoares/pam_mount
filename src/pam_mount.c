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

int debug;
config_t config;
pam_args_t args;

/* ============================ parse_pam_args () ========================== */
/* PRE:    argv is valid
 *         argc >= 1
 * POST:   args contains the arguments to pam_mount
 */
void
parse_pam_args (int argc, const char **argv)
{
  int i;
  /* first, set default values */
  args.auth_type = GET_PASS;
  for (i = 0; i < argc; i++)
    {
      w4rn ("pam_mount: pam_sm_open_session args: %s\n", argv[i]);
      if (!strcmp ("use_first_pass", argv[i]))
	args.auth_type = USE_FIRST_PASS;
      else if (!strcmp ("try_first_pass", argv[i]))
	args.auth_type = TRY_FIRST_PASS;
      else
	w4rn ("pam_mount: %s\n", "bad pam_mount option");
    }
}

/* ============================ clean_system_authtok () ==================== */
/* POST: if data points to a valid sting, then it is zeroized */
void
clean_system_authtok (pam_handle_t * pamh, void *data, int errcode)
{
  if (data)
    {
      memset (data, 0x00, strlen (data));	/* FIXME: not binary password safe */
      free (data);
    }
}

/* ============================ pam_sm_authenticate () ===================== */
/* PRE:    this function is called by PAM
 * POST:   user's system password is added to PAM's global module data
 *         Pam_pm_open_session does the rest.
 * FN VAL: PAM error code on error or PAM_SUCCESS
 * NOTE:   this is here because many PAM implementations don't allow
 *         pam_sm_open_session access to user's system password.
 */
PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh, int flags,
		     int argc, const char **argv)
{
  int ret;
  char *authtok = NULL;
  parse_pam_args (argc, argv);
  if (args.auth_type == USE_FIRST_PASS || args.auth_type == TRY_FIRST_PASS)
    {
      char *ptr;
      if ((ret =
	   pam_get_item (pamh, PAM_AUTHTOK,
			 (const void **) &ptr)) != PAM_SUCCESS || !ptr) /* FIXME: what if passwd is ""? */
	{
	  l0g ("pam_mount: %s\n", "could not get password from PAM system");
	  if (args.auth_type == USE_FIRST_PASS)
	    return ret;
	}
      else
	authtok = strdup (ptr);	/* FIXME: what if password is ""?  see also below */
    }
  if (args.auth_type == GET_PASS
      || (!authtok && args.auth_type == TRY_FIRST_PASS))
    {
      /* get the password */
      if ((ret = read_password (pamh, "password:", &authtok)) != PAM_SUCCESS)
	{
	  l0g ("pam_mount: %s\n", "error trying to read password");
	  return ret;
	}
      if ((ret = pam_set_item (pamh, PAM_AUTHTOK, authtok)) != PAM_SUCCESS)
	{
	  l0g ("pam_mount: %s\n", "error trying to export password");
	  return ret;
	}
    }
  if (!authtok)			/* FIXME: see above */
    l0g ("pam_mount: %s\n", "account seems to have no password");
  if (strlen (authtok) > MAX_PAR)
    {
      l0g ("pam_mount: %s\n", "password too long");
      return PAM_AUTH_ERR;
    }
  if ((ret =
       pam_set_data (pamh, "pam_mount_system_authtok", authtok,
		     clean_system_authtok)) != PAM_SUCCESS)
    {
      l0g ("pam_mount: %s\n",
	   "error trying to save authtok for session code");
      return ret;
    }
  return PAM_SUCCESS;
}

/* ============================ str_to_long () ============================= */
long
str_to_long (char *n)
/* PRE:    dosn't assume anything about n
 * FN VAL: if error LONG_MAX or LONG_MIN else long value of n, errors are logged 
 * NOTE:   this is needed because users own /var/run/pam_mount/<user> 
 *         and they could try something sneaky
 */
{
  long val;
  char *endptr = NULL;
  if (!n)
    {
      l0g ("pam_mount: %s\n", "count string is NULL");
      return LONG_MAX;
    }
  val = strtol (n, &endptr, 10);
  if (*endptr)
    {
      l0g ("pam_mount: count string is not valid\n");
      return LONG_MAX;
    }
  return val;
}

/* ============================ modify_pm_count () ========================= */
/* PRE:    user points to a valid string != NULL 
 * POST:   amount is added to /var/run/pam_mount/<user>'s value
 *         if value == 0, then file is removed. 
 * FN VAL: new value else -1 on error, errors are logged 
 * NOTE:   code is modified version of pam_console.c's use_count 
 * FIXME:  should this be replaced with utmp (man utmp) usage?  
 *         Is utmp portable?  This function is nasty.
 */
int
modify_pm_count (const char *user, long amount)
{
  char filename[PATH_MAX + 1];
  int tries = 0;
  int fd, err;
  long val;
  struct stat st;
  struct flock lockinfo;
  char *buf = NULL;
  struct passwd *passwd_ent;
  if (!(passwd_ent = getpwnam (user)))
    {
      w4rn ("pam_mount: could not resolve uid for %s\n", user);
      err = -1;
      goto return_error;
    }
  if (stat ("/var/run/pam_mount", &st) == -1)
    {
      w4rn ("pam_mount: %s\n", "creating /var/run/pam_mount");
      if (mkdir ("/var/run/pam_mount", 0000) == -1)
	{
	  w4rn ("pam_mount: %s\n", "unable to create /var/run/pam_mount\n");
	  err = -1;
	  goto return_error;
	}
      if (chown ("/var/run/pam_mount", 0, 0) == -1)
	{
	  w4rn ("pam_mount: unable to chown %s\n", "/var/run/pam_mount");
	  err = -1;
	  goto return_error;
	}
      /*
       * 0755: su creates file group owned by user and the releases
       * root perms.  User needs to be able to access file on
       * logout.
       */
      /*
       * FIXME: user can modify /var/.../<user> at will; security
       * problem?  Note that this file's contents is checked by 
       * str_to_long.
       */
      if (chmod ("/var/run/pam_mount", 0755) == -1)
	{
	  w4rn ("pam_mount: unable to chmod %s\n", "/var/run/pam_mount");
	  err = -1;
	  goto return_error;
	}
    }
  snprintf (filename, PATH_MAX + 1, "/var/run/pam_mount/%s", user);
top:
  tries++;
  if (stat (filename, &st) == -1)
    {
      if ((fd = open (filename, O_RDWR | O_CREAT, 0000)) == -1)
	{
	  w4rn ("pam_mount: unable to open %s\n", filename);
	  err = -1;
	  goto return_error;
	}
      /*
       * su creates file group owned by user and the releases root
       * perms.  User needs to be able to access file on logout.
       */
/* FIXME: testing root owned /var/run/pam_mount/* -- requires that pam_mount
 *        has root privileges when clossing session.
      if (fchown (fd, passwd_ent->pw_uid, passwd_ent->pw_gid) == -1)
*/
      if (fchown (fd, 0, 0) == -1)
	{
	  w4rn ("pam_mount: unable to chown %s\n", filename);
	  err = -1;
	  goto return_error;
	}
      if (fchmod (fd, 0600) == -1)
	{
	  w4rn ("pam_mount: unable to chmod %s\n", filename);
	  err = -1;
	  goto return_error;
	}
      if (write (fd, "0", 1) == -1)
	{
	  w4rn ("pam_mount: write error on %s\n", filename);
	  err = -1;
	  goto return_error;
	}
      if (lseek (fd, SEEK_SET, 0) == -1)
	{
	  w4rn ("pam_mount: seek error in %s\n", filename);
	  err = -1;
	  goto return_error;
	}
    }
  else
    fd = open (filename, O_RDWR);
  if (stat (filename, &st) == -1)
    {
      w4rn ("pam_mount: unable to stat %s\n", filename);
      err = -1;
      goto return_error;
    }
  if (fd < 0)
    {
      w4rn ("pam_mount: could not open count file %s\n", filename);
      return 0;
    }
  lockinfo.l_type = F_WRLCK;
  lockinfo.l_whence = SEEK_SET;
  lockinfo.l_start = 0;
  lockinfo.l_len = 0;
  alarm (20);
  err = fcntl (fd, F_SETLKW, &lockinfo);
  alarm (0);
  if (err == EAGAIN)
    {
      /*
       * if someone has locked the file and not written to it in at
       * least 20 seconds, we assume they either forgot to unlock
       * it or are catatonic -- chances are slim that they are in
       * the middle of a read-write cycle and I don't want to make
       * us lock users out.  Perhaps I should just return
       * PAM_SUCCESS instead and log the event?  Kill the process
       * holding the lock?  Options abound...  For now, we ignore
       * it.
       */
      fcntl (fd, F_GETLK, &lockinfo);
      /*
       * now lockinfo.l_pid == 0 implies that the lock was released
       * by the other process between returning from the 20 second
       * wait and calling fcntl again, not likely to ever happen,
       * and not a problem other than cosmetics even if it does.
       */
      w4rn ("pam_mount: ignoring stale lock on file %s\n", filename);
    }
  /*
   * it is possible at this point that the file has been removed by a
   * previous login; if this happens, we need to start over.
   * Unfortunately, the only way to do this without potential stack
   * trashing is a goto.
   */
  if (access (filename, F_OK) < 0)
    {
      if (tries < 10)
	{
	  w4rn ("pam_mount: could not access %s, trying again\n", filename);
	  sleep (1);
	  CLOSE (fd);
	  goto top;
	}
      else
	{
	  w4rn ("pam_mount: %s\n", "tried ten times, quitting");
	  err = -1;
	  goto return_error;
	}
    }
  if (!(buf = malloc (st.st_size + 2)))
    {				/* size will never grow by
				 * more than one */
      w4rn ("pam_mount: %s\n", "malloc failed");
      err = -1;
      goto return_error;
    }
  if (st.st_size)
    {
      if (read (fd, buf, st.st_size) == -1)
	{
	  w4rn ("pam_mount: read error on %s\n", filename);
	  err = -1;
	  goto return_error;
	}
      if (lseek (fd, 0, SEEK_SET) == -1)
	{
	  w4rn ("pam_mount: lseek error on %s\n", filename);
	  err = -1;
	  goto return_error;
	}
      buf[st.st_size] = '\0';
      if ((val = str_to_long (buf)) == LONG_MAX || val == LONG_MIN)
	{
	  l0g ("pam_mount: %s\n", "session count corrupt (overflow)");
	  err = -1;
	  goto return_error;
	}
    }
  else
    {
      val = 0;
    }
  if (amount)
    {				/* amount == 0 implies query */
      val += amount;
      if (val <= 0)
	{
	  if (unlink (filename))
	    {
	      w4rn ("pam_mount: unlink error on %s\n", filename);
	    }
	}
      snprintf (buf, st.st_size + 2, "%ld", val);
      if (write (fd, buf, strlen (buf)) == -1)
	{
	  w4rn ("pam_mount: write error on %s\n", filename);
	  err = -1;
	  goto return_error;
	}
    }
  err = val;
return_error:
  if (fd > 0)
    CLOSE (fd);
  if (buf)
    free (buf);
  return err;
}

/* ============================ pam_sm_open_session () ===================== */
/* PRE:    this function is called by PAM
 * POST:   user's directories are mounted if pam_mount.conf says they should 
 *         be or an error is logged
 * FN VAL: PAM error code on error or PAM_SUCCESS
 */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh, int flags,
		     int argc, const char **argv)
{
  int vol;
  int ret;
  char *system_authtok;
  /* if our CWD is in the home directory, it might not get umounted */
  /* Needed for KDM.  FIXME: Bug in KDM? */
  if (chdir ("/"))
    l0g ("pam_mount %s\n", "could not chdir");
  if ((ret = pam_get_user (pamh, &config.user, NULL)) != PAM_SUCCESS)
    {
      l0g ("pam_mount: %s\n", "could not get user");
      return ret;
    }
  w4rn ("pam_mount: user is %s\n", config.user);
  if (strlen (config.user) > MAX_PAR)
    {
      l0g ("pam_mount: username %s is too long\n", config.user);
      return PAM_SERVICE_ERR;
    }
  if ((ret =
       pam_get_data (pamh, "pam_mount_system_authtok",
		     (const void **) &system_authtok)) != PAM_SUCCESS)
    {
      l0g ("pam_mount: %s\n",
	   "error trying to retrieve authtok from session code");
      return ret;
    }
  initconfig (&config);
  if (!readconfig (config.user, CONFIGFILE, 1, &config))
    return PAM_SERVICE_ERR;
  w4rn ("pam_mount: %s\n", "back from global readconfig");
  if (!strlen (config.luserconf))
    w4rn ("pam_mount: %s\n",
	  "per-user configurations not allowed by pam_mount.conf");
  else if (exists (config.luserconf) && owns (config.user, config.luserconf))
    {
      w4rn ("pam_mount: %s\n", "going to readconfig user");
      if (!readconfig (config.user, config.luserconf, 0, &config))
	return PAM_SERVICE_ERR;
      w4rn ("pam_mount: %s\n", "back from user readconfig");
    }
  else
    w4rn ("pam_mount: %s does not exist or is not owned by user\n",
	  config.luserconf);
  if (config.volcount <= 0)
    {
      w4rn ("pam_mount: %s\n", "no volumes to mount");
    }
  if (!expandconfig (&config))
    {
      l0g ("pam_mount: %s\n", "error expanding configuration");
      return PAM_SERVICE_ERR;
    }
  w4rn ("pam_mount: real and effective user ID are %d and %d.\n",
	getuid (), geteuid ());
  for (vol = 0; vol < config.volcount; vol++)
    {
      w4rn ("pam_mount: %s\n", "about to perform mount operations");
      if (!mount_op
	  (do_mount, &config, vol, system_authtok, config.mkmountpoint))
	l0g ("pam_mount: mount of %s failed\n", config.volume[vol].volume);
    }
  /* Paranoia? */
  clean_system_authtok (pamh, system_authtok, 0);
  modify_pm_count (config.user, 1);
  return PAM_SUCCESS;
}

/* ============================ pam_sm_chauthtok () ======================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return pam_sm_authenticate (pamh, flags, argc, argv);
}

/* ============================ pam_sm_close_session () ==================== */
/* PRE:    this function is called by PAM
 * POST:   user's directories are unmounted if pam_mount.conf says they 
 *         should be or an error is logged 
 * FN VAL: PAM error code on error or PAM_SUCCESS
 */
PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh, int flags, int argc,
		      const char **argv)
{
  int vol;
  w4rn ("pam_mount: %s\n", "received order to close things");
  w4rn ("pam_mount: real and effective user ID are %d and %d.\n",
	getuid (), geteuid ());
  if (config.volcount <= 0)
    w4rn ("pam_mount: %s\n", "volcount is zero");
  if (modify_pm_count (config.user, -1) <= 0)
    /* Unmount in reverse order to facilitate nested mounting. */
    for (vol = config.volcount - 1; vol >= 0; vol--)
      {
	w4rn ("pam_mount: %s\n", "going to unmount");
	if (!mount_op (do_unmount, &config, vol, NULL, config.mkmountpoint))
	    l0g ("pam_mount: unmount of %s failed\n", config.volume[vol].volume);
      }
  else
    w4rn ("pam_mount: %s seems to have other remaining open sessions\n",
	  config.user);
  freeconfig (config);
  return PAM_SUCCESS;
}

/* ============================ pam_sm_setcred () ========================== */
/* NOTE: placeholder function so PAM does not get mad */
PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}
