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
static char system_password[MAX_PAR + 1];

/* ============================ pam_sm_authenticate () ===================== */
/* PRE:    this function is called by PAM
 * POST:   system_password is set to the user's system password.  
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
  char *tmp_pass;
  if ((ret = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &tmp_pass)))
    {
      l0g ("pam_mount: %s\n", "could not get password");
      return ret;
    }
  if (!tmp_pass)
    {
      w4rn ("pam_mount: %s\n", "account seems to have no password");
      *system_password = 0x00;
      return PAM_SUCCESS;
    }
  else
    {
      if (strlen (tmp_pass) > MAX_PAR)
	{
	  l0g ("pam_mount: %s\n", "password too long");
	  return PAM_SERVICE_ERR;
	}
      /*
       * Following is needed because PAM clears memory holding
       * password before pam_sm_open_session.
       */
      strncpy (system_password, tmp_pass, MAX_PAR);
      return PAM_SUCCESS;
    }
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
  char *ptr = n;
  if (!n)
    {
      l0g ("pam_mount: %s\n", "count string is NULL");
      return LONG_MAX;
    }
  if (!*n || *n == '\n')
    {
      l0g ("pam_mount: %s\n", "count string has no length");
      return LONG_MAX;
    }
  do
    {
      /* "123\n" okay, "1a23" bad, "1\n23" bad, "123" okay */
      if (!(isdigit (*ptr)))
	{
	  l0g ("pam_mount: %s\n", "count contains non-digits");
	  return LONG_MAX;
	}
      ptr++;
    }
  while (!(*ptr == '\n' && !*(ptr + 1)) && *ptr);
  return strtol (n, NULL, 10);
}

/* ============================ modify_pm_count () ========================= */
/* PRE:    user points to a valid string != NULL 
 * POST:   amount is added to /var/run/pam_mount/<user>'s value
 *         if value == 0, then file is removed. 
 * FN VAL: new value else -1 on error, errors are logged 
 * NOTE:   code is modified version of pam_console.c's use_count 
 * FIXME:  should this be replaced with utmp (man utmp) usage?  
 *         Is utmp portable?
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
      if (fchown (fd, passwd_ent->pw_uid, passwd_ent->pw_gid) == -1)
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

/* ============================ pass_type () =============================== */
/* PRE:    argv is valid
 *         argc >= 1
 * FN VAL: 1 if try_first_pass, else 0
 */
int
pass_type (int argc, const char **argv)
{
  int i;
  for (i = 0; i < argc; i++)
    {
      w4rn ("pam_mount: pam_sm_open_session args: %s\n", argv[i]);
      if (!strcmp ("use_first_pass", argv[i]))
	return 0;
      else if (!strcmp ("try_first_pass", argv[i]))
	return 1;
      else if (argc > 1)
	w4rn ("pam_mount: %s\n", "bad pam_mount option");
    }
  return GETPASS_DEFAULT;
}

/* ============================ pam_sm_open_session () ===================== */
/* PRE:    this function is called by PAM
 * POST:   user's directories are mounted if pam_mount.conf says they should 
 *         be or an error is logged
 * FN VAL: PAM error code on error or PAM_SUCCESS
 * NOTE:   This process's EUID should be set to zero and its UID should be 
 *         set to the user's UID.  This ensures mount command will perform 
 *         sanity checking on the mounts the user wishes to perform, as 
 *         configured in ~/.pam_mount.conf.
 */
PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh, int flags,
		     int argc, const char **argv)
{
  int vol;
  int ret;
  int get_pass;
  w4rn ("pam_mount: %s\n", "beginning");
  /* if our CWD is in the home directory, it might not get umounted */
  /* Needed for KDM.  FIXME: Bug in KDM? */
  if (chdir ("/"))
    w4rn ("pam_mount %s\n", "could not chdir");
  get_pass = pass_type (argc, argv);
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
  initconfig (&config);
  w4rn ("pam_mount: %s\n", "going to readconfig global");
  if (!readconfig (config.user, CONFIGFILE, 1, &config))
    return PAM_SERVICE_ERR;
  w4rn ("pam_mount: %s\n", "back from global readconfig");
  if (exists (config.luserconf) && owns (config.user, config.luserconf))
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
      /* system_password is "" if account has no password */
      if (!mount_op
	  (do_mount, &config, vol, system_password, config.mkmountpoint))
	{
	  w4rn ("pam_mount: %s\n", "mount process failed using use_pass");
	  if (get_pass)
	    {
	      char *passread;
	      /* get the password */
	      if (read_password (pamh, "mount password:", &passread) ==
		  PAM_SUCCESS)
		{
		  /* try with the password read */
		  if (!mount_op
		      (do_mount, &config, vol, passread, config.mkmountpoint))
		    {
		      l0g ("pam_mount: %s\n",
			   "mount process failed using get_pass");
		      return PAM_SERVICE_ERR;
		    }
		}
	      else
		{
		  l0g ("pam_mount: %s\n", "error trying to read password");
		  return PAM_SERVICE_ERR;
		}
	    }
	}
    }
  /* Paranoia? */
  memset (system_password, 0x00, MAX_PAR + 1);
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
    {
      w4rn ("pam_mount: %s\n", "volcount is zero");
    }
  if (modify_pm_count (config.user, -1) <= 0)
    /* Unmount in reverse order to facilitate nested mounting. */
    for (vol = config.volcount - 1; vol >= 0; vol--)
      {
	w4rn ("pam_mount: %s\n", "going to unmount");
	if (!mount_op (do_unmount, &config, vol, NULL, config.mkmountpoint))
	  {
	    l0g ("pam_mount:%s\n", "could not umount");
	    freeconfig (config);
	    return PAM_SERVICE_ERR;
	  }
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
