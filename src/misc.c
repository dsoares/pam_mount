#include <config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <security/pam_modules.h>

extern int debug;

/* ============================ l0g () ===================================== */
/* PRE:  format points to a valid string != NULL
 *       args point to valid strings != NULL
 * POST: format + args are logged and displayed */
void
l0g (const char *format, ...)
{
  /* Used to log issues that cause pam_mount to fail. */
  va_list args;
  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);
  va_start (args, format);
  vsyslog (LOG_AUTHPRIV | LOG_ERR, format, args);
  va_end (args);
}

/* ============================ w4rn () ==================================== */
/* PRE:  format points to a valid string != NULL
 *       args point to valid strings != NULL
 * POST: format + args are logged and displayed iff debug == 1
 * NOTE: Used to log informational messages and issues that should not cause
 *       pam_mount to fail. */
void
w4rn (const char *format, ...)
{
  if (debug)
    {
      va_list args;
      va_start (args, format);
      vfprintf (stderr, format, args);
      va_end (args);
      va_start (args, format);
      vsyslog (LOG_USER | LOG_ERR, format, args);
      va_end (args);
    }
}

/* ============================ exists () ================================== */
/* PRE:    file points to a valid string != NULL
 * FN VAL: 0 if file does not exist, -1 if file is a symlink, or 1 if file 
 *         is normal and exists */
int
exists (const char *file)
{
  struct stat filestat;
  if (stat (file, &filestat))
    {
      return 0;
    }
  if (S_ISLNK (filestat.st_mode))
    {
      return -1;
    }
  return 1;
}

/* ============================ owns () ==================================== */
/* PRE:    user points to a valid string != NULL
 *         file points to a valid string != NULL
 * FN VAL: 0 if user does not own file or 1 if user owns file */
int
owns (const char *user, const char *file)
{
  struct stat filestat;
  struct passwd *userinfo;

  userinfo = getpwnam (user);
  if (!userinfo)
    {
      l0g ("pam_mount: user %s could not be translated to UID\n", user);
      return 0;
    }

  if (stat (file, &filestat))
    {
      w4rn ("pam_mount: file %s could not be stat'ed\n", file);
      return 0;
    }

  if ((filestat.st_uid == userinfo->pw_uid) && !S_ISLNK (filestat.st_mode))
    return 1;
  return 0;
}

/* ============================ converse () ================================ */
/* PRE:    pamh points to a valid pam_handle_t structure
 *         nargs >= 0
 * POST:   response points to a structure containing PAM's (user's)
 *         response to message
 * FN VAL: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c */
static int
converse (pam_handle_t * pamh, int nargs,
	  const struct pam_message **message, struct pam_response **response)
{
  int retval;
  struct pam_conv *conv;
  retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
  if (retval == PAM_SUCCESS)
    retval = conv->conv (nargs, message, response, conv->appdata_ptr);
  return retval;		/* propagate error status */
}

/* ============================ read_password () =========================== */
/* PRE:    pamh points to a valid pam_handle_t structure
 *         prompt points to a valid string != NULL
 * POST:   pass points to a malloc'ed copy of the volume password
 * FN VAL: any PAM error code encountered or PAM_SUCCESS
 * NOTE:   adapted from pam_unix/support.c (_unix_read_password)
 */
int
read_password (pam_handle_t * pamh, char *prompt1, char **pass)
/* FIXME: take a close look at this logic for correctness */
{
  int retval;
  w4rn ("pam_mount: %s\n", "enter read_password");
  struct pam_message msg;
  const struct pam_message *pmsg = &msg;
  struct pam_response *resp = NULL;
  *pass = NULL;
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg = prompt1;
  retval = converse (pamh, 1, &pmsg, &resp);
  if (resp != NULL)
    {
      if (retval == PAM_SUCCESS)
	  *pass = strdup (resp->resp);
    }
  return retval;
}
