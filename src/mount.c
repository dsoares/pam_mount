#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <fstab.h>
#elif defined(__linux__)
#include <mntent.h>
#endif
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#endif /* HAVE_LIBCRYPTO */
#include <pam_mount.h>

extern int debug;

#ifdef HAVE_LIBCRYPTO
/* ============================ read_salt () =============================== */
/*
 * PRE:    fp points to a valid FILE *
 *         salt points to an array of size PKCS5_SALT_LEN
 * POST:   salt contains the salt used to encrypt fp
 * FN VAL: if error 0 else 1, errors are logged
 */
static int
read_salt (FILE * fp, unsigned char *salt)
{
  char magic[8];
  if ((fread (magic, 1, sizeof magic, fp) != sizeof magic)
      || (fread (salt, 1, PKCS5_SALT_LEN, fp) != PKCS5_SALT_LEN))
    {
      l0g ("pam_mount: %s\n", "error reading from ecrypted filesystem key");
      return 0;
    }
  else if (memcmp (magic, "Salted__", sizeof "Salted__" - 1))
    {
      l0g ("pam_mount: %s\n",
	   "magic string Salted__ not in filesystem key file");
      return 0;
    }
  return 1;
}
#endif /* HAVE_LIBCRYPTO */

/* ============================ decrypted_key () =========================== */
/*
 * PRE:    pt_fs_key points to an array, large enough to hold fsk (MAX_PAR + 1)
 *         pt_fs_key_len points to a valid int
 *         key points to a valid string != NULL, should unlock efsk
 *         fs_key_cipher = D, where D_key(efsk) = fsk
 * POST:   pt_fs_key points to fsk
 *         *pt_fs_key_len is the length of pt_fs_key
 * FN VAL: if error 0 else 1, errors are logged
 * NOTE:   efsk = encrypted filesystem key (stored in filesystem)
 *         fsk = filesystem key (D(efsk))
 *         pt_fs_key will contain binary data; don't use strlen, strcpy, etc.
 *         pt_fs_key may contain trailing garbage; use pt_fs_key_len
 */
static int
decrypted_key (char *pt_fs_key, int *pt_fs_key_len, const char *key,
	       const char *fs_key_cipher, const char *fs_key_path)
{
#ifdef HAVE_LIBCRYPTO
  int scratch;
  unsigned char ct_fs_key[MAX_PAR + 1];	/* encrypted filesystem key. */
  int ct_fs_key_len;
  unsigned char hashed_key[EVP_MAX_KEY_LENGTH]; /* hash(key) */
  FILE *fs_key_fp;
  unsigned char salt[PKCS5_SALT_LEN];
  unsigned char iv[EVP_MAX_IV_LENGTH];
  const EVP_CIPHER *cipher;
  EVP_CIPHER_CTX ctx;
  OpenSSL_add_all_ciphers ();
  if (!(cipher = EVP_get_cipherbyname (fs_key_cipher)))
    {
      l0g ("pam_mount: error getting cipher \"%s\"\n", fs_key_cipher);
      return 0;
    }
  if ((fs_key_fp = fopen (fs_key_path, "r")) <= 0)
    {
      l0g ("pam_mount: error opening %s\n", fs_key_path);
      return 0;
    }
  if (!read_salt (fs_key_fp, salt))
    return 0;
  if (!EVP_BytesToKey
      (cipher, EVP_md5 (), salt, key, strlen (key), 1, hashed_key, iv))
    {
      l0g ("pam_mount: %s\n", "failed to hash system password");
      return 0;
    }
  /* ct_fs_key is MAX_PAR + 1 bytes and binary data has not 0x00 terminator */
  if ((ct_fs_key_len = fread (ct_fs_key, 1, MAX_PAR + 1, fs_key_fp)) <= 0)
    {
      l0g ("pam_mount: failed to read encrypted filesystem key from %s\n",
	   fs_key_path);
      return 0;
    }
  EVP_CIPHER_CTX_init (&ctx);
  if (!EVP_DecryptInit (&ctx, cipher, hashed_key, iv))
    {
      l0g ("pam_mount: %s\n", "failed to initialize decryption code");
      return 0;
    }
  /* assumes plaintexts is always <= ciphertext in length */
  if (!EVP_DecryptUpdate
      (&ctx, pt_fs_key, pt_fs_key_len, ct_fs_key, ct_fs_key_len))
    {
      l0g ("pam_mount: %s\n", "failed to decrypt key");
      return 0;
    }
  if (!EVP_DecryptFinal (&ctx, pt_fs_key, &scratch))
    {
      l0g ("pam_mount: %s\n", "bad pad on end of encrypted file");
      return 0;
    }
  EVP_CIPHER_CTX_cleanup (&ctx);
  fclose (fs_key_fp);
  return 1;
#else
  l0g ("pam_mount: %s\n",
       "encrypted filesystem key not supported: no openssl");
  return 0;
#endif /* HAVE_LIBCRYPTO */
}

/* ============================ read_fstab_mountpoint () =================== */
/*
 * PRE:    volume points to a valid string != NULL
 *         mountpoint points to a char array of length >= FILENAME_MAX + 1
 * POST:   mountpoint is mp of volume as listed in fstab
 * FN VAL: if error 0 else 1, errors are logged
 */
static int
get_fstab_mountpoint (const char *volume, char *mountpoint)
{
#if defined (__FreeBSD__) || defined (__OpenBSD__)
  struct fstab *fstab_record;
  if (!setfsent ())
    {
      l0g
	("pam_mount: could not open fstab to determine mount point for %s\n",
	 volume);
      return 0;
    }
  if (!(fstab_record = getfsspec (volume)))
    {
      l0g ("pam_mount: could not determine mount point for %s\n", volume);
      return 0;
    }
  if (strlen (fstab_record->fs_file) > FILENAME_MAX)
    {
      l0g ("pam_mount: mnt point listed in /etc/fstab for %s too long",
	   volume);
      return 0;
    }
  strncpy (mountpoint, fstab_record->fs_file, FILENAME_MAX);
  mountpoint[FILENAME_MAX] = 0x00;
  return 1;
#elif defined(__linux__)
  FILE *fstab;
  struct mntent *fstab_record;
  if (!(fstab = fopen ("/etc/fstab", "r")))
    {
      l0g
	("pam_mount: could not open fstab to determine mount point for %s\n",
	 volume);
      return 0;
    }
  fstab_record = getmntent (fstab);
  while (fstab_record && strcmp (fstab_record->mnt_fsname, volume))
    fstab_record = getmntent (fstab);
  if (!fstab_record)
    {
      l0g ("pam_mount: could not determine mount point for %s\n", volume);
      return 0;
    }
  if (strlen (fstab_record->mnt_dir) > FILENAME_MAX)
    {
      l0g ("pam_mount: mnt point listed in /etc/fstab for %s too long",
	   volume);
      return 0;
    }
  strncpy (mountpoint, fstab_record->mnt_dir, FILENAME_MAX);
  mountpoint[FILENAME_MAX] = 0x00;
  return 1;
#else
  /* FIXME */
  l0g ("pam_mount: %s\n", "reading fstab not implemented on arch.");
  return 0;
#endif
}

/* ============================ run_lsof () ================================ */
/*
 * NOTE: this fn simply runs lsof on a directory and logs its output for
 * debugging purposes
 */
static void
run_lsof (const struct config_t *config, const int vol)
{
  int pipefds[2];
  pid_t pid;
  PIPE (pipefds);
  if ((pid = fork ()) < 0)
    {
      l0g ("pam_mount: %s\n", "fork failed for lsof");
    }
  else
    {
      if (pid == 0)
	{
	  CLOSE (1);
	  dup (pipefds[1]);
	  CLOSE (pipefds[1]);
	  CLOSE (pipefds[0]);
	  execl (config->command[0][LSOF], "lsof",
		 config->volume[vol].mountpoint, NULL);
	  l0g
	    ("pam_mount: failed to exec lsof command (%s) (check pam_mount.conf?)\n",
	     config->command[0][LSOF]);
	  exit (EXIT_FAILURE);
	}
      else
	{
	  FILE *fp;
	  char buf[BUFSIZ + 1];
	  CLOSE (pipefds[1]);
	  fp = fdopen (pipefds[0], "r");
	  w4rn ("pam_mount: lsof output (should be empty)...\n",
		strerror (errno));
	  while (fgets (buf, BUFSIZ, fp) != NULL)
	    w4rn ("pam_mount: %s\n", buf);
	  CLOSE (pipefds[0]);
	}
    }
}

/* ============================ exec_unmount_volume () ===================== */
/* FN VAL: if error 0 else 1, errors are logged */
static void
exec_unmount_volume (struct config_t *config, const int vol)
/*
 * PRE:    config->volume[vol].mountpoint points to a valid string
 * POST:   umount config->volume[vol].mountpoint is executed
 * FN VAL: should never return
 */
{
  w4rn ("pam_mount: unmount arg is %s\n", config->volume[vol].mountpoint);
  if (debug)
    /*
     * Often, a process still exists with ~ as its pwd after
     * logging out.  Running lsof helps debug this.
     */
    run_lsof (config, vol);
  /*
   * setuid 0 since Linux umount balks at euid of 0, uid != 0. I think
   * this is safe because volume and mount point must be owned by user
   * if mount is defined in ~/.pam_mount.
   */
  if (setuid (0) == -1)
    w4rn ("pam_mount: %s\n", "error setting uid to 0");
  /* Need to unmount mount point not volume to support SMB mounts, etc. */
  execl (config->command[0][UMOUNT], "umount", config->volume[vol].mountpoint,
	 NULL);
  l0g
    ("pam_mount: failed to exec umount command (%s) (check pam_mount.conf?)\n",
     config->command[0][UMOUNT]);
  exit (EXIT_FAILURE);
}

/* ============================ mkmountpoint () ============================ */
/*
 * PRE:    volume.user and volume.mountpoint are valid strings != NULL
 * FN VAL: if error 0 else 1, errors are logged
 */
static int
mkmountpoint (vol_t * volume)
{
  struct passwd *passwd_ent;
  if ((passwd_ent = getpwnam (volume->user)))
    {
      w4rn ("pam_mount: creating mount %s\n", volume->mountpoint);
      if (mkdir (volume->mountpoint, 0700) != 0)
	{
	  l0g ("pam_mount: tried to create %s but failed\n",
	       volume->mountpoint);
	  return 0;
	}
      if (chown (volume->mountpoint, passwd_ent->pw_uid, passwd_ent->pw_gid)
	  != 0)
	{
	  l0g ("pam_mount: could not chown homedir to %s\n", volume->user);
	  return 0;
	}
    }
  else
    {
      l0g ("pam_mount: could not determine uid from %s to make homedir\n",
	   volume->user);
      return 0;
    }
  volume->created_mntpt = 1;
  return 1;
}

/* ============================ already_mounted () ========================= */
/*
 * PRE:    config->volume[vol].type is a mount type (LCLMOUNT, SMBMOUNT, ...)
 *         config->volume[vol].volume points to a valid string != NULL
 *         config->volume[vol].server points to a valid string != NULL
 *         config->volume[vol].mountpoint points to a valid string != NULL
 *         (will be looked up in /etc/fstab if == "")
 * FN VAL: 1 if volume is mounted at mountpoint else 0
 * NOTE:   0 can also mean, "unable to figure it out."
 */
static int
already_mounted (struct config_t *config, const int vol)
{
  char match[PATH_MAX + 1];
#if defined(__linux__)
  FILE *mtab;
  struct mntent *mtab_record;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
  int pipefds[2];
  pid_t pid;
#endif
  memset (match, 0x00, sizeof (match));
  if (config->volume[vol].type == SMBMOUNT)
    {
      strcpy (match, "//");
      strncat (match, config->volume[vol].server, PATH_MAX - strlen (match));
      strncat (match, "/", PATH_MAX - strlen (match));
      strncat (match, config->volume[vol].volume, PATH_MAX - strlen (match));
    }
  else if (config->volume[vol].type == CIFSMOUNT)
    {
      strncpy (match, config->volume[vol].server, PATH_MAX - strlen (match));
      strncat (match, "/", PATH_MAX - strlen (match));
      strncat (match, config->volume[vol].volume, PATH_MAX - strlen (match));
    }
  else if (config->volume[vol].type == NCPMOUNT)
    {
      strncpy (match, config->volume[vol].server, PATH_MAX - strlen (match));
      strncat (match, "/", PATH_MAX - strlen (match));
      strncat (match, config->volume[vol].volume, PATH_MAX - strlen (match));
    }
  else
    {
      strncpy (match, config->volume[vol].volume, PATH_MAX);
    }
#if defined(__linux__)
  if (!(mtab = fopen ("/etc/mtab", "r")))
    {
      l0g ("pam_mount: %s\n", "could not open /etc/mtab");
      return 0;
    }
  mtab_record = getmntent (mtab);
  w4rn ("pam_mount: checking to see if %s is already mounted\n", match);
  while (mtab_record && strcmp (mtab_record->mnt_fsname, match)
	 && strcmp (mtab_record->mnt_dir, config->volume[vol].mountpoint))
    /* must handle multiple users mounting same volume. */
    mtab_record = getmntent (mtab);
  return mtab_record ? !strcmp (mtab_record->mnt_dir,
				config->volume[vol].mountpoint) : 0;
#elif defined(__FreeBSD__) || defined(__OpenBSD__)
  /*
   * FIXME: I'm not overly fond of using mount, but BSD has no
   * /etc/mtab?
   */
  PIPE (pipefds);
  if ((pid = fork ()) < 0)
    {
      l0g ("pam_mount: %s\n", "fork failed for mntcheck");
      return 0;			/* (I don't know) */
    }
  else
    {
      if (pid == 0)
	{
	  CLOSE (1);
	  dup (pipefds[1]);
	  CLOSE (pipefds[1]);
	  CLOSE (pipefds[0]);
	  execl (config->command[0][MNTCHECK], "mount", NULL);
	  l0g
	    ("pam_mount: failed to exec mntcheck command (%s) (check pam_mount.conf?)\n",
	     config->command[0][MNTCHECK]);
	  exit (EXIT_FAILURE);
	}
      else
	{
	  FILE *fp;
	  char dev[BUFSIZ + 1];
	  CLOSE (pipefds[1]);
	  fp = fdopen (pipefds[0], "r");
	  while (fgets (dev, BUFSIZ, fp) != NULL)
	    {
	      /*
	       * FIXME: A bit ugly but
	       * works.
	       */
	      char *mntpt, *trash;
	      w4rn ("pam_mount: mounted filesystem: %s", dev);	/* dev includes '\n' */
	      trash = strchr (dev, ' ');
	      if (!trash)
		return 0;	/* parse err */
	      *trash = 0x00;
	      mntpt = strchr (trash + 1, ' ');
	      if (!mntpt++)
		return 0;	/* parse err */
	      trash = strchr (mntpt, ' ');
	      if (!trash)
		return 0;	/* parse err */
	      *trash = 0x00;
	      if (!strcmp (dev, match)
		  && !strcmp (mntpt, config->volume[vol].mountpoint))
		return 1;
	    }
	  CLOSE (pipefds[0]);
	  return 0;
	}
    }
#else
  /* FIXME */
  l0g ("pam_mount: %s\n",
       "check for previous mount not implemented on arch.");
  return 0;
#endif
}

/* ============================ add_to_argv () ============================= */
/*
 * PRE:  argv points to an array of MAX_PAR + 1 char *s (incl. term. 0x00)
 *       argc points to the current number of entries in argv
 *       arg points to a valid string != NULL
 * POST: arg has been added to end of argv, which is NULL * terminated
 *       argc++
 * NOTE: this function exits on an error as an error means a buffer
 *       overflow would otherwise have occured
 */
static void
add_to_argv (char *argv[], int *argc, char *arg)
{
  if (*argc == MAX_PAR)
    {
      l0g ("pam_mount: %s\n", "too many arguments to mount command");
      exit (EXIT_FAILURE);
    }
  argv[(*argc)++] = arg;
  argv[*argc] = 0x00;
}

/* ============================ log_pm_input () ============================ */
static void
log_pm_input (const struct config_t *config, const int vol)
{
  int i;
  w4rn ("pam_mount: %s\n", "information for mount:");
  w4rn ("pam_mount: %s\n", "--------");
  w4rn ("pam_mount: %s\n",
	config->volume[vol].
	globalconf ? "(defined by globalconf)" : "(defined by luserconf)");
  w4rn ("pam_mount: user:          %s\n", config->volume[vol].user);
  w4rn ("pam_mount: server:        %s\n", config->volume[vol].server);
  w4rn ("pam_mount: volume:        %s\n", config->volume[vol].volume);
  w4rn ("pam_mount: mountpoint:    %s\n", config->volume[vol].mountpoint);
  w4rn ("pam_mount: options:       %s\n", config->volume[vol].options);
  w4rn ("pam_mount: fs_key_cipher: %s\n", config->volume[vol].fs_key_cipher);
  w4rn ("pam_mount: fs_key_path:   %s\n", config->volume[vol].fs_key_path);
  w4rn ("pam_mount: %s", "mount command:          ");
  for (i = 0; config->command[i][config->volume[vol].type]; i++)
    w4rn ("%s \n", config->command[i][config->volume[vol].type]);
  w4rn ("%s", "\n");
  w4rn ("pam_mount: %s\n", "--------");
}

/* ============================ exec_mount_volume () ======================= */
/*
 * PRE:    fds points to two fds (pipe)
 *         _argv points to a valid, NULL-terminated command array
 * POST:   _argv is executing and has pipe as stdin
 * FN VAL: should never return
 */
static void
exec_mount_volume (const int fds[2], char *_argv[])
{
  int i;
  CLOSE (fds[1]);
  if (dup2 (fds[0], STDIN_FILENO) == -1)
    {
      l0g ("pam_mount: %s\n", "error setting up mount's pipe");
      exit (EXIT_FAILURE);
    }
  for (i = 0; _argv[i]; i++)
    w4rn ("pam_mount: arg is: %s\n", _argv[i]);
  /*
   * setuid 0 since Linux mount balks at euid of 0, uid != 0. I think
   * this is safe because volume and mount point must be owned by user
   * if mount is defined in ~/.pam_mount.
   */
  if (setuid (0) == -1)
    w4rn ("pam_mount: %s\n", "error setting uid to 0");
  execv (_argv[0], &_argv[1]);
  l0g
    ("pam_mount: failed to exec mount command (%s) (check pam_mount.conf?)\n",
     _argv[0]);
  exit (EXIT_FAILURE);
}

/* ============================ do_unmount () ============================== */
int
do_unmount (struct config_t *config, const int vol, const char *password,
	    const int mkmntpoint, const int mntpt_from_fstab)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         password points to a valid string != NULL
 *         mkmountpoint is true if mount point should be rmdir'ed
 *         mntpt_from_fstab is IGNORED
 * POST:   volume is unmounted
 * FN VAL: if error 0 else 1, errors are logged
 */
{
  int child_exit;
  pid_t pid = -1;
  if ((pid = fork ()) < 0)
    {
      l0g ("pam_mount: %s\n", "fork failed for umount");
      return 0;
    }
  if (pid == 0)
    {
      exec_unmount_volume (config, vol);
      exit (EXIT_FAILURE);
    }
  waitpid (pid, &child_exit, 0);
  if (mkmntpoint && config->volume[vol].created_mntpt)
    {
      if (rmdir (config->volume[vol].mountpoint) == -1)	/* non-fatal */
	l0g ("pam_mount: could not remove %s\n",
	     config->volume[vol].mountpoint);
    }
  /* pass on through the result from the umount process */
  return (!WEXITSTATUS (child_exit));
}

/* ============================ do_mount () ================================ */
int
do_mount (struct config_t *config, const int vol, const char *password,
	  const int mkmntpoint, const int mntpt_from_fstab)
/* PRE:    config points to a valid struct config_t*
 *         config->volume[vol] is a valid struct vol_t
 *         password points to a valid string != NULL
 *         mkmntpoint is true if mount point should be mkdir'ed
 *         mntpt_from_fstab is true if mount point was read from fstab,
 *         false if mount point was received from pam_mount
 * POST:   volume is mounted
 * FN VAL: if error 0 else 1, errors are logged
 */
{

  char *_argv[MAX_PAR + 1];
  int _password_len;
  unsigned char _password[MAX_PAR + 1];
  int _argc = 0, fds[2], child_exit = 0;
  pid_t pid = -1;
  if (already_mounted (config, vol))
    {
      l0g ("pam_mount: %s already seems to be mounted, skipping\n",
	   config->volume[vol].volume);
      return 1;			/* success so try_first_pass does not try
				 * again */
    }
  if (!exists (config->volume[vol].mountpoint))
    if (mkmntpoint)
      {
	if (!mkmountpoint (&config->volume[vol]))
	  return 0;
      }
    else
      {
	l0g
	  ("pam_mount: mount point %s does not exist (pam_mount not configured to make it)\n",
	   config->volume[vol].mountpoint);
	return 0;
      }
  w4rn ("pam_mount: %s\n",
	"checking for encrypted filesystem key configuration");
  if (strlen (config->volume[vol].fs_key_cipher))
    {
      /* _password is binary data -- no strlen, strcpy, etc! */
      int password_len;
      w4rn ("pam_mount: decrypting FS key using system auth. token and %s\n",
	    config->volume[vol].fs_key_cipher);
      /*
       * config->volume[vol].fs_key_path contains real filesystem
       * key.
       */
      if (!decrypted_key
	  (_password, &_password_len, password,
	   config->volume[vol].fs_key_cipher,
	   config->volume[vol].fs_key_path))
	return 0;
    }
  else
    {
      /* _password is an ASCII string in this case */
      strncpy (_password, password, MAX_PAR);
      _password[MAX_PAR] = 0x00;
      _password_len = strlen (password);
    }
  w4rn ("pam_mount: %s\n", "about to start building mount command");
  while (config->command[_argc][config->volume[vol].type])
    add_to_argv (_argv, &_argc,
		 config->command[_argc][config->volume[vol].type]);
  if (config->volume[vol].type == NCPMOUNT)
    {
      char *tmp;		/* FIXME: never freed */
      w4rn ("pam_mount: %s\n", "mount type is NCPMOUNT");
      if (asprintf
	  (&tmp, "%s/%s", config->volume[vol].server,
	   config->volume[vol].user) == -1)
	{
	  l0g ("pam_mount: asprintf error: %s\n", strerror (errno));
	  return 0;
	}
      add_to_argv (_argv, &_argc, tmp);
      add_to_argv (_argv, &_argc, config->volume[vol].mountpoint);
      add_to_argv (_argv, &_argc, "-o");
      if (asprintf
	  (&tmp, "pass-fd=0,volume=%s%s%s", config->volume[vol].volume,
	   config->volume[vol].options[0] ? "," : "",
	   config->volume[vol].options) == -1)
	{
	  l0g ("pam_mount: asprintf error: %s\n", strerror (errno));
	  return 0;
	}
      add_to_argv (_argv, &_argc, tmp);
    }
  else if (config->volume[vol].type == SMBMOUNT)
    {
      char *tmp;		/* FIXME: never freed */
      w4rn ("pam_mount: %s\n", "mount type is SMBMOUNT");
      if (asprintf
	  (&tmp, "//%s/%s", config->volume[vol].server,
	   config->volume[vol].volume) == -1)
	{
	  l0g ("pam_mount: asprintf error: %s\n", strerror (errno));
	  return 0;
	}
      add_to_argv (_argv, &_argc, tmp);
      add_to_argv (_argv, &_argc, config->volume[vol].mountpoint);
      add_to_argv (_argv, &_argc, "-o");
      if (asprintf (&tmp, "username=%s%s%s",
		    config->volume[vol].user,
		    config->volume[vol].options[0] ? "," : "",
		    config->volume[vol].options) == -1)
	{
	  l0g ("pam_mount: asprintf error: %s\n", strerror (errno));
	  return 0;
	}
      add_to_argv (_argv, &_argc, tmp);
    }
  else if (config->volume[vol].type == CIFSMOUNT)
    {
      char *tmp;		/* FIXME: never freed */
      w4rn ("pam_mount: %s\n", "mount type is CIFSMOUNT");
      if (asprintf
	  (&tmp, "//%s/%s", config->volume[vol].server,
	   config->volume[vol].volume) == -1)
	{
	  l0g ("pam_mount: asprintf error: %s\n", strerror (errno));
	  return 0;
	}
      add_to_argv (_argv, &_argc, tmp);
      add_to_argv (_argv, &_argc, config->volume[vol].mountpoint);
      add_to_argv (_argv, &_argc, "-o");
      /* FIXME: password should not be given on command line! */
      /* And password may be binary data! */
      if (asprintf
	  (&tmp, "user=%s,pass=%s%s%s", config->volume[vol].user, _password,
	   config->volume[vol].options[0] ? "," : "",
	   config->volume[vol].options) == -1)
	{
	  l0g ("pam_mount: asprintf error: %s\n", strerror (errno));
	  return 0;
	}
      add_to_argv (_argv, &_argc, tmp);
    }
  else if (config->volume[vol].type == LCLMOUNT)
    {
      w4rn ("pam_mount: %s\n", "mount type is LCLMOUNT");
      if (config->volume[vol].options[0])
	{
	  add_to_argv (_argv, &_argc, "-o");
	  add_to_argv (_argv, &_argc, config->volume[vol].options);
	}
      add_to_argv (_argv, &_argc, config->volume[vol].volume);
      if (!mntpt_from_fstab)
	add_to_argv (_argv, &_argc, config->volume[vol].mountpoint);
    }
  else
    {
      l0g ("pam_mount: %s\n", "config->volume[vol].type is unknown");
      return 0;
    }
  PIPE (fds);
  /* send password down pipe to mount process */
  if (config->volume[vol].type == SMBMOUNT)
    setenv ("PASSWD_FD", "0", 1);
  if ((pid = fork ()) < 0)
    {
      l0g ("pam_mount: %s\n", "fork failed for mount");
      return 0;
    }
  if (!pid)
    {
      /* This is the child */
      exec_mount_volume (fds, _argv);
      exit (EXIT_FAILURE);
    }
  write (fds[1], _password, _password_len);
  /* Paranoia? */
  memset (_password, 0x00, MAX_PAR + 1);
  CLOSE (fds[0]);
  CLOSE (fds[1]);
  w4rn ("pam_mount: %s\n", "waiting for homedir mount");
  waitpid (pid, &child_exit, 0);
  /* pass on through the result from the mount process */
  return (!WEXITSTATUS (child_exit));
}

/* ============================ mount_op () ================================ */
/*
 * PRE:    mnt is function to execute mount operations: do_mount or do_unmount
 *         vol > 0
 *         config points to a valid struct config_t
 *         config->volume[vol] is a valid struct vol_t
 *         0 <= config->volume[vol].type < COMMAND_MAX
 *         config->volume[vol].fs_key_cipher points to a valid string (strlen >= 0)
 *         config->volume[vol].fs_key_path points to a valid string *
 *           (strlen must be > 0 if strlen of config->volume[vol].fs_key_cipher > 0)
 *         config->volume[vol].server points to a valid string (strlen >= 0) *
 *           (strlen must be > 0 if mount type is not local)
 *         config->volume[vol].user points to a valid string (strlen > 0) **
 *         config->volume[vol].volume points to a valid string (strlen > 0) **
 *         config->volume[vol].options points to a valid string (strlen >= 0)
 *         config->volume[vol].mountpoint points to a valid string (strlen >= 0)
 *         password points to a valid string (can be NULL if UNmounting)
 *         mkmntpoint is true if mount point should be created when it does
 *         not already exist
 * POST:   appropriate mount or unmount operations are performed
 * FN VAL: if error 0 else 1, errors are logged
 * NOTE:   * checked by volume_record_sane
 *         ** checked by read_volume()
 */
int
mount_op (int (*mnt)
	  (struct config_t * config, const int vol, const char *password,
	   const int mkmntpoint, const int mntpt_from_fstab),
	  struct config_t *config, const int vol, const char *password,
	  const int mkmntpoint)
{

  int mntpt_from_fstab = 0;
  if (debug)
    log_pm_input (config, vol);
  if (!strlen (config->volume[vol].mountpoint))
    {
      if (!get_fstab_mountpoint
	  (config->volume[vol].volume, config->volume[vol].mountpoint))
	{
	  return 0;
	}
      mntpt_from_fstab = 1;
    }
  mnt (config, vol, password, mkmntpoint, mntpt_from_fstab);
  return 1;
}
