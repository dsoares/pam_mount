#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <security/_pam_macros.h>
#ifdef HAVE_LIBSSL
#include <openssl/evp.h>
#endif				/* HAVE_LIBSSL */
#include <pam_mount.h>

struct data_t data;
void sigchld(int arg);
void signal_handler(int arg);
void config_signals();

extern pm_command_t command;

int debug;

#ifdef HAVE_LIBSSL
/* ============================ read_salt () =============================== */
/* PRE:    fp points to a valid BIO structure
 *         salt points to an array of size PKCS5_SALT_LEN
 * POST:   salt contains the salt used to encrypt fp
 * FN VAL: if error 0 else 1, errors are logged */
int read_salt(BIO * fp, unsigned char *salt)
/* sizeof salt must be == PKCS5_SALT_LEN and must fp point to an open file */
{
    char magic[8];
    if ((BIO_read(fp, magic, sizeof magic) != sizeof magic)
	|| (BIO_read(fp, salt, PKCS5_SALT_LEN) != PKCS5_SALT_LEN)) {
	log("pmhelper: %s\n",
	    "error reading from ecrypted filesystem key");
	return 0;
    } else if (memcmp(magic, "Salted__", sizeof "Salted__" - 1)) {
	log("pmhelper: %s\n",
	    "magic string Salted__ not in filesystem key file");
	return 0;
    }
    return 1;
}
#endif				/* HAVE_LIBSSL */

/* ============================ decrypted_key () =========================== */
/* PRE:    pt_fs_key points to an array, large enough to hold fsk
 *         pt_fs_key_len = sizeof (pt_fs_key array)
 *         password points to a valid string != NULL, should unlock efsk
 *         fs_key_cipher = D, where D_password(efsk) = fsk
 * POST:   pt_fs_key points to fsk
 * FN VAL: if error 0 else 1, errors are logged
 * NOTE:   efsk = encrypted filesystem key (stored in filesystem)
 *         fsk = filesystem key (D(efsk)) */
int decrypted_key(char *pt_fs_key, int pt_fs_key_len, char *password,
		  char *fs_key_cipher, char *fs_key_path)
{
#ifdef HAVE_LIBSSL
    int outlen, tmplen;
    unsigned char ct_fs_key[BUFSIZ + 1];	/* encrypted filesystem key. */
    unsigned char hashed_key[EVP_MAX_KEY_LENGTH];
    /* The one used to encrypt filesystem 
     * key -- hash(system_key). */
    BIO *fs_key_fp;
    unsigned char salt[PKCS5_SALT_LEN];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX ctx;

    OpenSSL_add_all_ciphers();
    if (!(cipher = EVP_get_cipherbyname(fs_key_cipher))) {
	log("pmhelper: error getting cipher \"%s\"\n", fs_key_cipher);
	return 0;
    }

    if (!(fs_key_fp = BIO_new(BIO_s_file()))) {
	log("pmhelper: %s\n", "error creating new BIO");;
	return 0;
    }
    if (BIO_read_filename(fs_key_fp, fs_key_path) <= 0) {
	log("pmhelper: error opening %s\n", fs_key_path);
	return 0;
    }
    if (!read_salt(fs_key_fp, salt))
	return 0;
    if (BIO_read(fs_key_fp, ct_fs_key, BUFSIZ) <= 0) {
	log("pmhelper: failed to read encrypted filesystem key from %s\n",
	    fs_key_path);
	return 0;
    }
    if (!EVP_BytesToKey
	(cipher, EVP_md5(), salt, password, strlen(password), 1,
	 hashed_key, iv)) {
	log("pmhelper: %s\n", "failed to hash system password");
	return 0;
    }

    if (!EVP_DecryptInit(&ctx, cipher, hashed_key, iv)) {
	log("pmhelper: %s\n", "failed to initialize decryption code");
	return 0;
    }
    memset(pt_fs_key, 0x00, pt_fs_key_len);
    if (!EVP_DecryptUpdate
	(&ctx, pt_fs_key, &outlen, ct_fs_key, strlen(ct_fs_key))) {
	/* FIXME: docs seem to imply last arg should be 
	 * MAX_PAR - EVP_MAX_IV_LENGTH + 2 (see below).  this causes 
	 * EVP_DecryptUpdate to fail.  strlen(ct_fs_key) is 40 and works.  
	 * 39 and 41 fail.  ???
	/* Fn. will decrypt no more that inl (last param) + block size - 1 
	 * bytes: k[MP + 1] = (MP - MAX + 2) + MAX - 1 */
	log("pmhelper: %s\n", "failed to decrypt key");
	return 0;
    }
    //if (!EVP_DecryptFinal(&ctx, pt_fs_key + outlen, &tmplen)) {
    if (!EVP_DecryptFinal(&ctx, pt_fs_key + outlen, &tmplen)) {
	log("pmhelper: %s\n", "failed to finish decrypting key");
	return 0;
    }
    memset (&ctx, 0x00, sizeof(EVP_CIPHER_CTX));
    /* w4rn("pmhelper: decrypted filesystem key is \"%s\"\n", pt_fs_key); */
    BIO_free(fs_key_fp);
    return 1;
#else
    log("pmhelper: %s\n",
	"encrypted filesystem key not supported: no openssl");
    return 0;
#endif				/* HAVE_LIBSSL */
}

/* ============================ read_fstab_mountpoint () =================== */
/* PRE:    volume points to a valid string != NULL
 *         mountpoint points to a char array of length >= BUFSIZ + 1
 * POST:   mountpoint is mp of volume as listed in fstab
 * FN VAL: if error 0 else 1, errors are logged  */
int get_fstab_mountpoint(char *volume, char *mountpoint)
{
    FILE *fstab;
    struct mntent *fstab_record;
    if (!(fstab = fopen("/etc/fstab", "r"))) {
	log("pmhelper: could not open fstab to determine mount point for %s\n", volume);
	return 0;
    }
    fstab_record = getmntent(fstab);
    while (fstab_record && strcmp(fstab_record->mnt_fsname, volume))
	fstab_record = getmntent(fstab);
    if (! fstab_record) {
	log("pmhelper: could not determine mount point for %s\n", volume);
        return 0;
    }
    if (strlen(fstab_record->mnt_dir) > BUFSIZ) {
	log("pmhelper: mnt point listed in /etc/fstab for %s too long", volume);
        return 0;
    }
    strcpy(mountpoint, fstab_record->mnt_dir);
    return 1;
}

/* ============================ run_lsof () ================================ */
/* NOTE: this fn simply runs lsof on a directory and logs its output for
 *       debugging purposes */
void run_lsof(void)
{
    int pid, pipefds[2];
    if (pipe(pipefds) < 0) {
	log("pmhelper: %s\n", "failed to create pipe for lsof");
    } else {
	if ((pid = fork()) < 0) {
	    log("pmhelper: %s\n", "fork failed for lsof");
	} else {
	    if (pid == 0) {
		close(1);
		dup(pipefds[1]);
		close(pipefds[1]);
		close(pipefds[0]);
		execl(data.lsof, "lsof", data.mountpoint, NULL);
		/* should not reach next instruction */
		w4rn("pmhelper: failed to execl %s\n", data.lsof);
	    } else {
		FILE *fp;
		char buf[BUFSIZ + 1];
		close(pipefds[1]);
		fp = fdopen(pipefds[0], "r");
		w4rn("pmhelper: lsof output (should be empty)...\n",
		     strerror(errno));
		sleep(1);	/* FIXME: need to find a better way to 
		                 * wait for child to catch up. */
		while (fgets(buf, BUFSIZ, fp) != NULL)
		    w4rn("pmhelper: %s\n", buf);
		close(pipefds[0]);
	    }
	}
    }
}

/* ============================ unmount_volume () ========================== */
/* FN VAL: if error 0 else 1, errors are logged */
int unmount_volume()
{
    int i;
    char *cmdarg[4];
    /* Need to unmount mount point not volume to support SMB mounts, etc. */
    cmdarg[0] = data.ucommand;
    cmdarg[1] = "umount";
    cmdarg[2] = data.mountpoint;
    cmdarg[3] = NULL;
    for (i = 0; cmdarg[i]; i++) {
	w4rn("pmhelper: arg is: %s\n", cmdarg[i]);
    }
    if (setuid(0) == -1)
	w4rn("pmhelper: %s\n", "could not set uid to 0");
    if (debug)
	/* Often, a process still exists with ~ as its pwd after logging out.  
	 * Running lsof helps debug this.
	 */
	run_lsof();
    execv(cmdarg[0], &cmdarg[1]);
    /* should not reach next instruction */
    log("pmhelper: %s\n", "failed to execv umount command");
    return 0;
}

/* ============================ mkmountpoint () ============================ */
/* PRE:    data.user and data.mountpoint are valid strings != NULL
 * FN VAL: if error 0 else 1, errors are logged */
int mkmountpoint(data_t data)
{
    struct passwd *passwd_ent;
    if ((passwd_ent = getpwnam(data.user))) {
	w4rn("pam_mount: creating mount %s\n", data.mountpoint);
	if (mkdir(data.mountpoint, 0700) != 0) {
	    log("pam_mount: tried to create %s but failed\n",
		data.mountpoint);
	    return 0;
	}
	if (chown(data.mountpoint, passwd_ent->pw_uid, passwd_ent->pw_gid)
	    != 0) {
	    log("pam_mount: could not chown homedir to %s\n", data.user);
	    return 0;
	}
    } else {
	log("pam_mount: could not determine uid from %s to make homedir\n",
	    data.user);
	return 0;
    }
    return 1;
}

/* ============================ already_mounted () ========================= */ 
/* PRE:    volume points to a valid string != NULL
 *         mountpoint points to a valid string != NULL 
 *           (will be looked up in /etc/fstab if == "")
 * FN VAL: 1 is volume is mounted at mountpoint else 0 
 *           FIXME: calls exit() on error */
int already_mounted(char *volume, char *mountpoint)
{
    FILE *mtab;
    struct mntent *mtab_record;
    char line[BUFSIZ + 1];
    if (!(mtab = fopen("/etc/mtab", "r"))) {
        log("pmhelper: %s\n", "could not open /etc/mtab");
	exit(EXIT_FAILURE);
    }
    mtab_record = getmntent(mtab);
    while (mtab_record && strcmp(mtab_record->mnt_fsname, volume))
	mtab_record = getmntent(mtab);
    return mtab_record ? ! strcmp(mtab_record->mnt_dir, mountpoint) : 0;
}

/* ============================ main () ==================================== */
/* NOTE: expects to read a data_t structure from stdin which determines what
 *       is mounted or unmounted and how. */
int main(int argc, char **argv)
{
    int total = 0, n;
    char *_argv[MAX_PAR+1];
    int _argc;
    int child;
    int fds[2];
    int child_exit;
    int i;
    int mntpt_from_fstab = 0;

    debug = getenv("PAM_MOUNT_DEBUG") ? 1 : 0;

    w4rn("pmhelper: %s\n", "I am executing");

    memset(&data, 0x00, sizeof(data_t));

    config_signals();

    while (total < sizeof(data_t)) {
	n = read(0, ((char *) &data) + total, sizeof(data) - total);
	if (n <= 0) {
	    log("pmhelper: %s\n", "failed to receive mount data");
	    exit(EXIT_FAILURE);
	}
	total += n;
    }
    if (total != sizeof(data_t)) {
	log("pmhelper: %s\n", "failed to receive all mount data");
	exit(EXIT_FAILURE);
    }
    if (! strlen(data.mountpoint)) {
        if (! get_fstab_mountpoint(data.volume, data.mountpoint)) {
	    exit(EXIT_FAILURE);
	}
	mntpt_from_fstab = 1;
    }
    for(_argc = 0; strlen(data.argv[_argc]); _argc++) {
        if (_argc >= MAX_PAR + 1) {
	    log("pmhelper: %s\n", "mount command line too long");
	    exit(EXIT_FAILURE);
        }
	_argv[_argc] = data.argv[_argc];
    }

    w4rn("pmhelper: %s\n", "received");
    w4rn("pmhelper: %s\n", "--------");
    /* w4rn("pmhelper: %s\n", data.password); */
    w4rn("pmhelper: %s\n", data.globalconf ? "(defined by globalconf)" : "(defined by luserconf)");
    w4rn("pmhelper: user:          %s\n", data.user);
    w4rn("pmhelper: server:        %s\n", data.server);
    w4rn("pmhelper: volume:        %s\n", data.volume);
    w4rn("pmhelper: mountpoint:    %s\n", data.mountpoint);
    w4rn("pmhelper: options:       %s\n", data.options);
    w4rn("pmhelper: fs_key_cipher: %s\n", data.fs_key_cipher);
    w4rn("pmhelper: fs_key_path:   %s\n", data.fs_key_path);
    w4rn("pmhelper: %s", "argv:          ");
    for(i = 0; strlen (data.argv[i]); i++)
        w4rn("%s ", data.argv[i]);
    w4rn("%s", "\n");
    w4rn("pmhelper: %s\n", "--------");

    sleep(1);

    if (data.unmount) {
	w4rn("pmhelper: %s\n", "unmounting");
	if (!unmount_volume())	/* FIXME: Should not return (exec) -- 
				 * clean logic */
	    exit(EXIT_FAILURE);
    }

    if (already_mounted(data.volume, data.mountpoint)) {
        log("pmhelper: %s already seems to be mounted, skipping", data.volume);
	exit(EXIT_SUCCESS); /* success so try_first_pass does not try again */
    }

    w4rn("pmhelper: %s\n", "checking for encrypted filesystem key configuration");

    /* FIXME: Should this be rmdir'ed when one logs out? How? */
    if (getenv("PAM_MOUNT_MKMOUNTPOINT") && !exists(data.mountpoint))
	if (!mkmountpoint(data))
	    exit(EXIT_FAILURE);
    if (strlen(data.fs_key_cipher)) {
	char k[MAX_PAR + 1];
	w4rn("pmhelper: %s\n",
	     "decrypting FS key using system auth. token...");
	/* data.fs_key_path contains real filesystem key. */
	if (!decrypted_key
	    (k, sizeof(k), data.password, data.fs_key_cipher,
	     data.fs_key_path))
	    exit(EXIT_FAILURE);
	memset(data.password, 0x00, MAX_PAR + 1);
	strncpy(data.password, k, MAX_PAR + 1);
    }

    w4rn("pmhelper: %s\n", "about to start building mount command");

    /* FIXME: overflow possibility on _argv (users can define commands) */
    if (data.type == NCPMOUNT) {
        w4rn("pmhelper: %s\n", "mount type is NCPMOUNT");
	_argv[_argc++] = "-S";
	_argv[_argc++] = data.server;
	_argv[_argc++] = "-U";
	_argv[_argc++] = data.user;
	_argv[_argc++] = "-V";
	_argv[_argc++] = data.volume;
	_argv[_argc++] = data.mountpoint;
    } else if (data.type == SMBMOUNT) {
        w4rn("pmhelper: %s\n", "mount type is SMBMOUNT");
	asprintf(&_argv[_argc++], "//%s/%s", data.server, data.volume);
	w4rn("pmhelper: added %s\n", _argv[_argc - 1]);
	_argv[_argc++] = data.mountpoint;
	w4rn("pmhelper: added %s\n", _argv[_argc - 1]);
	_argv[_argc++] = "-o";
	w4rn("pmhelper: added %s\n", _argv[_argc - 1]);
	asprintf(&_argv[_argc++], "username=%s%s%s",
		 data.user, data.options[0] ? "," : "", data.options);
	w4rn("pmhelper: added %s\n", _argv[_argc - 1]);
    } else if (data.type == LCLMOUNT) {
        w4rn("pmhelper: %s\n", "mount type is LCLMOUNT");
	_argv[_argc++] = data.volume;

	if (! mntpt_from_fstab)
	    _argv[_argc++] = data.mountpoint;
	if (data.options[0]) {
	    _argv[_argc++] = "-o";
	    _argv[_argc++] = data.options;
	}
    } else {
	log("pmhelper: %s\n", "data.type is unknown");
	exit(EXIT_FAILURE);
    }

    _argv[_argc++] = NULL;

    if (pipe(fds) != 0) {
	log("pmhelper: %s\n", "could not make pipe");
	exit(EXIT_FAILURE);
    }

    w4rn("pmhelper: %s\n", "about to fork");
    child = fork();
    if (child == -1) {
	log("pmhelper: %s\n", "failed to fork");
	exit(EXIT_FAILURE);
    }

    if (child == 0) {
	w4rn("pmhelper: %s\n", "pmhelper CHILD executing");
	/* This is the child */

	close(fds[1]);
	dup2(fds[0], STDIN_FILENO);
	if (setuid(0) == -1)
	    w4rn("pmhelper: %s\n", "could not set uid to 0");
	argv[i] = NULL;
	for (i = 0; _argv[i]; i++)
	    w4rn("pmhelper: arg is: %s\n", _argv[i]);
	execv(_argv[0], _argv + 1);

	/* should not reach next instruction */
	log("pmhelper: %s\n", "failed to execv mount command");
	exit(EXIT_FAILURE);
    }

    /* send password down pipe to mount process */
    write(fds[1], data.password, strlen(data.password) + 1);
    close(fds[0]);
    close(fds[1]);

    _pam_overwrite(data.password);

    w4rn("pmhelper: %s\n", "waiting for homedir mount");
    waitpid(child, &child_exit, 0);

    /* pass on through the result from the mount process */
    exit (WEXITSTATUS(child_exit));
}

/* ============================ config_signals () ========================== */
void config_signals()
{
    signal(SIGCHLD, sigchld);
    /* Pipe will be eventually closed by parent but we don't mind */
    signal(SIGPIPE, SIG_IGN);
}

/* ============================ sigchild () ================================ */
void sigchld(int arg)
{
    wait((int *) NULL);
    config_signals();
}
