#include <config.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <mntent.h>
#ifdef HAVE_LIBSSL
#include <openssl/evp.h>
#endif				/* HAVE_LIBSSL */
#include "pam_mount.h"

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>

struct pm_data data;
void sigchld(int arg);
void signal_handler(int arg);
void config_signals();
void parsecommand(const char *command, const char *name, char ***parg);
void unmount_volume();

int debug;

#ifdef HAVE_LIBSSL
int read_salt(BIO * fp, unsigned char *salt)
/* sizeof salt must be == PKCS5_SALT_LEN and fp point to an open file */
{
    char magic[8];
    if ((BIO_read(fp, magic, sizeof magic) != sizeof magic)
	|| (BIO_read(fp, salt, PKCS5_SALT_LEN) != PKCS5_SALT_LEN)) {
	log("pmhelper: %s", "error reading from ecrypted filesystem key");
	return 0;
    } else if (memcmp(magic, "Salted__", sizeof "Salted__" - 1)) {
	log("pmhelper: %s",
	    "magic string Salted__ not in filesystem key file");
	return 0;
    }
    return 1;
}
#endif				/* HAVE_LIBSSL */

int decrypted_key(char *pt_fs_key, char *password, char *fs_key_cipher,
		  char *fs_key_path)
{
#ifdef HAVE_LIBSSL
    int outlen, tmplen;
    unsigned char ct_fs_key[BUFSIZ + 1];	/* encrypted filesystem key. */
    unsigned char hashed_key[24];	/* The one used to encrypt filesystem 
					 * key -- hash(system_key). */
    BIO *fs_key_fp;
    unsigned char salt[PKCS5_SALT_LEN];
    unsigned char iv[MD5_DIGEST_LENGTH];
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX ctx;

    OpenSSL_add_all_ciphers();
    if (!(cipher = EVP_get_cipherbyname(fs_key_cipher))) {
	log("pmhelper: error getting cipher \"%s\"", fs_key_cipher);
	return 0;
    }

    if (!(fs_key_fp = BIO_new(BIO_s_file()))) {
	log("pmhelper: %s", "error creating new BIO");;
	return 0;
    }
    if (BIO_read_filename(fs_key_fp, fs_key_path) <= 0) {
	log("pmhelper: error opening %s", fs_key_path);
	return 0;
    }
    if (!read_salt(fs_key_fp, salt))
	return 0;
    if (!EVP_BytesToKey
	(cipher, EVP_md5(), salt, password, strlen(password), 1,
	 hashed_key, iv)) {
	log("pmhelper: %s", "failed to hash system password");
	return 0;
    }
    if (BIO_read(fs_key_fp, ct_fs_key, BUFSIZ) <= 0) {
	log("pmhelper: failed to read encrypted filesystem key from %s",
	    fs_key_path);
	return 0;
    }

    EVP_CIPHER_CTX_init(&ctx);
    if (!EVP_DecryptInit(&ctx, cipher, hashed_key, iv)) {
	log("pmhelper: %s", "failed to initialize decryption code");
	return 0;
    }
    if (!EVP_DecryptUpdate
	(&ctx, pt_fs_key, &outlen, ct_fs_key, strlen(ct_fs_key))) {
	log("pmhelper: %s", "failed to decrypt key");
	return 0;
    }
    if (!EVP_DecryptFinal(&ctx, pt_fs_key + outlen, &tmplen)) {
	log("pmhelper: %s", "failed to finish decrypting key");
	return 0;
    }
    /* w4rn("pmhelper: decrypted filesystem key is \"%s\"\n", pt_fs_key); */
    EVP_CIPHER_CTX_cleanup(&ctx);
    BIO_free(fs_key_fp);
    EVP_cleanup();
    return 1;
#else
    log("pmhelper: %s",
	"encrypted filesystem key not supported: no openssl");
    return 0;
#endif				/* HAVE_LIBSSL */
}

char *get_fstab_mountpoint(char *volume)
{
    FILE *fstab;
    struct mntent *fstab_record;
    if (!(fstab = fopen("/etc/fstab", "r"))) {
	log("%s", "pmhelper: could not determine mount point");
	exit(EXIT_FAILURE);
    }
    fstab_record = getmntent(fstab);
    while (fstab_record && strcmp(fstab_record->mnt_fsname, volume))
	fstab_record = getmntent(fstab);
    return fstab_record->mnt_dir;
}

int main(int argc, char **argv)
{
    int total, n;
    char *cmdarg[20];
    char **parg;
    int child;
    int fds[2];
    int child_exit;
    int i;

    w4rn("%s", "pmhelper: I am executing");

    bzero(&data, sizeof(data));

    config_signals();
    child = -1;

    total = 0;
    while (total < sizeof(data)) {
	n = read(0, ((char *) &data) + total, sizeof(data) - total);
	if (n <= 0) {
	    fprintf(stderr,
		    "\npmhelper: failed to receive mount data 1\n\n");
	    return 0;
	}
	total += n;
    }
    if (total != sizeof(data)) {
	fprintf(stderr, "\npmhelper: failed to receive mount data 2\n\n");
	return 0;
    }

    debug = data.debug;

    w4rn("%s", "pmhelper: received");
    w4rn("%s", "pmhelper: --------");
    w4rn("pmhelper: %s", data.server);
    w4rn("pmhelper: %s", data.user);
    /* w4rn("pmhelper: %s", data.password); */
    w4rn("pmhelper: %s", data.volume);
    w4rn("pmhelper: %s", data.mountpoint);
    w4rn("pmhelper: %s", data.fs_key_cipher);
    w4rn("pmhelper: %s", data.fs_key_path);
    w4rn("pmhelper: %s", data.command);
    w4rn("%s", "pmhelper: --------");

    sleep(1);

    if (data.unmount) {
	w4rn("%s", "pmhelper: unmounting");
	unmount_volume();
	return 0;
    }

    if (strlen(data.fs_key_cipher)) {
	/* data.fs_key_path contains real filesystem key. */
	char k[BUFSIZ + 1];
	if (!decrypted_key
	    (k, data.password, data.fs_key_cipher, data.fs_key_path))
	    return 0;
	strncpy(data.password, k, MAX_PAR + 1);
    }

    parg = cmdarg;
    if (data.type == NCPMOUNT) {
	parsecommand(data.command, "ncpmount", &parg);
	/* FIXME: Change to support defining in fstab too. */
	*(parg++) = "-S";
	*(parg++) = data.server;
	*(parg++) = "-U";
	*(parg++) = data.user;
	*(parg++) = "-P";
	*(parg++) = data.password;
	*(parg++) = "-V";
	*(parg++) = data.volume;
	*(parg++) = data.mountpoint;
    } else if (data.type == SMBMOUNT) {
	parsecommand(data.command, "smbmount", &parg);
	asprintf(parg++, "//%s/%s", data.server, data.volume);
	w4rn("pmhelper: asprintf %s", *(parg - 1));
	/* FIXME: Change to support defining in fstab too. */
	*(parg++) = data.mountpoint;
	*(parg++) = "-o";
	asprintf(parg++, "username=%s%%%s%s%s",
		 data.user, data.password,
		 data.options[0] ? "," : "", data.options);
    } else if (data.type == LCLMOUNT) {
	parsecommand(data.command, "mount", &parg);
	*(parg++) = data.volume;

	if (data.mountpoint[0]) /* If this is used, fstab will not be used. */
	    *(parg++) = data.mountpoint;

	if (data.options[0]) {
	    *(parg++) = "-o";
	    *(parg++) = data.options;
	}

	/* XXX should check that we actually need to send a password
	   before creating the pipe */
	if (pipe(fds) != 0) {
	    log("%s", "pmhelper: could not make pipe");
	    return 0;
	}
    } else {
	log("%s", "pmhelper: data.type is unkonwn");
	return 0;
    }
    *(parg++) = NULL;

    w4rn("%s", "pmhelper: about to fork");
    child = fork();
    if (child == -1) {
	log("%s", "pmhelper: failed to fork");
	return 0;
    }

    if (child == 0) {
	/* This is the child */

	if (data.type == LCLMOUNT) {
	    /* XXX want to use same fd as specified in config file
	       (rather than STDIN) */
	    /* XXX may want to check that password is actually needed
	       for this mount */
	    close(fds[1]);
	    dup2(fds[0], STDIN_FILENO);
	}

	for (i = 0; cmdarg[i]; i++) {
	    w4rn("pmhelper: arg is: %s", cmdarg[i]);
	}

	if (setuid(0) == -1)
	    w4rn("%s", "pmhelper: could not set uid to 0");
	execv(cmdarg[0], &cmdarg[1]);

	/* should not reach next instruction */
	log("%s", "pmhelper: failed to execv mount command");
	return 0;
    }

    if (data.type == LCLMOUNT) {
	/* XXX might want to check that password is actually needed
	   for this mount */

	/* send password down pipe to mount process */
	write(fds[1], data.password, strlen(data.password) + 1);
	close(fds[0]);
	close(fds[1]);
    }

    /* Clean password so virtual memory does not retain it */
    bzero(&(data.password), sizeof(data.password));

    w4rn("%s", "pmhelper: waiting for homedir mount\n");
    waitpid(child, &child_exit, 0);

    /* Unmounting is PAM module responsability */

    /* pass on through the result from the mount process */
    return WEXITSTATUS(child_exit);
}

void config_signals()
{
    signal(SIGCHLD, sigchld);

    /* Pipe will be eventually closed by parent but we don't mind */

    signal(SIGPIPE, SIG_IGN);
}

/* SIGCHLD handler */

void sigchld(int arg)
{
    wait((int *) NULL);
    config_signals();
}

void run_lsof(void)
{
    int pid, pipefds[2];
    if (pipe(pipefds) < 0) {
	log("%s", "pmhelper: failed to create pipe for lsof");
    } else {
	if ((pid = fork()) < 0) {
	    log("%s", "pmhelper: fork failed for lsof");
	} else {
	    if (pid == 0) {
		close(1);
		dup(pipefds[1]);
		close(pipefds[1]);
		close(pipefds[0]);
		execl(data.lsof, "lsof", data.mountpoint[0] ? data.mountpoint : get_fstab_mountpoint (data.volume), NULL);
		/* should not reach next instruction */
		w4rn("pmhelper: failed to execl %s", data.lsof);
	    } else {
		FILE *fp;
		char buf[BUFSIZ + 1];
		close(pipefds[1]);
		fp = fdopen(pipefds[0], "r");
		w4rn("pmhelper: lsof output (should be empty)...", strerror(errno));
		sleep(1);	/* FIXME: need to find a better way to wait for child 
				 * to catch up. 
				 */
		while (fgets(buf, BUFSIZ, fp) != NULL)
		    w4rn("pmhelper: %s", buf);
		close(pipefds[0]);
	    }
	}
    }
}

/* Unmount function */

void unmount_volume()
{
    int i;
    char *cmdarg[4];
    cmdarg[0] = data.ucommand;
    cmdarg[1] = "umount";
    /* Need to unmount mount point not volume to support SMB mounts, etc. */
    cmdarg[2] = data.mountpoint[0] ? data.mountpoint : get_fstab_mountpoint(data.volume);
    cmdarg[3] = NULL;

    for (i = 0; cmdarg[i]; i++) {
	w4rn("pmhelper: arg is: %s", cmdarg[i]);
    }

    if (setuid(0) == -1)
	w4rn("%s", "pmhelper: could not set uid to 0");

    if (debug)
	/* Often, a process still exists with ~ as its pwd after logging out.  
	 * Running lsof helps debug this.
	 */
	run_lsof();

    execv(cmdarg[0], &cmdarg[1]);
    /* should not reach next instruction */
    log("%s", "pmhelper: failed to execv umount command");
    _exit(1);
}

void parsecommand(const char *command, const char *name, char ***pparg)
{
    char *sprov = strdup(command);
    char *argument;

    w4rn("%s", "pmhelper: entering parsecommand");

    argument = strtok(sprov, "\t\n ");
    while (argument) {
	w4rn("pmhelper: adding token %s", argument);
	**pparg = strdup(argument);
	(*pparg)++;
	if (name) {
	    w4rn("pmhelper: adding token %s", name);
	    **pparg = strdup(name);
	    (*pparg)++;
	    name = NULL;
	}
	argument = strtok(NULL, "\t\n ");
    }

    w4rn("%s", "pmhelper: leaving parsecommand");

    free(sprov);
}
