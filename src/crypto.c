/*   FILE: crypto.c
 * AUTHOR: W. Michael Petullo <mike@flyn.org>
 *   DATE: 2002
 *
 * Copyright (C) 2002 W. Michael Petullo <mike@flyn.org>
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
#include <assert.h>
#include <sys/types.h>
#ifdef HAVE_LIBCRYPTO
#include <openssl/evp.h>
#include <openssl/err.h>
#ifndef EVP_MAX_BLOCK_LENGTH
#define EVP_MAX_BLOCK_LENGTH 32	/* some older openssl versions need this */
#endif
#else
#define EVP_MAX_BLOCK_LENGTH 0	/* FIXME: this is ugly, but needed */
#endif
#include <pam_mount.h>

#ifdef HAVE_LIBCRYPTO
/* human readable SSL error message */
static void sslerror(const char *msg)
{
	unsigned long err = ERR_get_error();
	if (err != 0) {
		l0g("pam_mount: %s: %s", msg, ERR_error_string(err, NULL));
	}
}

/* ============================ hash_authtok () ============================ */
/* INPUT: fp, file containing encrypted stream; cipher; authtok, the key
 *        to unlock stream contained in fs
 * SIDE AFFECTS: hash, hash(authtok); iv, the initialization vector for fp;
 *               errors are logged
 * OUTPUT: if error 0 else 1
 */
static int hash_authtok(FILE * const fp, const EVP_CIPHER * const cipher,
			const char *const authtok,
			unsigned char *const hash, unsigned char *const iv)
{
	const EVP_MD *md;
	unsigned char salt[PKCS5_SALT_LEN];
	char magic[sizeof "Salted__" - 1];

	assert(fp != NULL);	/* FIXME: check if valid, open file */
	assert(cipher != NULL);	/* FIXME: check if cipher is valid OpenSSL cipher */
	assert(authtok != NULL);
	assert(hash != NULL);	/* FIXME: check hash is big enough? */
	assert(iv != NULL);	/* FIXME: check iv is big enough? */

	if ((fread(magic, 1, sizeof "Salted__" - 1, fp) !=
	     sizeof "Salted__" - 1)
	    || (fread(salt, 1, PKCS5_SALT_LEN, fp) != PKCS5_SALT_LEN)) {
		l0g("pam_mount: %s\n",
		    "error reading salt from encrypted filesystem key");
		return 0;
	}
	if (memcmp(magic, "Salted__", sizeof "Salted__" - 1) != 0) {
		l0g("pam_mount: %s\n",
		    "magic string Salted__ not in filesystem key file");
		return 0;
	}
	md = EVP_md5();
	if (EVP_BytesToKey
	    (cipher, md, salt, authtok, strlen(authtok), 1,
	     hash, iv) <= 0) {
		l0g("pam_mount: %s\n", "failed to hash system password");
		return 0;
	}

	return 1;
}
#endif				/* HAVE_LIBCRYPTO */

/* ============================ decrypted_key () =========================== */
/* INPUT: fs_key_path, the path to an encrypted file (efsk); fs_key_cipher,
 *        the cipher used to encrypt the file; authtok, the key to unlock the
 *        file at fs_key_path
 * SIDE AFFECTS: pt_fs_key points to the decrypted data from the file at
 *               fs_key_path (fsk); pt_fs_key_len is the length of pt_fs_key;
 *               errors are logged
 * OUTPUT: if error 0 else 1
 * NOTE: pt_fs_key must point to a memory block large enough to hold fsk
 *       (MAX_PAR + EVP_MAX_BLOCK_LENGTH -- length of ct_fs_key + one block)
 *       efsk = encrypted filesystem key (stored in filesystem)
 *       fsk = filesystem key (D(efsk))
 *       pt_fs_key will contain binary data; don't use strlen, strcpy, etc.
 *       pt_fs_key may contain trailing garbage; use pt_fs_key_len
 */
int
decrypted_key(char *const pt_fs_key, size_t * const pt_fs_key_len,
	      const char *const fs_key_path,
	      const char *const fs_key_cipher, const char *const authtok)
{
/* FIXME: this function may need to be broken up and made more readable */
#ifdef HAVE_LIBCRYPTO
	int ret = 1;
	int segment_len;
	unsigned char ct_fs_key[MAX_PAR];	/* encrypted filesystem key. */
	size_t ct_fs_key_len;
	unsigned char hashed_authtok[EVP_MAX_KEY_LENGTH];	/* hash(system authtok) */
	unsigned char iv[EVP_MAX_IV_LENGTH];
	FILE *fs_key_fp;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;

	assert(pt_fs_key != NULL);
	assert(pt_fs_key_len != NULL);
	assert(fs_key_cipher != NULL);	/* fs_key_cipher = D, where D_key(efsk) = fsk */
	assert(fs_key_path != NULL);	/* path to efsk */
	assert(authtok != NULL);	/* should unlock efsk */

	memset(pt_fs_key, 0x00, MAX_PAR + EVP_MAX_BLOCK_LENGTH);
	OpenSSL_add_all_ciphers();
	EVP_CIPHER_CTX_init(&ctx);
	SSL_load_error_strings();
	if (!(fs_key_fp = fopen(fs_key_path, "r"))) {
		l0g("pam_mount: error opening %s\n", fs_key_path);
		ret = 0;
		goto _return_no_close;
	}
	if (!(cipher = EVP_get_cipherbyname(fs_key_cipher))) {
		l0g("pam_mount: error getting cipher \"%s\"\n",
		    fs_key_cipher);
		ret = 0;
		goto _return;
	}
	if (hash_authtok(fs_key_fp, cipher, authtok, hashed_authtok, iv) ==
	    0) {
		ret = 0;
		goto _return;
	}
	if ((ct_fs_key_len = fread(ct_fs_key, 1, MAX_PAR, fs_key_fp)) == 0) {
		l0g("pam_mount: failed to read encrypted filesystem key from %s\n", fs_key_path);
		ret = 0;
		goto _return;
	}
	if (EVP_DecryptInit_ex(&ctx, cipher, NULL, hashed_authtok, iv) ==
	    0) {
		sslerror("failed to initialize decryption code");
		ret = 0;
		goto _return;
	}
	/* assumes plaintexts is always <= ciphertext + EVP_MAX_BLOCK_LEN in length
	 * OpenSSL's documentation seems to promise this */
	if (EVP_DecryptUpdate
	    (&ctx, pt_fs_key, &segment_len, ct_fs_key,
	     ct_fs_key_len) == 0) {
		sslerror("failed to decrypt key");
		ret = 0;
		goto _return;
	}
	*pt_fs_key_len = segment_len;
	if (EVP_DecryptFinal_ex
	    (&ctx, &pt_fs_key[*pt_fs_key_len], &segment_len) == 0) {
		sslerror
		    ("bad pad on end of encrypted file (wrong algorithm or key size?)");
		ret = 0;
		goto _return;
	}
	*pt_fs_key_len += segment_len;
      _return:
	if (fclose(fs_key_fp) != 0) {
		l0g("pam_mount: error closing file pointer\n");
		ret = 0;
	}
      _return_no_close:
	if (EVP_CIPHER_CTX_cleanup(&ctx) == 0) {
		sslerror("error cleaning up cipher context");
		ret = 0;
	}

	ERR_free_strings();
	/* pt_fs_key_len is unsigned */
	assert(ret == 0
	       || *pt_fs_key_len <= MAX_PAR + EVP_MAX_BLOCK_LENGTH);

	return ret;
#else
	l0g("pam_mount: %s\n",
	    "encrypted filesystem key not supported: no openssl");
	return 0;
#endif				/* HAVE_LIBCRYPTO */
}
