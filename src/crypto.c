/*=============================================================================
pam_mount - crypto.c
  Copyright © W. Michael Petullo <mike@flyn.org>, 2002
  Copyright © CC Computer Consultants GmbH, 2005 - 2007
  Contact: Jan Engelhardt <jengelh [at] computergmbh de>

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
#include <config.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <libHX/defs.h>
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_LIBSSL)
#	include <openssl/ssl.h>
#	include <openssl/evp.h>
#	include <openssl/err.h>
#endif
#include "crypto.h"
#include "misc.h"
#include "pam_mount.h"

/* Functions */
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_LIBSSL)
static int hash_authtok(FILE *, const EVP_CIPHER *, const char *,
	unsigned char *, unsigned char *);
static void sslerror(const char *);
#endif

//-----------------------------------------------------------------------------
#if defined(HAVE_LIBCRYPTO) && defined(HAVE_LIBSSL)
/**
 * sslerror -
 * @msg:	Prefix to display
 *
 * Print the human-readable form of the current SSL error.
 */
static void sslerror(const char *msg)
{
	unsigned long err = ERR_get_error();
	if (err != 0)
		l0g("%s: %s", msg, ERR_error_string(err, NULL));
}

/**
 * hash_authtok -
 * @fp:		stream containing encrypted stream
 * @cipher:	OpenSSL cipher struct
 * @authtok:	key to unlock stream
 * @hash:
 * @iv:		initialization vector for @fp
 *
 * Returns zero on error or positive non-zero on success.
 */
static int hash_authtok(FILE *fp, const EVP_CIPHER *cipher,
    const char *authtok, unsigned char *hash, unsigned char *iv)
{
	const EVP_MD *md;
	unsigned char salt[PKCS5_SALT_LEN];
	char magic[sizeof_z("Salted__")];

	assert(fp != NULL);	/* FIXME: check if valid, open file */
	assert(cipher != NULL);	/* FIXME: check if cipher is valid OpenSSL cipher */
	assert(authtok != NULL);
	assert(hash != NULL);	/* FIXME: check hash is big enough? */
	assert(iv != NULL);	/* FIXME: check iv is big enough? */

	if (fread(magic, 1, sizeof(magic), fp) != sizeof_z("Salted__") ||
	    fread(salt, 1, sizeof(salt), fp) != PKCS5_SALT_LEN) {
		l0g("error reading salt from encrypted filesystem key\n");
		return 0;
	}
	if (memcmp(magic, "Salted__", sizeof(magic)) != 0) {
		l0g("magic string Salted__ not in filesystem key file\n");
		return 0;
	}
	md = EVP_md5();
	if (EVP_BytesToKey(cipher, md, salt,
	    signed_cast(const unsigned char *, authtok),
	    strlen(authtok), 1, hash, iv) <= 0) {
		l0g("failed to hash system password\n");
		return 0;
	}

	return 1;
}

/**
 * decrypted_key -
 * @pt_fs_key:		plaintext filesystem key
 * @fs_key_path:	path to an encrypted file (EFSK)
 * @fs_key_cipher:	the cipher used to encrypt the file
 * @authtok:		key to unlock the file at @fs_key_path
 *
 * Decrypts the keyfile given be @fs_key_path,@fs_key_cipher using @authtok and
 * returns the decrypted contents in @pt_fs_key.
 *
 * Returns zero on error or positive non-zero on success.
 *
 * NOTES:
 * - @pt_fs_key must point to a memory block large enough to hold fsk
 *   (MAX_PAR + EVP_MAX_BLOCK_LENGTH -- length of @ct_fs_key + one block)
 * - efsk = encrypted filesystem key (stored in filesystem)
 * - fsk = filesystem key (D(efsk))
 * - @pt_fs_key will contain binary data; do not use strlen(), strcpy(), etc.
 * - @pt_fs_key may contain trailing garbage; use @pt_fs_key_len
 *
 * FIXME: this function may need to be broken up and made more readable.
 */
int decrypted_key(hmc_t **pt_fs_key, const char *fs_key_path,
    const char *fs_key_cipher, const char *authtok)
{
	hmc_t *ct_fs_key = NULL, *line = NULL;
	int segment_len, pt_fs_key_len, ret = 1;
	unsigned char hashed_authtok[EVP_MAX_KEY_LENGTH];	/* hash(system authtok) */
	unsigned char iv[EVP_MAX_IV_LENGTH];
	FILE *fs_key_fp;
	const EVP_CIPHER *cipher;
	EVP_CIPHER_CTX ctx;

	assert(pt_fs_key != NULL);
	assert(fs_key_cipher != NULL);	/* fs_key_cipher = D, where D_key(efsk) = fsk */
	assert(fs_key_path != NULL);	/* path to efsk */
	assert(authtok != NULL);	/* should unlock efsk */

	OpenSSL_add_all_ciphers();
	EVP_CIPHER_CTX_init(&ctx);
	SSL_load_error_strings();
	if ((fs_key_fp = fopen(fs_key_path, "r")) == NULL) {
		l0g("error opening %s\n", fs_key_path);
		ret = 0;
		goto out;
	}
	if ((cipher = EVP_get_cipherbyname(fs_key_cipher)) == NULL) {
		l0g("error getting cipher \"%s\"\n", fs_key_cipher);
		ret = 0;
		goto out2;
	}
	if (hash_authtok(fs_key_fp, cipher, authtok,
	    hashed_authtok, iv) == 0) {
		ret = 0;
		goto out2;
	}

	ct_fs_key = hmc_minit(NULL, 0);
	while (HX_getl(&line, fs_key_fp) != NULL)
		hmc_memcat(&ct_fs_key, line, hmc_length(line));
	hmc_free(line);

	if (hmc_length(ct_fs_key) == 0) {
		l0g("failed to read encrypted filesystem key from %s, "
		    "or file empty.\n", fs_key_path);
		ret = 0;
		goto out3;
	}
	if (EVP_DecryptInit_ex(&ctx, cipher, NULL, hashed_authtok, iv) == 0) {
		sslerror("failed to initialize decryption code");
		ret = 0;
		goto out3;
	}

	*pt_fs_key = hmc_minit(NULL, 0);
	hmc_trunc(pt_fs_key, hmc_length(ct_fs_key) + EVP_MAX_BLOCK_LENGTH);
	if (EVP_DecryptUpdate(&ctx, signed_cast(unsigned char *,
	    *pt_fs_key), &segment_len, signed_cast(const unsigned char *,
	    ct_fs_key), hmc_length(ct_fs_key)) == 0) {
		sslerror("failed to decrypt key");
		ret = 0;
		goto out4;
	}
	pt_fs_key_len = segment_len;
	if (EVP_DecryptFinal_ex(&ctx, signed_cast(unsigned char *,
	    &pt_fs_key[segment_len]), &segment_len) == 0) {
		sslerror("bad pad on end of encrypted file (wrong algorithm "
		         "or key size?)");
		ret = 0;
		goto out4;
	}
	pt_fs_key_len += segment_len;
	hmc_trunc(pt_fs_key, pt_fs_key_len);

 out4:
	if (ret == 0)
		hmc_free(*pt_fs_key);
 out3:
	hmc_free(ct_fs_key);
 out2:
	if (fclose(fs_key_fp) != 0) {
		l0g("error closing file pointer\n");
		ret = 0;
	}
 out:
	if (EVP_CIPHER_CTX_cleanup(&ctx) == 0) {
		sslerror("error cleaning up cipher context");
		ret = 0;
	}

	ERR_free_strings();
	/* pt_fs_key_len is unsigned */
	assert(ret == 0);
	return ret;
}

#else /* HAVE_LIBCRYPTO && HAVE_LIBSSL */

int decrypted_key(hmc_t **pt_fs_key, const char *fs_key_path,
    const char *fs_key_cipher, const char *authtok)
{
	l0g("encrypted filesystem key not supported: no openssl\n");
	return 0;
}

#endif /* HAVE_LIBCRYPTO && HAVE_LIBSSL */
