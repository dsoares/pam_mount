#ifndef PMT_CRYPTO_H
#define PMT_CRYPTO_H 1

#include <sys/types.h>

#ifdef HAVE_LIBCRYPTO
#	ifndef EVP_MAX_BLOCK_LENGTH
		/* some older openssl versions need this */
#		define EVP_MAX_BLOCK_LENGTH 32
#	endif
#else
	/* FIXME: this is ugly, but needed */
#	define EVP_MAX_BLOCK_LENGTH 0
#endif

int decrypted_key(unsigned char *, size_t *, const char *, const char *,
	const char *);

#endif /* PMT_CRYPTO_H */
