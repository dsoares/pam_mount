#ifndef PMT_CRYPTO_H
#define PMT_CRYPTO_H 1

#ifdef __cplusplus
extern "C" {
#endif

int decrypted_key(unsigned char *, size_t *, const char *, const char *,
    const char *);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // PMT_CRYPTO_H
