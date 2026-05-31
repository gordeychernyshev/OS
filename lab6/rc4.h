#ifndef RC4_H
#define RC4_H

#include <stddef.h>

typedef struct rc4_secure_ctx rc4_secure_ctx_t;

int rc4_crypt(const unsigned char *key,
              size_t key_len,
              const unsigned char *input,
              unsigned char *output,
              size_t len);

int rc4_secure_init(rc4_secure_ctx_t **out_ctx,
                    const unsigned char *key,
                    size_t key_len);
int rc4_secure_crypt_chunk(rc4_secure_ctx_t *ctx,
                           const unsigned char *input,
                           unsigned char *output,
                           size_t len);
int rc4_secure_destroy(rc4_secure_ctx_t *ctx);

#endif
