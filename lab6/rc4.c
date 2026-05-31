#include "rc4.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct {
    unsigned char s[256];
    unsigned int i;
    unsigned int j;
} rc4_state_t;

struct rc4_secure_ctx {
    rc4_state_t *state;
    size_t map_size;
};

static void rc4_wipe_memory(void *data, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)data;
    size_t i;

    if (data == NULL) {
        return;
    }

    for (i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

static void rc4_swap(unsigned char *left, unsigned char *right) {
    unsigned char tmp = *left;

    *left = *right;
    *right = tmp;
}

static int rc4_init_state(rc4_state_t *state,
                          const unsigned char *key,
                          size_t key_len) {
    unsigned int i;
    unsigned int j;

    if (state == NULL || key == NULL || key_len == 0) {
        return 0;
    }

    for (i = 0; i < 256; ++i) {
        state->s[i] = (unsigned char)i;
    }

    j = 0;
    for (i = 0; i < 256; ++i) {
        j = (j + state->s[i] + key[i % key_len]) & 0xffu;
        rc4_swap(&state->s[i], &state->s[j]);
    }

    state->i = 0;
    state->j = 0;
    return 1;
}

static void rc4_xor_stream(rc4_state_t *state,
                           const unsigned char *input,
                           unsigned char *output,
                           size_t len) {
    size_t k;

    for (k = 0; k < len; ++k) {
        unsigned char stream_byte;

        state->i = (state->i + 1u) & 0xffu;
        state->j = (state->j + state->s[state->i]) & 0xffu;

        rc4_swap(&state->s[state->i], &state->s[state->j]);

        stream_byte =
            state->s[(state->s[state->i] + state->s[state->j]) & 0xffu];
        output[k] = (unsigned char)(input[k] ^ stream_byte);
    }
}

static int rc4_protect_state(rc4_secure_ctx_t *ctx, int protection) {
    return ctx != NULL && ctx->state != NULL &&
           mprotect(ctx->state, ctx->map_size, protection) == 0;
}

static size_t rc4_state_map_size(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    size_t map_size;

    if (page_size <= 0) {
        return 0;
    }

    map_size = (size_t)page_size;
    if (map_size < sizeof(rc4_state_t)) {
        size_t pages = (sizeof(rc4_state_t) + map_size - 1) / map_size;
        map_size *= pages;
    }

    return map_size;
}

int rc4_secure_init(rc4_secure_ctx_t **out_ctx,
                    const unsigned char *key,
                    size_t key_len) {
    rc4_secure_ctx_t *ctx;
    size_t map_size;

    if (out_ctx == NULL || key == NULL || key_len == 0) {
        return 0;
    }

    *out_ctx = NULL;

    map_size = rc4_state_map_size();
    if (map_size == 0) {
        return 0;
    }

    ctx = (rc4_secure_ctx_t *)malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return 0;
    }

    ctx->map_size = map_size;
    ctx->state = (rc4_state_t *)mmap(NULL,
                                     ctx->map_size,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS,
                                     -1,
                                     0);
    if (ctx->state == MAP_FAILED) {
        free(ctx);
        return 0;
    }

    if (!rc4_init_state(ctx->state, key, key_len)) {
        rc4_wipe_memory(ctx->state, ctx->map_size);
        munmap(ctx->state, ctx->map_size);
        free(ctx);
        return 0;
    }

    if (!rc4_protect_state(ctx, PROT_NONE)) {
        rc4_wipe_memory(ctx->state, ctx->map_size);
        munmap(ctx->state, ctx->map_size);
        free(ctx);
        return 0;
    }

    *out_ctx = ctx;
    return 1;
}

int rc4_secure_crypt_chunk(rc4_secure_ctx_t *ctx,
                           const unsigned char *input,
                           unsigned char *output,
                           size_t len) {
    int ok;

    if (ctx == NULL || ctx->state == NULL) {
        return 0;
    }
    if (len > 0 && (input == NULL || output == NULL)) {
        return 0;
    }
    if (len == 0) {
        return 1;
    }

    if (!rc4_protect_state(ctx, PROT_READ | PROT_WRITE)) {
        return 0;
    }

    rc4_xor_stream(ctx->state, input, output, len);

    ok = rc4_protect_state(ctx, PROT_NONE);
    return ok;
}

int rc4_secure_destroy(rc4_secure_ctx_t *ctx) {
    int ok = 1;

    if (ctx == NULL) {
        return 1;
    }

    if (ctx->state != NULL) {
        if (!rc4_protect_state(ctx, PROT_READ | PROT_WRITE)) {
            ok = 0;
        } else {
            rc4_wipe_memory(ctx->state, ctx->map_size);
        }

        if (munmap(ctx->state, ctx->map_size) != 0) {
            ok = 0;
        }
    }

    rc4_wipe_memory(ctx, sizeof(*ctx));
    free(ctx);
    return ok;
}

int rc4_crypt(const unsigned char *key,
              size_t key_len,
              const unsigned char *input,
              unsigned char *output,
              size_t len) {
    rc4_secure_ctx_t *ctx = NULL;
    int ok;

    if (key == NULL || key_len == 0) {
        return 0;
    }
    if (len > 0 && (input == NULL || output == NULL)) {
        return 0;
    }

    if (!rc4_secure_init(&ctx, key, key_len)) {
        return 0;
    }

    ok = rc4_secure_crypt_chunk(ctx, input, output, len);
    if (!rc4_secure_destroy(ctx)) {
        ok = 0;
    }

    return ok;
}
