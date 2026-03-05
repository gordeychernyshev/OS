#include "caesar.h"
#include <stddef.h>

static unsigned char g_key = 0;

void set_key(char key) {
    g_key = (unsigned char)key;
}

void caesar(void *src, void *dst, int len) {
    int i;
    unsigned char *s;
    unsigned char *d;

    if (len <= 0 || src == NULL || dst == NULL) {
        return;
    }

    s = (unsigned char *)src;
    d = (unsigned char *)dst;

    for (i = 0; i < len; ++i) {
        d[i] = (unsigned char)(s[i] ^ g_key);
    }
}