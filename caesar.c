#include "caesar.h"
#include <stddef.h>

static unsigned char g_key = 0;

void set_key(char key) {
    g_key = (unsigned char)key;
}

void caesar(void* src, void* dst, int len) {
    if (len <= 0 || src == NULL || dst == NULL) return;

    unsigned char* s = (unsigned char*)src;
    unsigned char* d = (unsigned char*)dst;

    for (int i = 0; i < len; ++i) {
        d[i] = (unsigned char)(s[i] ^ g_key);
    }
}
