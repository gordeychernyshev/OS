#include "caesar.h"
#include "secure_key.h"

#include <stddef.h>

void set_key(char key) {
    secure_key_set_byte((unsigned char)key);
}

void caesar(void *src, void *dst, int len) {
    int i;
    unsigned char *s;
    unsigned char *d;
    const unsigned char *key_ptr;

    if (len <= 0 || src == NULL || dst == NULL) {
        return;
    }

    s = (unsigned char *)src;
    d = (unsigned char *)dst;

    key_ptr = secure_key_begin_read();

    for (i = 0; i < len; ++i) {
        d[i] = (unsigned char)(s[i] ^ key_ptr[0]);
    }

    secure_key_end_read();
}