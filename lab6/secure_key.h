#ifndef SECURE_KEY_H
#define SECURE_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

void secure_key_init(void);
void secure_key_set_from_string(const char *text);
void secure_key_set_byte(unsigned char key);

const unsigned char *secure_key_begin_read(void);
void secure_key_end_read(void);

void secure_key_destroy(void);

void secure_key_test_illegal_write(void);
void secure_key_test_destroy(void);

#ifdef __cplusplus
}
#endif

#endif