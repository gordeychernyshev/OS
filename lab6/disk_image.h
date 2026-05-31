#ifndef DISK_IMAGE_H
#define DISK_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#define IMAGE_SALT_SIZE 16
#define IMAGE_MAX_WORKERS 5

typedef struct {
    char *name;
    uint32_t file_size;
    unsigned char salt[IMAGE_SALT_SIZE];
    uint64_t data_offset;
} image_entry_t;

typedef struct {
    image_entry_t *entries;
    size_t count;
} image_index_t;

int image_add_paths(const char *image_path,
                    const char *master_key,
                    const char **paths,
                    size_t path_count);
int image_list_print(const char *image_path);
int image_get_file(const char *image_path,
                   const char *master_key,
                   const char *file_name,
                   const char *out_path);

int image_load_index(const char *image_path, image_index_t *index);
void image_free_index(image_index_t *index);
const image_entry_t *image_find_entry(const image_index_t *index,
                                      const char *file_name);
int image_read_decrypt_entry(const char *image_path,
                             const char *master_key,
                             const image_entry_t *entry,
                             unsigned char **out_data,
                             size_t *out_size);

#endif
