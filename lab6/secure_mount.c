#define FUSE_USE_VERSION 35

#include "disk_image.h"
#include "rc4.h"

#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define MOUNT_IO_CHUNK_SIZE 65536

typedef struct {
    const image_entry_t *entry;
    FILE *image_file;
    rc4_secure_ctx_t *rc4_ctx;
    uint64_t position;
    pthread_mutex_t lock;
} mount_file_handle_t;

static const char *g_image_path = NULL;
static const char *g_master_key = NULL;
static char g_image_real_path[PATH_MAX];
static image_index_t g_index;

static void wipe_mount_buffer(unsigned char *data, size_t len) {
    volatile unsigned char *p = data;
    size_t i;

    if (data == NULL) {
        return;
    }

    for (i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

static int mount_build_rc4_key(const char *master_key,
                               const unsigned char salt[IMAGE_SALT_SIZE],
                               unsigned char **out_key,
                               size_t *out_len) {
    size_t master_len;
    size_t total_len;
    unsigned char *key;

    if (master_key == NULL || salt == NULL || out_key == NULL ||
        out_len == NULL) {
        return 0;
    }

    master_len = strlen(master_key);
    if (master_len > SIZE_MAX - IMAGE_SALT_SIZE) {
        return 0;
    }

    total_len = master_len + IMAGE_SALT_SIZE;
    key = (unsigned char *)malloc(total_len);
    if (key == NULL) {
        return 0;
    }

    memcpy(key, master_key, master_len);
    memcpy(key + master_len, salt, IMAGE_SALT_SIZE);

    *out_key = key;
    *out_len = total_len;
    return 1;
}

static const image_entry_t *mount_find_entry(const char *path) {
    const image_entry_t *entry;
    size_t i;

    entry = image_find_entry(&g_index, path);
    if (entry != NULL) {
        return entry;
    }

    if (path[0] == '/') {
        entry = image_find_entry(&g_index, path + 1);
        if (entry != NULL) {
            return entry;
        }
    }

    for (i = 0; i < g_index.count; ++i) {
        const char *name = g_index.entries[i].name;

        if (name[0] == '/' && strcmp(name + 1, path) == 0) {
            return &g_index.entries[i];
        }
    }

    return NULL;
}

static int path_is_directory(const char *path) {
    size_t path_len;
    size_t i;

    if (strcmp(path, "/") == 0) {
        return 1;
    }

    path_len = strlen(path);
    for (i = 0; i < g_index.count; ++i) {
        const char *name = g_index.entries[i].name;

        if (strncmp(name, path, path_len) == 0 && name[path_len] == '/') {
            return 1;
        }

        if (path[0] == '/' && name[0] != '/') {
            const char *path_no_slash = path + 1;
            size_t no_slash_len = strlen(path_no_slash);

            if (strncmp(name, path_no_slash, no_slash_len) == 0 &&
                name[no_slash_len] == '/') {
                return 1;
            }
        }
    }

    return 0;
}

static char *duplicate_child_name(const char *dir_path, const char *file_path) {
    const char *rest;
    const char *slash;
    size_t dir_len;
    size_t child_len;
    char *child;

    if (strcmp(dir_path, "/") == 0) {
        rest = file_path[0] == '/' ? file_path + 1 : file_path;
    } else {
        dir_len = strlen(dir_path);

        if (file_path[0] == '/') {
            if (strncmp(file_path, dir_path, dir_len) != 0 ||
                file_path[dir_len] != '/') {
                return NULL;
            }
            rest = file_path + dir_len + 1;
        } else {
            const char *dir_no_slash = dir_path[0] == '/' ? dir_path + 1
                                                          : dir_path;
            dir_len = strlen(dir_no_slash);

            if (strncmp(file_path, dir_no_slash, dir_len) != 0 ||
                file_path[dir_len] != '/') {
                return NULL;
            }
            rest = file_path + dir_len + 1;
        }
    }

    if (rest[0] == '\0') {
        return NULL;
    }

    slash = strchr(rest, '/');
    child_len = slash == NULL ? strlen(rest) : (size_t)(slash - rest);
    if (child_len == 0) {
        return NULL;
    }

    child = (char *)malloc(child_len + 1);
    if (child == NULL) {
        return NULL;
    }

    memcpy(child, rest, child_len);
    child[child_len] = '\0';
    return child;
}

static int child_seen(char **children, size_t count, const char *child) {
    size_t i;

    for (i = 0; i < count; ++i) {
        if (strcmp(children[i], child) == 0) {
            return 1;
        }
    }

    return 0;
}

static int add_seen_child(char ***children, size_t *count, char *child) {
    char **new_children;

    new_children = (char **)realloc(*children, (*count + 1) * sizeof(char *));
    if (new_children == NULL) {
        return 0;
    }

    *children = new_children;
    (*children)[*count] = child;
    (*count)++;
    return 1;
}

static void free_seen_children(char **children, size_t count) {
    size_t i;

    for (i = 0; i < count; ++i) {
        free(children[i]);
    }
    free(children);
}

static int mount_reset_stream(mount_file_handle_t *handle) {
    unsigned char *rc4_key = NULL;
    size_t rc4_key_len = 0;
    int ok = 0;

    if (handle == NULL || handle->entry == NULL || handle->image_file == NULL) {
        return 0;
    }

    if (handle->rc4_ctx != NULL) {
        rc4_secure_ctx_t *old_ctx = handle->rc4_ctx;

        handle->rc4_ctx = NULL;
        if (!rc4_secure_destroy(old_ctx)) {
            return 0;
        }
    }

    if (!mount_build_rc4_key(g_master_key,
                             handle->entry->salt,
                             &rc4_key,
                             &rc4_key_len)) {
        goto cleanup;
    }

    if (handle->entry->data_offset > (uint64_t)LLONG_MAX ||
        fseeko(handle->image_file,
               (off_t)handle->entry->data_offset,
               SEEK_SET) != 0) {
        goto cleanup;
    }

    if (!rc4_secure_init(&handle->rc4_ctx, rc4_key, rc4_key_len)) {
        goto cleanup;
    }

    handle->position = 0;
    ok = 1;

cleanup:
    wipe_mount_buffer(rc4_key, rc4_key_len);
    free(rc4_key);
    return ok;
}

static int mount_advance_stream(mount_file_handle_t *handle,
                                uint64_t target_position) {
    unsigned char encrypted_chunk[MOUNT_IO_CHUNK_SIZE];
    unsigned char plain_chunk[MOUNT_IO_CHUNK_SIZE];
    int ok = 0;

    if (handle == NULL || handle->rc4_ctx == NULL ||
        target_position > handle->entry->file_size) {
        return 0;
    }

    while (handle->position < target_position) {
        uint64_t left = target_position - handle->position;
        size_t chunk_size = left > MOUNT_IO_CHUNK_SIZE
                                ? MOUNT_IO_CHUNK_SIZE
                                : (size_t)left;
        size_t nread = fread(encrypted_chunk,
                             1,
                             chunk_size,
                             handle->image_file);

        if (nread != chunk_size) {
            goto cleanup;
        }

        if (!rc4_secure_crypt_chunk(handle->rc4_ctx,
                                    encrypted_chunk,
                                    plain_chunk,
                                    nread)) {
            goto cleanup;
        }

        handle->position += nread;
    }

    ok = 1;

cleanup:
    wipe_mount_buffer(encrypted_chunk, sizeof(encrypted_chunk));
    wipe_mount_buffer(plain_chunk, sizeof(plain_chunk));
    return ok;
}

static int mount_read_stream(mount_file_handle_t *handle,
                             uint64_t offset,
                             char *buf,
                             size_t size,
                             size_t *read_size) {
    unsigned char encrypted_chunk[MOUNT_IO_CHUNK_SIZE];
    size_t total = 0;
    size_t to_read;
    int ok = 0;

    if (handle == NULL || buf == NULL || read_size == NULL ||
        handle->entry == NULL) {
        return 0;
    }

    *read_size = 0;
    if (offset >= handle->entry->file_size || size == 0) {
        return 1;
    }

    to_read = (size_t)(handle->entry->file_size - offset);
    if (to_read > size) {
        to_read = size;
    }
    if (to_read > (size_t)INT_MAX) {
        to_read = (size_t)INT_MAX;
    }

    if (pthread_mutex_lock(&handle->lock) != 0) {
        return 0;
    }

    if (offset < handle->position && !mount_reset_stream(handle)) {
        goto cleanup;
    }

    if (offset > handle->position &&
        !mount_advance_stream(handle, offset)) {
        goto cleanup;
    }

    while (total < to_read) {
        size_t chunk_size = to_read - total;
        size_t nread;

        if (chunk_size > MOUNT_IO_CHUNK_SIZE) {
            chunk_size = MOUNT_IO_CHUNK_SIZE;
        }

        nread = fread(encrypted_chunk, 1, chunk_size, handle->image_file);
        if (nread != chunk_size) {
            goto cleanup;
        }

        if (!rc4_secure_crypt_chunk(handle->rc4_ctx,
                                    encrypted_chunk,
                                    (unsigned char *)buf + total,
                                    nread)) {
            goto cleanup;
        }

        total += nread;
        handle->position += nread;
    }

    *read_size = total;
    ok = 1;

cleanup:
    wipe_mount_buffer(encrypted_chunk, sizeof(encrypted_chunk));
    pthread_mutex_unlock(&handle->lock);
    return ok;
}

static int mount_free_handle(mount_file_handle_t *handle) {
    int ok = 1;

    if (handle == NULL) {
        return 1;
    }

    if (handle->rc4_ctx != NULL && !rc4_secure_destroy(handle->rc4_ctx)) {
        ok = 0;
    }

    if (handle->image_file != NULL && fclose(handle->image_file) != 0) {
        ok = 0;
    }

    pthread_mutex_destroy(&handle->lock);
    memset(handle, 0, sizeof(*handle));
    free(handle);
    return ok;
}

static int secure_mount_getattr(const char *path,
                                struct stat *stbuf,
                                struct fuse_file_info *fi) {
    const image_entry_t *entry;

    (void)fi;
    memset(stbuf, 0, sizeof(*stbuf));

    entry = mount_find_entry(path);
    if (entry != NULL) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = (off_t)entry->file_size;
        return 0;
    }

    if (path_is_directory(path)) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
        return 0;
    }

    return -ENOENT;
}

static int secure_mount_readdir(const char *path,
                                void *buf,
                                fuse_fill_dir_t filler,
                                off_t offset,
                                struct fuse_file_info *fi,
                                enum fuse_readdir_flags flags) {
    char **children = NULL;
    size_t child_count = 0;
    size_t i;

    (void)offset;
    (void)fi;
    (void)flags;

    if (!path_is_directory(path)) {
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    for (i = 0; i < g_index.count; ++i) {
        char *child = duplicate_child_name(path, g_index.entries[i].name);

        if (child == NULL) {
            continue;
        }

        if (child_seen(children, child_count, child)) {
            free(child);
            continue;
        }

        if (!add_seen_child(&children, &child_count, child)) {
            free(child);
            free_seen_children(children, child_count);
            return -ENOMEM;
        }

        filler(buf, child, NULL, 0, 0);
    }

    free_seen_children(children, child_count);
    return 0;
}

static int secure_mount_open(const char *path, struct fuse_file_info *fi) {
    const image_entry_t *entry;
    mount_file_handle_t *handle;

    if ((fi->flags & O_ACCMODE) != O_RDONLY) {
        return -EACCES;
    }

    entry = mount_find_entry(path);
    if (entry == NULL) {
        return -ENOENT;
    }

    handle = (mount_file_handle_t *)calloc(1, sizeof(*handle));
    if (handle == NULL) {
        return -ENOMEM;
    }

    handle->entry = entry;
    handle->image_file = fopen(g_image_path, "rb");
    if (handle->image_file == NULL) {
        free(handle);
        return -EIO;
    }

    if (pthread_mutex_init(&handle->lock, NULL) != 0) {
        fclose(handle->image_file);
        free(handle);
        return -EIO;
    }

    if (!mount_reset_stream(handle)) {
        mount_free_handle(handle);
        return -EIO;
    }

    fi->fh = (uint64_t)(uintptr_t)handle;
    return 0;
}

static int secure_mount_read(const char *path,
                             char *buf,
                             size_t size,
                             off_t offset,
                             struct fuse_file_info *fi) {
    const image_entry_t *entry;
    mount_file_handle_t *handle;
    size_t read_size = 0;

    if (offset < 0) {
        return -EINVAL;
    }

    entry = mount_find_entry(path);
    if (entry == NULL) {
        return -ENOENT;
    }

    if (fi == NULL || fi->fh == 0) {
        return -EIO;
    }

    handle = (mount_file_handle_t *)(uintptr_t)fi->fh;
    if (handle->entry != entry) {
        return -EIO;
    }

    if (!mount_read_stream(handle, (uint64_t)offset, buf, size, &read_size)) {
        return -EIO;
    }

    return (int)read_size;
}

static int secure_mount_release(const char *path, struct fuse_file_info *fi) {
    mount_file_handle_t *handle;

    (void)path;

    if (fi == NULL || fi->fh == 0) {
        return 0;
    }

    handle = (mount_file_handle_t *)(uintptr_t)fi->fh;
    fi->fh = 0;
    return mount_free_handle(handle) ? 0 : -EIO;
}

static const struct fuse_operations secure_mount_ops = {
    .getattr = secure_mount_getattr,
    .readdir = secure_mount_readdir,
    .open = secure_mount_open,
    .read = secure_mount_read,
    .release = secure_mount_release,
};

static void print_usage(const char *program) {
    fprintf(stderr, "Usage: %s -image <image> -key <key> <mount_dir>\n",
            program);
}

int main(int argc, char *argv[]) {
    const char *mount_dir = NULL;
    char *fuse_argv[5];
    int fuse_argc = 4;
    int rc;
    int i;

    memset(&g_index, 0, sizeof(g_index));

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-image") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            g_image_path = argv[++i];
        } else if (strcmp(argv[i], "-key") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return EXIT_FAILURE;
            }
            g_master_key = argv[++i];
        } else if (argv[i][0] == '-') {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        } else if (mount_dir == NULL) {
            mount_dir = argv[i];
        } else {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (g_image_path == NULL || g_master_key == NULL || mount_dir == NULL) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (realpath(g_image_path, g_image_real_path) == NULL) {
        perror("secure_mount: realpath image");
        return EXIT_FAILURE;
    }
    g_image_path = g_image_real_path;

    if (!image_load_index(g_image_path, &g_index)) {
        return EXIT_FAILURE;
    }

    fuse_argv[0] = argv[0];
    fuse_argv[1] = (char *)mount_dir;
    fuse_argv[2] = "-o";
    fuse_argv[3] = "ro";
    fuse_argv[4] = NULL;

    rc = fuse_main(fuse_argc, fuse_argv, &secure_mount_ops, NULL);
    image_free_index(&g_index);

    return rc;
}
