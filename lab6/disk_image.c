#include "disk_image.h"

#include "rc4.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define IMAGE_IO_CHUNK_SIZE 8192

typedef struct {
    char *src_path;
    char *image_name;
    uint32_t file_size;
    uint64_t record_offset;
    uint64_t data_offset;
    uint64_t record_size;
} add_task_t;

typedef struct {
    add_task_t *items;
    size_t count;
    size_t capacity;
} task_list_t;

typedef struct {
    const char *image_path;
    const char *master_key;
    int image_fd;
    add_task_t *tasks;
    size_t task_count;
    size_t next_task;
    int error;
    pthread_mutex_t queue_mutex;
} add_context_t;

static char *duplicate_string(const char *text) {
    size_t len;
    char *copy;

    if (text == NULL) {
        return NULL;
    }

    len = strlen(text);
    copy = (char *)malloc(len + 1);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, text, len + 1);
    return copy;
}

static char *join_path(const char *left, const char *right) {
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    int need_slash = left_len > 0 && left[left_len - 1] != '/';
    char *result = (char *)malloc(left_len + (size_t)need_slash + right_len + 1);

    if (result == NULL) {
        return NULL;
    }

    memcpy(result, left, left_len);
    if (need_slash) {
        result[left_len] = '/';
        memcpy(result + left_len + 1, right, right_len + 1);
    } else {
        memcpy(result + left_len, right, right_len + 1);
    }

    return result;
}

static char *join_relative(const char *left, const char *right) {
    if (left[0] == '\0') {
        return duplicate_string(right);
    }

    return join_path(left, right);
}

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    const char *sep = slash;

    if (backslash != NULL && (sep == NULL || backslash > sep)) {
        sep = backslash;
    }

    if (sep == NULL) {
        return path;
    }

    return sep + 1;
}

static char *image_name_from_relative(const char *relative_path) {
    size_t len = strlen(relative_path);
    char *name;

    if (len == 0 || len > (size_t)UINT32_MAX - 1) {
        return NULL;
    }

    name = (char *)malloc(len + 2);
    if (name == NULL) {
        return NULL;
    }

    name[0] = '/';
    memcpy(name + 1, relative_path, len + 1);
    return name;
}

static void free_task(add_task_t *task) {
    free(task->src_path);
    free(task->image_name);
    task->src_path = NULL;
    task->image_name = NULL;
    task->file_size = 0;
    task->record_offset = 0;
    task->data_offset = 0;
    task->record_size = 0;
}

static void free_task_list(task_list_t *list) {
    size_t i;

    for (i = 0; i < list->count; ++i) {
        free_task(&list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int reserve_tasks(task_list_t *list, size_t needed) {
    add_task_t *new_items;
    size_t new_capacity;

    if (needed <= list->capacity) {
        return 1;
    }

    new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
    while (new_capacity < needed) {
        if (new_capacity > (SIZE_MAX / 2)) {
            return 0;
        }
        new_capacity *= 2;
    }

    new_items =
        (add_task_t *)realloc(list->items, new_capacity * sizeof(add_task_t));
    if (new_items == NULL) {
        return 0;
    }

    list->items = new_items;
    list->capacity = new_capacity;
    return 1;
}

static int add_task(task_list_t *list,
                    const char *src_path,
                    const char *image_name,
                    uint32_t file_size) {
    add_task_t *task;

    if (!reserve_tasks(list, list->count + 1)) {
        fprintf(stderr, "image add: not enough memory for task list\n");
        return 0;
    }

    task = &list->items[list->count];
    task->src_path = duplicate_string(src_path);
    task->image_name = duplicate_string(image_name);
    task->file_size = file_size;

    if (task->src_path == NULL || task->image_name == NULL) {
        free_task(task);
        fprintf(stderr, "image add: not enough memory for file path\n");
        return 0;
    }

    list->count++;
    return 1;
}

static int add_regular_file_task(task_list_t *list,
                                 const char *src_path,
                                 const char *image_name,
                                 const struct stat *st) {
    size_t name_len;

    if (st->st_size < 0 || (uint64_t)st->st_size > UINT32_MAX) {
        fprintf(stderr, "image add: file is too large: %s\n", src_path);
        return 0;
    }

    name_len = strlen(image_name);
    if (name_len == 0 || name_len > UINT32_MAX) {
        fprintf(stderr, "image add: image file name is too long: %s\n", src_path);
        return 0;
    }

    return add_task(list, src_path, image_name, (uint32_t)st->st_size);
}

static int collect_directory(task_list_t *list,
                             const char *dir_path,
                             const char *relative_dir) {
    DIR *dir;
    struct dirent *entry;

    dir = opendir(dir_path);
    if (dir == NULL) {
        perror("image add: opendir");
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        char *child_path;
        char *child_relative;
        int ok = 1;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        child_path = join_path(dir_path, entry->d_name);
        child_relative = join_relative(relative_dir, entry->d_name);
        if (child_path == NULL || child_relative == NULL) {
            fprintf(stderr, "image add: not enough memory for directory walk\n");
            free(child_path);
            free(child_relative);
            closedir(dir);
            return 0;
        }

        if (lstat(child_path, &st) != 0) {
            perror("image add: lstat");
            free(child_path);
            free(child_relative);
            closedir(dir);
            return 0;
        }

        if (S_ISDIR(st.st_mode)) {
            ok = collect_directory(list, child_path, child_relative);
        } else if (S_ISREG(st.st_mode)) {
            char *image_name = image_name_from_relative(child_relative);

            if (image_name == NULL) {
                fprintf(stderr, "image add: invalid image name: %s\n",
                        child_path);
                ok = 0;
            } else {
                ok = add_regular_file_task(list, child_path, image_name, &st);
            }
            free(image_name);
        }

        free(child_path);
        free(child_relative);

        if (!ok) {
            closedir(dir);
            return 0;
        }
    }

    if (closedir(dir) != 0) {
        perror("image add: closedir");
        return 0;
    }

    return 1;
}

static int collect_path(task_list_t *list, const char *path) {
    struct stat st;

    if (lstat(path, &st) != 0) {
        perror("image add: lstat");
        return 0;
    }

    if (S_ISDIR(st.st_mode)) {
        return collect_directory(list, path, "");
    }

    if (S_ISREG(st.st_mode)) {
        const char *name_part = base_name(path);
        char *image_name;
        int ok;

        if (name_part[0] == '\0') {
            fprintf(stderr, "image add: empty file name: %s\n", path);
            return 0;
        }

        image_name = image_name_from_relative(name_part);
        if (image_name == NULL) {
            fprintf(stderr, "image add: invalid image name: %s\n", path);
            return 0;
        }

        ok = add_regular_file_task(list, path, image_name, &st);
        free(image_name);
        return ok;
    }

    fprintf(stderr, "image add: skipped non-regular path: %s\n", path);
    return 1;
}

static int fill_random_salt(unsigned char salt[IMAGE_SALT_SIZE]) {
    int fd;
    size_t done = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("image add: open /dev/urandom");
        return 0;
    }

    while (done < IMAGE_SALT_SIZE) {
        ssize_t n = read(fd, salt + done, IMAGE_SALT_SIZE - done);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("image add: read /dev/urandom");
            close(fd);
            return 0;
        }
        if (n == 0) {
            fprintf(stderr, "image add: unexpected EOF from /dev/urandom\n");
            close(fd);
            return 0;
        }

        done += (size_t)n;
    }

    if (close(fd) != 0) {
        perror("image add: close /dev/urandom");
        return 0;
    }

    return 1;
}

static void wipe_buffer(unsigned char *data, size_t len) {
    volatile unsigned char *p = data;
    size_t i;

    if (data == NULL) {
        return;
    }

    for (i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

static int build_rc4_key(const char *master_key,
                         const unsigned char salt[IMAGE_SALT_SIZE],
                         unsigned char **out_key,
                         size_t *out_len) {
    size_t master_len;
    size_t total_len;
    unsigned char *key;

    if (master_key == NULL || out_key == NULL || out_len == NULL) {
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

static void store_u32_le(unsigned char bytes[4], uint32_t value) {
    bytes[0] = (unsigned char)(value & 0xffu);
    bytes[1] = (unsigned char)((value >> 8) & 0xffu);
    bytes[2] = (unsigned char)((value >> 16) & 0xffu);
    bytes[3] = (unsigned char)((value >> 24) & 0xffu);
}

static int pwrite_all(int fd, const void *data, size_t len, uint64_t offset) {
    const unsigned char *p = (const unsigned char *)data;
    size_t done = 0;

    if (len == 0) {
        return 1;
    }

    while (done < len) {
        ssize_t written;

        if (offset + done > (uint64_t)LLONG_MAX) {
            errno = EOVERFLOW;
            return 0;
        }

        written = pwrite(fd, p + done, len - done, (off_t)(offset + done));
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        if (written == 0) {
            errno = EIO;
            return 0;
        }

        done += (size_t)written;
    }

    return 1;
}

static int write_image_record_header(int fd,
                                     const add_task_t *task,
                                     const unsigned char salt[IMAGE_SALT_SIZE]) {
    unsigned char bytes[4];
    uint32_t name_len = (uint32_t)strlen(task->image_name);
    uint64_t offset = task->record_offset;

    store_u32_le(bytes, task->file_size);
    if (!pwrite_all(fd, bytes, sizeof(bytes), offset)) {
        return 0;
    }
    offset += sizeof(bytes);

    store_u32_le(bytes, name_len);
    if (!pwrite_all(fd, bytes, sizeof(bytes), offset)) {
        return 0;
    }
    offset += sizeof(bytes);

    if (!pwrite_all(fd, salt, IMAGE_SALT_SIZE, offset)) {
        return 0;
    }
    offset += IMAGE_SALT_SIZE;

    return pwrite_all(fd, task->image_name, name_len, offset);
}

static uint32_t load_u32_le(const unsigned char bytes[4]) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static int encrypt_file_to_image(int image_fd,
                                 const add_task_t *task,
                                 const unsigned char *rc4_key,
                                 size_t rc4_key_len) {
    FILE *input_file = NULL;
    rc4_secure_ctx_t *rc4_ctx = NULL;
    unsigned char in_buf[IMAGE_IO_CHUNK_SIZE];
    unsigned char out_buf[IMAGE_IO_CHUNK_SIZE];
    uint32_t remaining = task->file_size;
    uint64_t output_offset = task->data_offset;
    int ok = 0;

    input_file = fopen(task->src_path, "rb");
    if (input_file == NULL) {
        perror("image add: fopen input");
        return 0;
    }

    if (!rc4_secure_init(&rc4_ctx, rc4_key, rc4_key_len)) {
        fprintf(stderr, "image add: RC4 secure state initialization failed\n");
        goto cleanup;
    }

    while (remaining > 0) {
        size_t chunk_size = remaining > IMAGE_IO_CHUNK_SIZE
                                ? IMAGE_IO_CHUNK_SIZE
                                : (size_t)remaining;
        size_t nread = fread(in_buf, 1, chunk_size, input_file);

        if (nread != chunk_size) {
            if (ferror(input_file)) {
                perror("image add: fread input");
            } else {
                fprintf(stderr, "image add: input file changed while reading: %s\n",
                        task->src_path);
            }
            goto cleanup;
        }

        if (!rc4_secure_crypt_chunk(rc4_ctx, in_buf, out_buf, nread)) {
            fprintf(stderr, "image add: RC4 chunk encryption failed\n");
            goto cleanup;
        }

        if (!pwrite_all(image_fd, out_buf, nread, output_offset)) {
            perror("image add: pwrite encrypted chunk");
            goto cleanup;
        }

        output_offset += nread;
        remaining -= (uint32_t)nread;
    }

    if (fgetc(input_file) != EOF) {
        fprintf(stderr, "image add: input file changed while reading: %s\n",
                task->src_path);
        goto cleanup;
    }
    if (ferror(input_file)) {
        perror("image add: fread input");
        goto cleanup;
    }

    ok = 1;

cleanup:
    wipe_buffer(in_buf, sizeof(in_buf));
    wipe_buffer(out_buf, sizeof(out_buf));

    if (rc4_ctx != NULL && !rc4_secure_destroy(rc4_ctx)) {
        fprintf(stderr, "image add: RC4 secure state destroy failed\n");
        ok = 0;
    }

    if (input_file != NULL && fclose(input_file) != 0) {
        perror("image add: fclose input");
        ok = 0;
    }

    return ok;
}

static void set_context_error(add_context_t *ctx) {
    pthread_mutex_lock(&ctx->queue_mutex);
    ctx->error = 1;
    pthread_mutex_unlock(&ctx->queue_mutex);
}

static add_task_t *take_next_task(add_context_t *ctx) {
    add_task_t *task = NULL;

    pthread_mutex_lock(&ctx->queue_mutex);
    if (!ctx->error && ctx->next_task < ctx->task_count) {
        task = &ctx->tasks[ctx->next_task];
        ctx->next_task++;
    }
    pthread_mutex_unlock(&ctx->queue_mutex);

    return task;
}

static int process_add_task(add_context_t *ctx, const add_task_t *task) {
    unsigned char salt[IMAGE_SALT_SIZE];
    unsigned char *rc4_key = NULL;
    size_t rc4_key_len = 0;
    int ok = 0;

    if (!fill_random_salt(salt)) {
        goto cleanup;
    }

    if (!build_rc4_key(ctx->master_key, salt, &rc4_key, &rc4_key_len)) {
        fprintf(stderr, "image add: not enough memory for RC4 key\n");
        goto cleanup;
    }

    if (!write_image_record_header(ctx->image_fd, task, salt)) {
        perror("image add: pwrite record header");
        goto cleanup;
    }

    if (!encrypt_file_to_image(ctx->image_fd, task, rc4_key, rc4_key_len)) {
        goto cleanup;
    }

    ok = 1;

cleanup:
    wipe_buffer(rc4_key, rc4_key_len);
    free(rc4_key);
    memset(salt, 0, sizeof(salt));
    return ok;
}

static void *add_worker(void *arg) {
    add_context_t *ctx = (add_context_t *)arg;

    while (1) {
        add_task_t *task = take_next_task(ctx);

        if (task == NULL) {
            break;
        }

        if (!process_add_task(ctx, task)) {
            set_context_error(ctx);
            break;
        }
    }

    return NULL;
}

static int compute_task_layout(task_list_t *tasks,
                               uint64_t base_offset,
                               uint64_t *out_final_size) {
    uint64_t current_offset = base_offset;
    size_t i;

    if (tasks == NULL || out_final_size == NULL) {
        return 0;
    }

    for (i = 0; i < tasks->count; ++i) {
        add_task_t *task = &tasks->items[i];
        size_t name_len = strlen(task->image_name);
        uint64_t fixed_size = 4u + 4u + IMAGE_SALT_SIZE;
        uint64_t record_size;

        if (name_len == 0 || name_len > UINT32_MAX) {
            fprintf(stderr, "image add: invalid image file name: %s\n",
                    task->image_name);
            return 0;
        }

        if (current_offset > (uint64_t)LLONG_MAX) {
            fprintf(stderr, "image add: image offset is too large\n");
            return 0;
        }

        record_size = fixed_size + (uint64_t)name_len + task->file_size;
        if (record_size < fixed_size ||
            current_offset > UINT64_MAX - record_size) {
            fprintf(stderr, "image add: image size overflow\n");
            return 0;
        }

        task->record_offset = current_offset;
        task->data_offset = current_offset + fixed_size + (uint64_t)name_len;
        task->record_size = record_size;
        current_offset += record_size;
    }

    if (current_offset > (uint64_t)LLONG_MAX) {
        fprintf(stderr, "image add: resulting image is too large\n");
        return 0;
    }

    *out_final_size = current_offset;
    return 1;
}

int image_add_paths(const char *image_path,
                    const char *master_key,
                    const char **paths,
                    size_t path_count) {
    task_list_t tasks;
    add_context_t ctx;
    pthread_t workers[IMAGE_MAX_WORKERS];
    size_t worker_count;
    size_t created_workers = 0;
    size_t i;
    uint64_t old_size = 0;
    uint64_t final_size = 0;
    off_t end_pos;
    int ok = 1;

    memset(&tasks, 0, sizeof(tasks));
    memset(&ctx, 0, sizeof(ctx));
    ctx.image_fd = -1;

    if (image_path == NULL || master_key == NULL || paths == NULL ||
        path_count == 0) {
        fprintf(stderr, "image add: invalid arguments\n");
        return 0;
    }

    for (i = 0; i < path_count; ++i) {
        if (!collect_path(&tasks, paths[i])) {
            free_task_list(&tasks);
            return 0;
        }
    }

    if (tasks.count == 0) {
        free_task_list(&tasks);
        return 1;
    }

    ctx.image_fd = open(image_path, O_RDWR | O_CREAT, 0644);
    if (ctx.image_fd < 0) {
        perror("image add: open image");
        free_task_list(&tasks);
        return 0;
    }

    end_pos = lseek(ctx.image_fd, 0, SEEK_END);
    if (end_pos < 0) {
        perror("image add: seek image end");
        close(ctx.image_fd);
        free_task_list(&tasks);
        return 0;
    }
    old_size = (uint64_t)end_pos;

    if (!compute_task_layout(&tasks, old_size, &final_size)) {
        close(ctx.image_fd);
        free_task_list(&tasks);
        return 0;
    }

    if (ftruncate(ctx.image_fd, (off_t)final_size) != 0) {
        perror("image add: preallocate image");
        close(ctx.image_fd);
        free_task_list(&tasks);
        return 0;
    }

    ctx.image_path = image_path;
    ctx.master_key = master_key;
    ctx.tasks = tasks.items;
    ctx.task_count = tasks.count;

    if (pthread_mutex_init(&ctx.queue_mutex, NULL) != 0) {
        perror("image add: pthread_mutex_init queue");
        ftruncate(ctx.image_fd, (off_t)old_size);
        close(ctx.image_fd);
        free_task_list(&tasks);
        return 0;
    }

    worker_count = tasks.count < IMAGE_MAX_WORKERS ? tasks.count
                                                   : IMAGE_MAX_WORKERS;

    for (i = 0; i < worker_count; ++i) {
        if (pthread_create(&workers[i], NULL, add_worker, &ctx) != 0) {
            perror("image add: pthread_create");
            set_context_error(&ctx);
            ok = 0;
            break;
        }
        created_workers++;
    }

    for (i = 0; i < created_workers; ++i) {
        pthread_join(workers[i], NULL);
    }

    if (ctx.error) {
        ok = 0;
    }

    if (ok && fsync(ctx.image_fd) != 0) {
        perror("image add: fsync image");
        ok = 0;
    }

    if (!ok && ftruncate(ctx.image_fd, (off_t)old_size) != 0) {
        perror("image add: rollback image");
    }

    if (close(ctx.image_fd) != 0) {
        perror("image add: close image");
        ok = 0;
    }

    pthread_mutex_destroy(&ctx.queue_mutex);
    free_task_list(&tasks);

    return ok;
}

static int get_file_length(FILE *fp, uint64_t *length) {
    off_t end_pos;

    if (fseeko(fp, 0, SEEK_END) != 0) {
        return 0;
    }

    end_pos = ftello(fp);
    if (end_pos < 0) {
        return 0;
    }

    if (fseeko(fp, 0, SEEK_SET) != 0) {
        return 0;
    }

    *length = (uint64_t)end_pos;
    return 1;
}

static int read_required(FILE *fp, void *data, size_t len) {
    if (len == 0) {
        return 1;
    }

    return fread(data, 1, len, fp) == len;
}

static int append_index_entry(image_index_t *index, image_entry_t *entry) {
    image_entry_t *new_entries;

    new_entries = (image_entry_t *)realloc(
        index->entries, (index->count + 1) * sizeof(image_entry_t));
    if (new_entries == NULL) {
        return 0;
    }

    index->entries = new_entries;
    index->entries[index->count] = *entry;
    index->count++;
    return 1;
}

int image_load_index(const char *image_path, image_index_t *index) {
    FILE *fp;
    uint64_t image_len;

    if (index == NULL) {
        return 0;
    }

    index->entries = NULL;
    index->count = 0;

    fp = fopen(image_path, "rb");
    if (fp == NULL) {
        perror("image: fopen");
        return 0;
    }

    if (!get_file_length(fp, &image_len)) {
        perror("image: ftello");
        fclose(fp);
        return 0;
    }

    while ((uint64_t)ftello(fp) < image_len) {
        unsigned char file_size_bytes[4];
        unsigned char name_len_bytes[4];
        image_entry_t entry;
        off_t data_offset;
        uint64_t current_offset;
        uint32_t name_len;

        memset(&entry, 0, sizeof(entry));

        current_offset = (uint64_t)ftello(fp);
        if (image_len - current_offset < 8 + IMAGE_SALT_SIZE) {
            fprintf(stderr, "image: truncated record header\n");
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        if (!read_required(fp, file_size_bytes, sizeof(file_size_bytes)) ||
            !read_required(fp, name_len_bytes, sizeof(name_len_bytes)) ||
            !read_required(fp, entry.salt, IMAGE_SALT_SIZE)) {
            fprintf(stderr, "image: truncated record\n");
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        entry.file_size = load_u32_le(file_size_bytes);
        name_len = load_u32_le(name_len_bytes);
        if (name_len == 0) {
            fprintf(stderr, "image: empty file name in record\n");
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        current_offset = (uint64_t)ftello(fp);
        if (image_len - current_offset < (uint64_t)name_len) {
            fprintf(stderr, "image: truncated file name\n");
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        entry.name = (char *)malloc((size_t)name_len + 1);
        if (entry.name == NULL) {
            fprintf(stderr, "image: not enough memory for file name\n");
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        if (!read_required(fp, entry.name, name_len)) {
            fprintf(stderr, "image: truncated file name\n");
            free(entry.name);
            image_free_index(index);
            fclose(fp);
            return 0;
        }
        entry.name[name_len] = '\0';

        data_offset = ftello(fp);
        if (data_offset < 0) {
            perror("image: ftello data");
            free(entry.name);
            image_free_index(index);
            fclose(fp);
            return 0;
        }
        entry.data_offset = (uint64_t)data_offset;

        if (image_len - entry.data_offset < entry.file_size) {
            fprintf(stderr, "image: truncated file content\n");
            free(entry.name);
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        if (!append_index_entry(index, &entry)) {
            fprintf(stderr, "image: not enough memory for index\n");
            free(entry.name);
            image_free_index(index);
            fclose(fp);
            return 0;
        }

        if (fseeko(fp, (off_t)entry.file_size, SEEK_CUR) != 0) {
            perror("image: skip file content");
            image_free_index(index);
            fclose(fp);
            return 0;
        }
    }

    if (fclose(fp) != 0) {
        perror("image: fclose");
        image_free_index(index);
        return 0;
    }

    return 1;
}

void image_free_index(image_index_t *index) {
    size_t i;

    if (index == NULL) {
        return;
    }

    for (i = 0; i < index->count; ++i) {
        free(index->entries[i].name);
        index->entries[i].name = NULL;
    }

    free(index->entries);
    index->entries = NULL;
    index->count = 0;
}

const image_entry_t *image_find_entry(const image_index_t *index,
                                      const char *file_name) {
    size_t i;

    if (index == NULL || file_name == NULL) {
        return NULL;
    }

    for (i = 0; i < index->count; ++i) {
        if (strcmp(index->entries[i].name, file_name) == 0) {
            return &index->entries[i];
        }
    }

    return NULL;
}

static int compare_entry_ptrs(const void *left, const void *right) {
    const image_entry_t *const *a = (const image_entry_t *const *)left;
    const image_entry_t *const *b = (const image_entry_t *const *)right;

    return strcmp((*a)->name, (*b)->name);
}

int image_list_print(const char *image_path) {
    image_index_t index;
    const image_entry_t **sorted = NULL;
    size_t i;
    int ok = 1;

    if (!image_load_index(image_path, &index)) {
        return 0;
    }

    if (index.count > 0) {
        sorted = (const image_entry_t **)malloc(index.count * sizeof(*sorted));
        if (sorted == NULL) {
            fprintf(stderr, "image list: not enough memory\n");
            image_free_index(&index);
            return 0;
        }

        for (i = 0; i < index.count; ++i) {
            sorted[i] = &index.entries[i];
        }

        qsort(sorted, index.count, sizeof(*sorted), compare_entry_ptrs);
    }

    for (i = 0; i < index.count; ++i) {
        if (printf("%s %u\n", sorted[i]->name,
                   (unsigned)sorted[i]->file_size) < 0) {
            ok = 0;
            break;
        }
    }

    free(sorted);
    image_free_index(&index);
    return ok;
}

int image_read_decrypt_entry(const char *image_path,
                             const char *master_key,
                             const image_entry_t *entry,
                             unsigned char **out_data,
                             size_t *out_size) {
    FILE *fp = NULL;
    rc4_secure_ctx_t *rc4_ctx = NULL;
    unsigned char *plain = NULL;
    unsigned char *rc4_key = NULL;
    unsigned char encrypted_chunk[IMAGE_IO_CHUNK_SIZE];
    size_t plain_len;
    size_t rc4_key_len = 0;
    size_t offset = 0;
    uint32_t remaining;
    int ok = 0;

    if (image_path == NULL || master_key == NULL || entry == NULL ||
        out_data == NULL || out_size == NULL) {
        return 0;
    }

    if (!build_rc4_key(master_key, entry->salt, &rc4_key, &rc4_key_len)) {
        fprintf(stderr, "image get: not enough memory for RC4 key\n");
        goto cleanup;
    }

    plain_len = (size_t)entry->file_size;
    plain = (unsigned char *)malloc(plain_len == 0 ? 1 : plain_len);
    if (plain == NULL) {
        fprintf(stderr, "image get: not enough memory for plaintext\n");
        goto cleanup;
    }

    fp = fopen(image_path, "rb");
    if (fp == NULL) {
        perror("image get: fopen image");
        goto cleanup;
    }

    if (entry->data_offset > (uint64_t)LLONG_MAX ||
        fseeko(fp, (off_t)entry->data_offset, SEEK_SET) != 0) {
        perror("image get: seek content");
        goto cleanup;
    }

    if (!rc4_secure_init(&rc4_ctx, rc4_key, rc4_key_len)) {
        fprintf(stderr, "image get: RC4 secure state initialization failed\n");
        goto cleanup;
    }

    remaining = entry->file_size;
    while (remaining > 0) {
        size_t chunk_size = remaining > IMAGE_IO_CHUNK_SIZE
                                ? IMAGE_IO_CHUNK_SIZE
                                : (size_t)remaining;
        size_t nread = fread(encrypted_chunk, 1, chunk_size, fp);

        if (nread != chunk_size) {
            if (ferror(fp)) {
                perror("image get: fread content");
            } else {
                fprintf(stderr, "image get: truncated file content\n");
            }
            goto cleanup;
        }

        if (!rc4_secure_crypt_chunk(rc4_ctx,
                                    encrypted_chunk,
                                    plain + offset,
                                    nread)) {
            fprintf(stderr, "image get: RC4 chunk decryption failed\n");
            goto cleanup;
        }

        offset += nread;
        remaining -= (uint32_t)nread;
    }

    *out_data = plain;
    *out_size = plain_len;
    plain = NULL;
    ok = 1;

cleanup:
    wipe_buffer(encrypted_chunk, sizeof(encrypted_chunk));
    wipe_buffer(rc4_key, rc4_key_len);

    if (rc4_ctx != NULL && !rc4_secure_destroy(rc4_ctx)) {
        fprintf(stderr, "image get: RC4 secure state destroy failed\n");
        ok = 0;
    }

    if (fp != NULL && fclose(fp) != 0) {
        perror("image get: fclose image");
        ok = 0;
    }

    free(rc4_key);
    free(plain);
    return ok;
}

static int image_decrypt_entry_to_stream(const char *image_path,
                                         const char *master_key,
                                         const image_entry_t *entry,
                                         FILE *out) {
    FILE *fp = NULL;
    rc4_secure_ctx_t *rc4_ctx = NULL;
    unsigned char *rc4_key = NULL;
    unsigned char encrypted_chunk[IMAGE_IO_CHUNK_SIZE];
    unsigned char plain_chunk[IMAGE_IO_CHUNK_SIZE];
    size_t rc4_key_len = 0;
    uint32_t remaining;
    int ok = 0;

    if (image_path == NULL || master_key == NULL || entry == NULL ||
        out == NULL) {
        return 0;
    }

    if (!build_rc4_key(master_key, entry->salt, &rc4_key, &rc4_key_len)) {
        fprintf(stderr, "image get: not enough memory for RC4 key\n");
        goto cleanup;
    }

    fp = fopen(image_path, "rb");
    if (fp == NULL) {
        perror("image get: fopen image");
        goto cleanup;
    }

    if (entry->data_offset > (uint64_t)LLONG_MAX ||
        fseeko(fp, (off_t)entry->data_offset, SEEK_SET) != 0) {
        perror("image get: seek content");
        goto cleanup;
    }

    if (!rc4_secure_init(&rc4_ctx, rc4_key, rc4_key_len)) {
        fprintf(stderr, "image get: RC4 secure state initialization failed\n");
        goto cleanup;
    }

    remaining = entry->file_size;
    while (remaining > 0) {
        size_t chunk_size = remaining > IMAGE_IO_CHUNK_SIZE
                                ? IMAGE_IO_CHUNK_SIZE
                                : (size_t)remaining;
        size_t nread = fread(encrypted_chunk, 1, chunk_size, fp);

        if (nread != chunk_size) {
            if (ferror(fp)) {
                perror("image get: fread content");
            } else {
                fprintf(stderr, "image get: truncated file content\n");
            }
            goto cleanup;
        }

        if (!rc4_secure_crypt_chunk(rc4_ctx,
                                    encrypted_chunk,
                                    plain_chunk,
                                    nread)) {
            fprintf(stderr, "image get: RC4 chunk decryption failed\n");
            goto cleanup;
        }

        if (fwrite(plain_chunk, 1, nread, out) != nread) {
            perror("image get: fwrite output");
            goto cleanup;
        }

        remaining -= (uint32_t)nread;
    }

    ok = 1;

cleanup:
    wipe_buffer(encrypted_chunk, sizeof(encrypted_chunk));
    wipe_buffer(plain_chunk, sizeof(plain_chunk));
    wipe_buffer(rc4_key, rc4_key_len);

    if (rc4_ctx != NULL && !rc4_secure_destroy(rc4_ctx)) {
        fprintf(stderr, "image get: RC4 secure state destroy failed\n");
        ok = 0;
    }

    if (fp != NULL && fclose(fp) != 0) {
        perror("image get: fclose image");
        ok = 0;
    }

    free(rc4_key);
    return ok;
}

static const image_entry_t *find_cli_entry(const image_index_t *index,
                                           const char *file_name) {
    const image_entry_t *entry;
    char *with_slash;

    if (file_name == NULL) {
        return NULL;
    }

    entry = image_find_entry(index, file_name);
    if (entry != NULL || file_name[0] == '/') {
        return entry;
    }

    with_slash = image_name_from_relative(file_name);
    if (with_slash == NULL) {
        return NULL;
    }

    entry = image_find_entry(index, with_slash);
    free(with_slash);
    return entry;
}

int image_get_file(const char *image_path,
                   const char *master_key,
                   const char *file_name,
                   const char *out_path) {
    image_index_t index;
    const image_entry_t *entry;
    FILE *out = NULL;
    int ok = 0;

    if (image_path == NULL || master_key == NULL || file_name == NULL ||
        out_path == NULL) {
        fprintf(stderr, "image get: invalid arguments\n");
        return 0;
    }

    if (!image_load_index(image_path, &index)) {
        return 0;
    }

    entry = find_cli_entry(&index, file_name);
    if (entry == NULL) {
        fprintf(stderr, "image get: file not found: %s\n", file_name);
        image_free_index(&index);
        return 0;
    }

    out = fopen(out_path, "wb");
    if (out == NULL) {
        perror("image get: fopen output");
        goto cleanup;
    }

    if (!image_decrypt_entry_to_stream(image_path, master_key, entry, out)) {
        goto cleanup;
    }

    if (fclose(out) != 0) {
        perror("image get: fclose output");
        goto cleanup;
    }
    out = NULL;

    ok = 1;

cleanup:
    if (out != NULL && fclose(out) != 0) {
        perror("image get: fclose output");
        ok = 0;
    }
    image_free_index(&index);
    return ok;
}
