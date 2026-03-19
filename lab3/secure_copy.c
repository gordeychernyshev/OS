#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "caesar.h"

#define CHUNK_SIZE 8192
#define WORKERS 3
#define LOCK_TIMEOUT_SEC 5

typedef struct {
    const char **inputs;
    int input_count;
    const char *out_dir;
    char key;

    int next_index;
    pthread_mutex_t task_mutex;

    FILE *log_file;
    pthread_mutex_t log_mutex;
} shared_t;

static int parse_key(const char *text, char *key) {
    char *endptr = NULL;
    long value = strtol(text, &endptr, 10);

    if (text[0] == '\0' || *endptr != '\0') {
        return 0;
    }

    if (value < 0 || value > 255) {
        return 0;
    }

    *key = (char)value;
    return 1;
}

static const char *basename_simple(const char *path) {
    const char *slash = strrchr(path, '/');
    if (slash == NULL) {
        return path;
    }
    return slash + 1;
}

static void ensure_out_dir_or_die(const char *out_dir) {
    struct stat st;

    if (stat(out_dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Ошибка: '%s' существует, но это не папка\n",
                    out_dir);
            exit(EXIT_FAILURE);
        }
        return;
    }

    if (mkdir(out_dir, 0755) != 0) {
        perror("Ошибка создания папки вывода");
        exit(EXIT_FAILURE);
    }
}

static int open_unique_output_fd(const char *out_dir,
                                 const char *base_name,
                                 char *final_path,
                                 size_t final_path_size) {
    int fd;
    int attempt = 0;

    while (1) {
        if (attempt == 0) {
            snprintf(final_path, final_path_size, "%s/%s", out_dir, base_name);
        } else {
            const char *dot = strrchr(base_name, '.');
            if (dot != NULL && dot != base_name) {
                size_t name_len = (size_t)(dot - base_name);
                char name_part[512];
                char ext_part[512];

                if (name_len >= sizeof(name_part)) {
                    name_len = sizeof(name_part) - 1;
                }

                memcpy(name_part, base_name, name_len);
                name_part[name_len] = '\0';

                snprintf(ext_part, sizeof(ext_part), "%s", dot);
                snprintf(final_path, final_path_size, "%s/%s(%d)%s", out_dir,
                         name_part, attempt, ext_part);
            } else {
                snprintf(final_path, final_path_size, "%s/%s(%d)", out_dir,
                         base_name, attempt);
            }
        }

        fd = open(final_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) {
            return fd;
        }

        if (errno == EEXIST) {
            attempt++;
            continue;
        }

        perror("Ошибка создания выходного файла");
        return -1;
    }
}

static void lock_log_or_die(pthread_mutex_t *mtx) {
    int rc = pthread_mutex_trylock(mtx);
    if (rc == 0) {
        return;
    }

    if (rc != EBUSY) {
        fprintf(stderr, "Ошибка trylock (log_mutex): %s\n", strerror(rc));
        exit(EXIT_FAILURE);
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        perror("clock_gettime");
        exit(EXIT_FAILURE);
    }

    ts.tv_sec += LOCK_TIMEOUT_SEC;

    rc = pthread_mutex_timedlock(mtx, &ts);
    if (rc != 0) {
        if (rc == ETIMEDOUT) {
            fprintf(stderr,
                    "Не удалось захватить log_mutex за %d секунд. "
                    "Аварийное завершение.\n",
                    LOCK_TIMEOUT_SEC);
        } else {
            fprintf(stderr, "Ошибка timedlock (log_mutex): %s\n", strerror(rc));
        }
        exit(EXIT_FAILURE);
    }
}

static void write_log_line(shared_t *sh, const char *out_name) {
    time_t now = time(NULL);
    struct tm tm_now;
    char buf[64];

    localtime_r(&now, &tm_now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_now);

    lock_log_or_die(&sh->log_mutex);

    fprintf(sh->log_file, "%s pid=%ld tid=%lu file=%s\n", buf, (long)getpid(),
            (unsigned long)pthread_self(), out_name);
    fflush(sh->log_file);

    pthread_mutex_unlock(&sh->log_mutex);
}

static int process_one_file(const char *input_path,
                            const char *out_dir,
                            char key,
                            char *out_path,
                            size_t out_path_size) {
    FILE *in = NULL;
    FILE *out = NULL;

    unsigned char in_buf[CHUNK_SIZE];
    unsigned char out_buf[CHUNK_SIZE];

    const char *base = basename_simple(input_path);
    int out_fd = open_unique_output_fd(out_dir, base, out_path, out_path_size);
    if (out_fd < 0) {
        return 0;
    }

    in = fopen(input_path, "rb");
    if (in == NULL) {
        perror("Ошибка открытия входного файла");
        close(out_fd);
        return 0;
    }

    out = fdopen(out_fd, "wb");
    if (out == NULL) {
        perror("Ошибка fdopen для выходного файла");
        close(out_fd);
        fclose(in);
        return 0;
    }

    set_key(key);

    while (1) {
        size_t n = fread(in_buf, 1, CHUNK_SIZE, in);
        if (n > 0) {
            caesar(in_buf, out_buf, (int)n);
            if (fwrite(out_buf, 1, n, out) != n) {
                perror("Ошибка записи в выходной файл");
                fclose(in);
                fclose(out);
                return 0;
            }
        }

        if (n < CHUNK_SIZE) {
            if (ferror(in)) {
                perror("Ошибка чтения входного файла");
                fclose(in);
                fclose(out);
                return 0;
            }
            break;
        }
    }

    fclose(in);
    fclose(out);
    return 1;
}

static int take_next_task(shared_t *sh) {
    int idx;

    pthread_mutex_lock(&sh->task_mutex);
    idx = sh->next_index;
    sh->next_index++;
    pthread_mutex_unlock(&sh->task_mutex);

    if (idx >= sh->input_count) {
        return -1;
    }
    return idx;
}

static void *worker_thread(void *arg) {
    shared_t *sh = (shared_t *)arg;

    while (1) {
        int idx = take_next_task(sh);
        if (idx < 0) {
            break;
        }

        const char *input_path = sh->inputs[idx];
        char out_path[1024];

        if (!process_one_file(input_path, sh->out_dir, sh->key, out_path,
                              sizeof(out_path))) {
            fprintf(stderr, "Ошибка обработки файла: %s\n", input_path);
            /* По ТЗ про аварийный выход сказано для timedlock.
               Здесь оставляем обычный fail-fast: завершаем весь процесс. */
            exit(EXIT_FAILURE);
        }

        write_log_line(sh, out_path);
    }

    return NULL;
}

int main(int argc, char *argv[]) {
    shared_t sh;
    pthread_t threads[WORKERS];
    const char *out_dir;
    char key;
    int input_count;

    if (argc < 4) {
        fprintf(stderr,
                "Использование: %s <file1> ... <fileN> <out_dir> <key>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    out_dir = argv[argc - 2];

    if (!parse_key(argv[argc - 1], &key)) {
        fprintf(stderr, "Ошибка: key должен быть целым числом от 0 до 255\n");
        return EXIT_FAILURE;
    }

    input_count = argc - 3;
    if (input_count <= 0) {
        fprintf(stderr, "Ошибка: не указаны входные файлы\n");
        return EXIT_FAILURE;
    }

    ensure_out_dir_or_die(out_dir);

    sh.inputs = (const char **)&argv[1];
    sh.input_count = input_count;
    sh.out_dir = out_dir;
    sh.key = key;
    sh.next_index = 0;

    if (pthread_mutex_init(&sh.task_mutex, NULL) != 0) {
        perror("pthread_mutex_init task_mutex");
        return EXIT_FAILURE;
    }

    if (pthread_mutex_init(&sh.log_mutex, NULL) != 0) {
        perror("pthread_mutex_init log_mutex");
        pthread_mutex_destroy(&sh.task_mutex);
        return EXIT_FAILURE;
    }

    sh.log_file = fopen("log.txt", "a");
    if (sh.log_file == NULL) {
        perror("Ошибка открытия log.txt");
        pthread_mutex_destroy(&sh.task_mutex);
        pthread_mutex_destroy(&sh.log_mutex);
        return EXIT_FAILURE;
    }

    for (int i = 0; i < WORKERS; ++i) {
        if (pthread_create(&threads[i], NULL, worker_thread, &sh) != 0) {
            perror("Ошибка создания потока");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < WORKERS; ++i) {
        pthread_join(threads[i], NULL);
    }

    fclose(sh.log_file);
    pthread_mutex_destroy(&sh.task_mutex);
    pthread_mutex_destroy(&sh.log_mutex);

    return EXIT_SUCCESS;
}