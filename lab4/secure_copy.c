#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "caesar.h"

#define CHUNK_SIZE 8192
#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif
#define LOCK_TIMEOUT_SEC 5

typedef enum {
    MODE_SEQUENTIAL = 0,
    MODE_PARALLEL = 1,
    MODE_AUTO = 2
} run_mode_t;

typedef struct {
    struct timespec start;
    struct timespec end;
    double duration_ms;
    int ok;
} file_stat_t;

typedef struct {
    run_mode_t mode;
    int total_files;
    int processed_files;
    int failed_files;
    double total_ms;
    double avg_ms;
    file_stat_t *files;
} run_stats_t;

typedef struct {
    const char **inputs;
    int input_count;
    const char *out_dir;
    unsigned char key;

    int *queue;
    int queue_head;
    int queue_count;
    int start_flag;

    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;

    run_stats_t *stats;
    pthread_mutex_t stats_mutex;

    int fatal_error;

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

static int parse_mode_arg(const char *arg, run_mode_t *mode) {
    const char *prefix = "--mode=";
    size_t prefix_len = strlen(prefix);

    if (strncmp(arg, prefix, prefix_len) != 0) {
        return 0;
    }

    arg += prefix_len;
    if (strcmp(arg, "sequential") == 0) {
        *mode = MODE_SEQUENTIAL;
        return 1;
    }
    if (strcmp(arg, "parallel") == 0) {
        *mode = MODE_PARALLEL;
        return 1;
    }
    if (strcmp(arg, "auto") == 0) {
        *mode = MODE_AUTO;
        return 1;
    }

    return -1;
}

static const char *mode_to_str(run_mode_t mode) {
    if (mode == MODE_SEQUENTIAL) {
        return "sequential";
    }
    if (mode == MODE_PARALLEL) {
        return "parallel";
    }
    return "auto";
}

static run_mode_t choose_mode_heuristic(int file_count) {
    if (file_count < 5) {
        return MODE_SEQUENTIAL;
    }
    return MODE_PARALLEL;
}

static double diff_ms(const struct timespec *start, const struct timespec *end) {
    long sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;
    return (double)sec * 1000.0 + (double)nsec / 1000000.0;
}

static const char *basename_simple(const char *path) {
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
                            unsigned char key,
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

    (void)key;

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

static void store_file_result(shared_t *sh,
                              int idx,
                              int ok,
                              const struct timespec *start,
                              const struct timespec *end) {
    pthread_mutex_lock(&sh->stats_mutex);

    sh->stats->files[idx].start = *start;
    sh->stats->files[idx].end = *end;
    sh->stats->files[idx].duration_ms = diff_ms(start, end);
    sh->stats->files[idx].ok = ok;

    sh->stats->processed_files++;
    if (!ok) {
        sh->stats->failed_files++;
    }

    pthread_mutex_unlock(&sh->stats_mutex);
}

static void set_fatal_error(shared_t *sh) {
    pthread_mutex_lock(&sh->stats_mutex);
    sh->fatal_error = 1;
    pthread_mutex_unlock(&sh->stats_mutex);
}

static int get_fatal_error(shared_t *sh) {
    int v;
    pthread_mutex_lock(&sh->stats_mutex);
    v = sh->fatal_error;
    pthread_mutex_unlock(&sh->stats_mutex);
    return v;
}

static int take_next_task(shared_t *sh) {
    int idx = -1;

    pthread_mutex_lock(&sh->queue_mutex);
    while (!sh->start_flag) {
        pthread_cond_wait(&sh->queue_cond, &sh->queue_mutex);
    }

    if (sh->queue_count > 0) {
        idx = sh->queue[sh->queue_head];
        sh->queue_head++;
        sh->queue_count--;
    }

    pthread_mutex_unlock(&sh->queue_mutex);
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
        struct timespec start_ts;
        struct timespec end_ts;
        int ok;

        if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
            perror("clock_gettime start");
            set_fatal_error(sh);
            break;
        }

        ok = process_one_file(input_path, sh->out_dir, sh->key, out_path,
                              sizeof(out_path));

        if (clock_gettime(CLOCK_MONOTONIC, &end_ts) != 0) {
            perror("clock_gettime end");
            set_fatal_error(sh);
            break;
        }

        if (!ok) {
            fprintf(stderr, "Ошибка обработки файла: %s\n", input_path);
        } else {
            write_log_line(sh, out_path);
        }

        store_file_result(sh, idx, ok, &start_ts, &end_ts);
    }

    return NULL;
}

static int run_sequential(const char **inputs,
                          int input_count,
                          const char *out_dir,
                          unsigned char key,
                          shared_t *sh,
                          run_stats_t *stats) {
    int i;

    set_key((char)key);

    for (i = 0; i < input_count; ++i) {
        char out_path[1024];
        struct timespec start_ts;
        struct timespec end_ts;
        int ok;

        if (clock_gettime(CLOCK_MONOTONIC, &start_ts) != 0) {
            perror("clock_gettime start");
            return 0;
        }

        ok = process_one_file(inputs[i], out_dir, key, out_path, sizeof(out_path));

        if (clock_gettime(CLOCK_MONOTONIC, &end_ts) != 0) {
            perror("clock_gettime end");
            return 0;
        }

        stats->files[i].start = start_ts;
        stats->files[i].end = end_ts;
        stats->files[i].duration_ms = diff_ms(&start_ts, &end_ts);
        stats->files[i].ok = ok;
        stats->processed_files++;

        if (!ok) {
            stats->failed_files++;
            fprintf(stderr, "Ошибка обработки файла: %s\n", inputs[i]);
        } else {
            write_log_line(sh, out_path);
        }
    }

    return 1;
}

static int run_parallel(const char **inputs,
                        int input_count,
                        const char *out_dir,
                        unsigned char key,
                        shared_t *sh,
                        run_stats_t *stats) {
    pthread_t workers[WORKERS_COUNT];
    int queue_size = input_count;
    int worker_count = input_count < WORKERS_COUNT ? input_count : WORKERS_COUNT;
    int i;

    (void)inputs;
    (void)out_dir;
    (void)key;
    (void)stats;

    sh->queue = (int *)malloc((size_t)queue_size * sizeof(int));
    if (sh->queue == NULL) {
        fprintf(stderr, "Ошибка: не удалось выделить память под очередь задач\n");
        return 0;
    }

    for (i = 0; i < queue_size; ++i) {
        sh->queue[i] = i;
    }

    sh->queue_head = 0;
    sh->queue_count = queue_size;
    sh->start_flag = 0;

    if (pthread_mutex_init(&sh->queue_mutex, NULL) != 0) {
        perror("pthread_mutex_init queue_mutex");
        free(sh->queue);
        sh->queue = NULL;
        return 0;
    }

    if (pthread_mutex_init(&sh->stats_mutex, NULL) != 0) {
        perror("pthread_mutex_init stats_mutex");
        pthread_mutex_destroy(&sh->queue_mutex);
        free(sh->queue);
        sh->queue = NULL;
        return 0;
    }

    pthread_mutex_lock(&sh->stats_mutex);
    sh->fatal_error = 0;
    pthread_mutex_unlock(&sh->stats_mutex);

    if (pthread_cond_init(&sh->queue_cond, NULL) != 0) {
        perror("pthread_cond_init queue_cond");
        pthread_mutex_destroy(&sh->stats_mutex);
        pthread_mutex_destroy(&sh->queue_mutex);
        free(sh->queue);
        sh->queue = NULL;
        return 0;
    }

    set_key((char)sh->key);

    for (i = 0; i < worker_count; ++i) {
        if (pthread_create(&workers[i], NULL, worker_thread, sh) != 0) {
            perror("Ошибка создания потока");
            set_fatal_error(sh);
            worker_count = i;
            break;
        }
    }

    pthread_mutex_lock(&sh->queue_mutex);
    sh->start_flag = 1;
    pthread_cond_broadcast(&sh->queue_cond);
    pthread_mutex_unlock(&sh->queue_mutex);

    for (i = 0; i < worker_count; ++i) {
        pthread_join(workers[i], NULL);
    }

    pthread_cond_destroy(&sh->queue_cond);
    pthread_mutex_destroy(&sh->queue_mutex);
    pthread_mutex_destroy(&sh->stats_mutex);
    free(sh->queue);
    sh->queue = NULL;

    return get_fatal_error(sh) ? 0 : 1;
}

static int run_mode(const char **inputs,
                    int input_count,
                    const char *out_dir,
                    unsigned char key,
                    run_mode_t mode,
                    shared_t *sh,
                    run_stats_t *stats) {
    struct timespec run_start;
    struct timespec run_end;
    int ok;
    int i;

    stats->mode = mode;
    stats->total_files = input_count;
    stats->processed_files = 0;
    stats->failed_files = 0;
    stats->total_ms = 0.0;
    stats->avg_ms = 0.0;
    sh->stats = stats;

    stats->files = (file_stat_t *)calloc((size_t)input_count, sizeof(file_stat_t));
    if (stats->files == NULL) {
        fprintf(stderr, "Ошибка: не удалось выделить память под статистику\n");
        return 0;
    }

    for (i = 0; i < input_count; ++i) {
        stats->files[i].ok = 0;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &run_start) != 0) {
        perror("clock_gettime run_start");
        free(stats->files);
        stats->files = NULL;
        sh->stats = NULL;
        return 0;
    }

    if (mode == MODE_SEQUENTIAL) {
        ok = run_sequential(inputs, input_count, out_dir, key, sh, stats);
    } else {
        ok = run_parallel(inputs, input_count, out_dir, key, sh, stats);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &run_end) != 0) {
        perror("clock_gettime run_end");
        free(stats->files);
        stats->files = NULL;
        sh->stats = NULL;
        return 0;
    }

    stats->total_ms = diff_ms(&run_start, &run_end);
    if (stats->processed_files > 0) {
        stats->avg_ms = stats->total_ms / (double)stats->processed_files;
    }

    if (!ok) {
        free(stats->files);
        stats->files = NULL;
        sh->stats = NULL;
        return 0;
    }

    sh->stats = NULL;
    return 1;
}

static void print_stats(const run_stats_t *stats, const char **inputs) {
    int i;

    printf("\n=== Статистика режима: %s ===\n", mode_to_str(stats->mode));
    printf("Файлов всего: %d\n", stats->total_files);
    printf("Файлов обработано: %d\n", stats->processed_files);
    printf("Ошибок: %d\n", stats->failed_files);
    printf("Общее время: %.3f ms\n", stats->total_ms);
    printf("Среднее время на файл: %.3f ms\n", stats->avg_ms);
    printf("Детализация по файлам:\n");

    for (i = 0; i < stats->total_files; ++i) {
        printf("  [%d] %s | status=%s | %.3f ms\n",
               i + 1,
               inputs[i],
               stats->files[i].ok ? "ok" : "fail",
               stats->files[i].duration_ms);
    }
}

static void print_auto_comparison(const run_stats_t *chosen,
                                  const run_stats_t *alternative) {
    printf("\n=== Сравнение режимов (auto) ===\n");
    printf("Выбранный режим: %s\n", mode_to_str(chosen->mode));
    printf("%-12s | %-14s | %-14s | %-8s\n", "mode", "total_ms", "avg_ms", "failed");
    printf("%-12s | %-14.3f | %-14.3f | %-8d\n",
           mode_to_str(chosen->mode),
           chosen->total_ms,
           chosen->avg_ms,
           chosen->failed_files);
    printf("%-12s | %-14.3f | %-14.3f | %-8d\n",
           mode_to_str(alternative->mode),
           alternative->total_ms,
           alternative->avg_ms,
           alternative->failed_files);
}

static void free_stats(run_stats_t *stats) {
    free(stats->files);
    stats->files = NULL;
}

int main(int argc, char *argv[]) {
    shared_t sh;
    const char *out_dir;
    const char *chosen_out_dir;
    const char *alternative_out_dir;
    const char **inputs;
    run_mode_t mode = MODE_AUTO;
    run_mode_t chosen_mode;
    run_mode_t alternative_mode;
    run_stats_t chosen_stats;
    run_stats_t alternative_stats;
    char auto_root_dir[1024];
    char chosen_mode_dir[1024];
    char alternative_mode_dir[1024];
    time_t now;
    char key;
    int input_count;
    int first_arg = 1;
    int mode_parse_rc;
    int ok;

    memset(&sh, 0, sizeof(sh));
    memset(&chosen_stats, 0, sizeof(chosen_stats));
    memset(&alternative_stats, 0, sizeof(alternative_stats));

    if (argc >= 2) {
        mode_parse_rc = parse_mode_arg(argv[1], &mode);
        if (mode_parse_rc == 1) {
            first_arg = 2;
        } else if (mode_parse_rc == -1) {
            fprintf(stderr,
                    "Ошибка: неизвестный режим. Используйте --mode=sequential|parallel|auto\n");
            return EXIT_FAILURE;
        }
    }

    if ((argc - first_arg) < 3) {
        fprintf(stderr,
                "Использование: %s [--mode=sequential|parallel|auto] <file1> ... <fileN> <out_dir> <key>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    out_dir = argv[argc - 2];

    if (!parse_key(argv[argc - 1], &key)) {
        fprintf(stderr, "Ошибка: key должен быть целым числом от 0 до 255\n");
        return EXIT_FAILURE;
    }

    input_count = argc - first_arg - 2;
    if (input_count <= 0) {
        fprintf(stderr, "Ошибка: не указаны входные файлы\n");
        return EXIT_FAILURE;
    }

    inputs = (const char **)&argv[first_arg];

    ensure_out_dir_or_die(out_dir);

    sh.inputs = inputs;
    sh.input_count = input_count;
    sh.out_dir = out_dir;
    sh.key = (unsigned char)key;

    if (pthread_mutex_init(&sh.log_mutex, NULL) != 0) {
        perror("pthread_mutex_init log_mutex");
        return EXIT_FAILURE;
    }

    sh.log_file = fopen("log.txt", "a");
    if (sh.log_file == NULL) {
        perror("Ошибка открытия log.txt");
        pthread_mutex_destroy(&sh.log_mutex);
        return EXIT_FAILURE;
    }

    chosen_mode = mode == MODE_AUTO ? choose_mode_heuristic(input_count) : mode;
    alternative_mode = chosen_mode == MODE_SEQUENTIAL ? MODE_PARALLEL : MODE_SEQUENTIAL;

    chosen_out_dir = out_dir;
    alternative_out_dir = out_dir;

    if (mode == MODE_AUTO) {
        now = time(NULL);
        if (snprintf(auto_root_dir,
                     sizeof(auto_root_dir),
                     "%s/auto_run_%ld_%ld",
                     out_dir,
                     (long)getpid(),
                     (long)now) >= (int)sizeof(auto_root_dir)) {
            fprintf(stderr, "Ошибка: слишком длинный путь папки вывода\n");
            fclose(sh.log_file);
            pthread_mutex_destroy(&sh.log_mutex);
            return EXIT_FAILURE;
        }

        ensure_out_dir_or_die(auto_root_dir);

        if (snprintf(chosen_mode_dir,
                     sizeof(chosen_mode_dir),
                     "%s/%s",
                     auto_root_dir,
                     mode_to_str(chosen_mode)) >= (int)sizeof(chosen_mode_dir)) {
            fprintf(stderr, "Ошибка: слишком длинный путь папки выбранного режима\n");
            fclose(sh.log_file);
            pthread_mutex_destroy(&sh.log_mutex);
            return EXIT_FAILURE;
        }

        if (snprintf(alternative_mode_dir,
                     sizeof(alternative_mode_dir),
                     "%s/%s",
                     auto_root_dir,
                     mode_to_str(alternative_mode)) >= (int)sizeof(alternative_mode_dir)) {
            fprintf(stderr, "Ошибка: слишком длинный путь папки альтернативного режима\n");
            fclose(sh.log_file);
            pthread_mutex_destroy(&sh.log_mutex);
            return EXIT_FAILURE;
        }

        ensure_out_dir_or_die(chosen_mode_dir);
        ensure_out_dir_or_die(alternative_mode_dir);

        chosen_out_dir = chosen_mode_dir;
        alternative_out_dir = alternative_mode_dir;

        printf("Auto output root: %s\n", auto_root_dir);
    }

    ok = run_mode(inputs,
                  input_count,
                  chosen_out_dir,
                  (unsigned char)key,
                  chosen_mode,
                  &sh,
                  &chosen_stats);
    if (!ok) {
        fprintf(stderr, "Ошибка запуска режима: %s\n", mode_to_str(chosen_mode));
        fclose(sh.log_file);
        pthread_mutex_destroy(&sh.log_mutex);
        return EXIT_FAILURE;
    }

    print_stats(&chosen_stats, inputs);

    if (mode == MODE_AUTO) {
        ok = run_mode(inputs,
                      input_count,
                      alternative_out_dir,
                      (unsigned char)key,
                      alternative_mode,
                      &sh,
                      &alternative_stats);
        if (!ok) {
            fprintf(stderr, "Ошибка запуска альтернативного режима: %s\n",
                    mode_to_str(alternative_mode));
            free_stats(&chosen_stats);
            fclose(sh.log_file);
            pthread_mutex_destroy(&sh.log_mutex);
            return EXIT_FAILURE;
        }

        print_stats(&alternative_stats, inputs);
        print_auto_comparison(&chosen_stats, &alternative_stats);
        free_stats(&alternative_stats);
    }

    free_stats(&chosen_stats);

    fclose(sh.log_file);
    pthread_mutex_destroy(&sh.log_mutex);

    return EXIT_SUCCESS;
}