#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "caesar.h"

#define CHUNK_SIZE 8192
#define QUEUE_CAPACITY 4

volatile sig_atomic_t keep_running = 1;

typedef struct {
    unsigned char data[CHUNK_SIZE];
    size_t size;
    int is_last;
} chunk_t;

typedef struct {
    chunk_t items[QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int producer_done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} queue_t;

typedef struct {
    FILE *input;
    queue_t *queue;
    char key;
} producer_args_t;

typedef struct {
    FILE *output;
    queue_t *queue;
} consumer_args_t;

static void handle_sigint(int signo) {
    (void)signo;
    keep_running = 0;
}

static void queue_init(queue_t *queue) {
    queue->head = 0;
    queue->tail = 0;
    queue->count = 0;
    queue->producer_done = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
}

static void queue_destroy(queue_t *queue) {
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
}

static int queue_push(queue_t *queue, const chunk_t *chunk) {
    pthread_mutex_lock(&queue->mutex);

    while (queue->count == QUEUE_CAPACITY && keep_running) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }

    if (!keep_running) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    queue->items[queue->tail] = *chunk;
    queue->tail = (queue->tail + 1) % QUEUE_CAPACITY;
    queue->count++;

    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);

    return 1;
}

static int queue_pop(queue_t *queue, chunk_t *chunk) {
    pthread_mutex_lock(&queue->mutex);

    while (queue->count == 0 && !queue->producer_done && keep_running) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }

    if (queue->count == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    *chunk = queue->items[queue->head];
    queue->head = (queue->head + 1) % QUEUE_CAPACITY;
    queue->count--;

    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);

    return 1;
}

static void queue_mark_done(queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    queue->producer_done = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

static void wake_all(queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

static void *producer_thread(void *arg) {
    producer_args_t *args = (producer_args_t *)arg;
    unsigned char input_buf[CHUNK_SIZE];
    unsigned char encrypted_buf[CHUNK_SIZE];

    set_key(args->key);

    while (keep_running) {
        size_t bytes_read = fread(input_buf, 1, CHUNK_SIZE, args->input);

        if (bytes_read > 0) {
            chunk_t chunk;

            caesar(input_buf, encrypted_buf, (int)bytes_read);
            memcpy(chunk.data, encrypted_buf, bytes_read);
            chunk.size = bytes_read;
            chunk.is_last = 0;

            if (feof(args->input)) {
                chunk.is_last = 1;
            }

            if (!queue_push(args->queue, &chunk)) {
                break;
            }
        }

        if (bytes_read < CHUNK_SIZE) {
            if (ferror(args->input)) {
                perror("Ошибка чтения входного файла");
                keep_running = 0;
            }
            break;
        }
    }

    queue_mark_done(args->queue);
    return NULL;
}

static void *consumer_thread(void *arg) {
    consumer_args_t *args = (consumer_args_t *)arg;
    chunk_t chunk;

    while (keep_running || !args->queue->producer_done ||
           args->queue->count > 0) {
        if (!queue_pop(args->queue, &chunk)) {
            if (!keep_running && args->queue->count == 0) {
                break;
            }
            if (args->queue->producer_done) {
                break;
            }
            continue;
        }

        if (chunk.size > 0) {
            size_t bytes_written = fwrite(chunk.data, 1, chunk.size,
                                          args->output);
            if (bytes_written != chunk.size) {
                perror("Ошибка записи в выходной файл");
                keep_running = 0;
                wake_all(args->queue);
                break;
            }
        }

        if (chunk.is_last) {
            break;
        }
    }

    return NULL;
}

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

int main(int argc, char *argv[]) {
    FILE *input = NULL;
    FILE *output = NULL;
    pthread_t producer;
    pthread_t consumer;
    queue_t queue;
    producer_args_t producer_args;
    consumer_args_t consumer_args;
    struct sigaction sa;
    char key;

    if (argc != 4) {
        fprintf(stderr, "Использование: %s <input> <output> <key>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    if (!parse_key(argv[3], &key)) {
        fprintf(stderr,
                "Ошибка: ключ должен быть целым числом от 0 до 255\n");
        return EXIT_FAILURE;
    }

    input = fopen(argv[1], "rb");
    if (input == NULL) {
        perror("Ошибка открытия входного файла");
        return EXIT_FAILURE;
    }

    output = fopen(argv[2], "wb");
    if (output == NULL) {
        perror("Ошибка открытия выходного файла");
        fclose(input);
        return EXIT_FAILURE;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        perror("Ошибка установки обработчика SIGINT");
        fclose(input);
        fclose(output);
        return EXIT_FAILURE;
    }

    queue_init(&queue);

    producer_args.input = input;
    producer_args.queue = &queue;
    producer_args.key = key;

    consumer_args.output = output;
    consumer_args.queue = &queue;

    if (pthread_create(&producer, NULL, producer_thread, &producer_args) !=
        0) {
        perror("Ошибка создания producer thread");
        queue_destroy(&queue);
        fclose(input);
        fclose(output);
        return EXIT_FAILURE;
    }

    if (pthread_create(&consumer, NULL, consumer_thread, &consumer_args) !=
        0) {
        perror("Ошибка создания consumer thread");
        keep_running = 0;
        wake_all(&queue);
        pthread_join(producer, NULL);
        queue_destroy(&queue);
        fclose(input);
        fclose(output);
        return EXIT_FAILURE;
    }

    pthread_join(producer, NULL);
    wake_all(&queue);
    pthread_join(consumer, NULL);

    queue_destroy(&queue);

    fclose(input);
    fclose(output);

    if (!keep_running) {
        printf("Операция прервана пользователем\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}