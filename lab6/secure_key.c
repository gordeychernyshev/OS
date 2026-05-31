#include "secure_key.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static void *g_key_page = NULL;
static size_t g_page_size = 0;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char g_sigsegv_key_msg[] =
    "Ошибка безопасности: попытка доступа к защищенной памяти ключа\n";
static const char g_sigsegv_other_msg[] =
    "Ошибка: получен SIGSEGV вне защищенной памяти ключа\n";

static int address_inside_key_page(const void *addr) {
    uintptr_t start;
    uintptr_t current;

    if (g_key_page == NULL || g_page_size == 0 || addr == NULL) {
        return 0;
    }

    start = (uintptr_t)g_key_page;
    current = (uintptr_t)addr;

    return current >= start && current - start < g_page_size;
}

static void segv_handler(int signo, siginfo_t *info, void *context) {
    (void)signo;
    (void)context;

    if (info != NULL && address_inside_key_page(info->si_addr)) {
        write(STDERR_FILENO, g_sigsegv_key_msg, sizeof(g_sigsegv_key_msg) - 1);
    } else {
        write(STDERR_FILENO,
              g_sigsegv_other_msg,
              sizeof(g_sigsegv_other_msg) - 1);
    }

    _exit(EXIT_FAILURE);
}

static void install_sigsegv_handler(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        perror("sigaction SIGSEGV");
        exit(EXIT_FAILURE);
    }
}

static void wipe_key_page(void) {
    memset(g_key_page, 0, g_page_size);
}

static int key_page_is_zero(void) {
    volatile unsigned char *p = (volatile unsigned char *)g_key_page;
    size_t i;

    for (i = 0; i < g_page_size; ++i) {
        if (p[i] != 0) {
            return 0;
        }
    }

    return 1;
}

void secure_key_init(void) {
    long page_size;

    if (g_key_page != NULL) {
        return;
    }

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        fprintf(stderr, "Ошибка: не удалось получить размер страницы памяти\n");
        exit(EXIT_FAILURE);
    }
    g_page_size = (size_t)page_size;

    g_key_page = mmap(NULL,
                      g_page_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1,
                      0);
    if (g_key_page == MAP_FAILED) {
        perror("mmap");
        g_key_page = NULL;
        exit(EXIT_FAILURE);
    }

    install_sigsegv_handler();

    if (mprotect(g_key_page, g_page_size, PROT_NONE) != 0) {
        perror("mprotect PROT_NONE");
        munmap(g_key_page, g_page_size);
        g_key_page = NULL;
        exit(EXIT_FAILURE);
    }
}

void secure_key_set_byte(unsigned char key) {
    unsigned char tmp = key;

    if (g_key_page == NULL) {
        secure_key_init();
    }

    pthread_mutex_lock(&g_key_mutex);

    if (mprotect(g_key_page, g_page_size, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect PROT_READ | PROT_WRITE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    memcpy(g_key_page, &tmp, sizeof(tmp));
    memset(&tmp, 0, sizeof(tmp));

    if (mprotect(g_key_page, g_page_size, PROT_NONE) != 0) {
        perror("mprotect PROT_NONE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    pthread_mutex_unlock(&g_key_mutex);
}

void secure_key_set_from_string(const char *text) {
    char *endptr = NULL;
    long value;
    unsigned char key;

    if (text == NULL || text[0] == '\0') {
        fprintf(stderr, "Ошибка: key должен быть целым числом от 0 до 255\n");
        exit(EXIT_FAILURE);
    }

    value = strtol(text, &endptr, 10);
    if (*endptr != '\0' || value < 0 || value > 255) {
        fprintf(stderr, "Ошибка: key должен быть целым числом от 0 до 255\n");
        exit(EXIT_FAILURE);
    }

    key = (unsigned char)value;
    secure_key_set_byte(key);
    key = 0;
}

const unsigned char *secure_key_begin_read(void) {
    if (g_key_page == NULL) {
        fprintf(stderr, "Ошибка: защищенный ключ не инициализирован\n");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_lock(&g_key_mutex);

    if (mprotect(g_key_page, g_page_size, PROT_READ) != 0) {
        perror("mprotect PROT_READ");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    return (const unsigned char *)g_key_page;
}

void secure_key_end_read(void) {
    if (g_key_page == NULL) {
        fprintf(stderr, "Ошибка: защищенный ключ не инициализирован\n");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    if (mprotect(g_key_page, g_page_size, PROT_NONE) != 0) {
        perror("mprotect PROT_NONE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    pthread_mutex_unlock(&g_key_mutex);
}

void secure_key_destroy(void) {
    if (g_key_page == NULL) {
        return;
    }

    pthread_mutex_lock(&g_key_mutex);

    if (mprotect(g_key_page, g_page_size, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect PROT_READ | PROT_WRITE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    wipe_key_page();

    if (mprotect(g_key_page, g_page_size, PROT_NONE) != 0) {
        perror("mprotect PROT_NONE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    if (munmap(g_key_page, g_page_size) != 0) {
        perror("munmap");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    g_key_page = NULL;
    g_page_size = 0;

    pthread_mutex_unlock(&g_key_mutex);
}

void secure_key_test_illegal_write(void) {
    unsigned char *p;

    if (g_key_page == NULL) {
        fprintf(stderr, "Ошибка: защищенный ключ не инициализирован\n");
        exit(EXIT_FAILURE);
    }

    printf("Тест защиты ключа: ключ находится в mmap-памяти\n");
    printf("Тест защиты ключа: устанавливаем права PROT_READ\n");

    if (mprotect(g_key_page, g_page_size, PROT_READ) != 0) {
        perror("mprotect PROT_READ");
        exit(EXIT_FAILURE);
    }

    printf("Тест защиты ключа: пробуем напрямую записать в защищенную память\n");
    fflush(stdout);

    p = (unsigned char *)g_key_page;
    *p = 123;

    fprintf(stderr, "Ошибка: запись в защищенную память неожиданно удалась\n");
    exit(EXIT_FAILURE);
}

void secure_key_test_destroy(void) {
    if (g_key_page == NULL) {
        fprintf(stderr, "Ошибка: защищенный ключ не инициализирован\n");
        exit(EXIT_FAILURE);
    }

    printf("Тест уничтожения ключа: ключ находится в mmap-памяти\n");

    pthread_mutex_lock(&g_key_mutex);

    if (mprotect(g_key_page, g_page_size, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect PROT_READ | PROT_WRITE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    wipe_key_page();

    if (key_page_is_zero()) {
        printf("Тест уничтожения ключа: область ключа затерта нулями\n");
    } else {
        fprintf(stderr, "Ошибка: ключ не был затерт\n");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    if (mprotect(g_key_page, g_page_size, PROT_NONE) != 0) {
        perror("mprotect PROT_NONE");
        pthread_mutex_unlock(&g_key_mutex);
        exit(EXIT_FAILURE);
    }

    pthread_mutex_unlock(&g_key_mutex);

    secure_key_destroy();

    printf("Тест уничтожения ключа: память освобождена через munmap\n");
}
