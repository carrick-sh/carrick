#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const int FILES = 16;
static const off_t FILE_BYTES = 1024 * 1024;
static const int WARMUP = 64;
static const int UPDATES = 512;
static const char WRITE_BYTE = 'x';

static void die(const char *what) {
    fprintf(stderr, "%s failed errno=%d (%s)\n", what, errno, strerror(errno));
    exit(1);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        die("clock_gettime");
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    const uint64_t left = *(const uint64_t *)a;
    const uint64_t right = *(const uint64_t *)b;
    return (left > right) - (left < right);
}

static long nproc(void) {
    const char *override = getenv("BENCH_NPROC");
    if (override != NULL && override[0] != '\0') {
        char *end = NULL;
        errno = 0;
        long value = strtol(override, &end, 10);
        if (errno == 0 && end != override && *end == '\0' && value > 0) {
            return value;
        }
    }
    long value = sysconf(_SC_NPROCESSORS_ONLN);
    return value > 0 ? value : 0;
}

static void create_file(const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        die("open(create)");
    }
    if (ftruncate(fd, FILE_BYTES) != 0) {
        die("ftruncate");
    }
    if (close(fd) != 0) {
        die("close(create)");
    }
}

static void update_once(char paths[][PATH_MAX], int iteration) {
    const char *path = paths[iteration % FILES];
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        die("open(update)");
    }
    off_t offset = (off_t)(((uint64_t)iteration * 4099u) % (uint64_t)FILE_BYTES);
    if (lseek(fd, offset, SEEK_SET) != offset) {
        die("lseek");
    }
    ssize_t n = write(fd, &WRITE_BYTE, 1);
    if (n != 1) {
        die("write");
    }
    if (close(fd) != 0) {
        die("close(update)");
    }
}

int main(void) {
    const char *dir = getenv("BENCH_DIR");
    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }
    if (mkdir(dir, 0777) != 0 && errno != EEXIST) {
        die("mkdir");
    }

    char paths[16][PATH_MAX];
    for (int i = 0; i < FILES; i++) {
        int n = snprintf(
            paths[i],
            sizeof(paths[i]),
            "%s/carrick_dynamic_overlay_small_updates_%ld_%d.dat",
            dir,
            (long)getpid(),
            i);
        if (n < 0 || (size_t)n >= sizeof(paths[i])) {
            fprintf(stderr, "path too long for benchmark file\n");
            return 1;
        }
        create_file(paths[i]);
    }

    for (int iteration = 0; iteration < WARMUP; iteration++) {
        update_once(paths, iteration);
    }

    uint64_t samples[512];
    uint64_t total_start = now_ns();
    for (int iteration = 0; iteration < UPDATES; iteration++) {
        uint64_t start = now_ns();
        update_once(paths, iteration + WARMUP);
        samples[iteration] = now_ns() - start;
    }
    uint64_t total_ns = now_ns() - total_start;

    qsort(samples, UPDATES, sizeof(samples[0]), cmp_u64);
    double p50_us = (double)samples[UPDATES / 2] / 1000.0;
    double total_us = (double)total_ns / 1000.0;

    for (int i = 0; i < FILES; i++) {
        unlink(paths[i]);
    }

    printf("dynamic_overlay_small_updates_p50_us=%.3f\n", p50_us);
    printf("dynamic_overlay_small_updates_total_us=%.3f\n", total_us);
    printf("files=%d\n", FILES);
    printf("file_bytes=%lld\n", (long long)FILE_BYTES);
    printf("updates=%d\n", UPDATES);
    printf("write_bytes=1\n");
    printf("nproc=%ld\n", nproc());
    return 0;
}
