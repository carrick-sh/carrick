/* Portable buffered regular-file syscall control. Same source on Darwin/Linux.
 * Measures hot-inode 64-byte overwrite, rewind, positional overwrite and stat.
 * No fsync: these are syscall/page-cache costs, not durable storage throughput.
 * Startup, file creation and final verification are outside timed intervals.
 * Usage: io-floor EXCLUSIVE_FILE [iterations=32768] [samples=9] [phase=all]
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *what) { perror(what); exit(1); }
static uint64_t now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) fail("clock_gettime");
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}
static uint64_t positive(const char *value) {
    char *end;
    errno = 0;
    unsigned long long n = strtoull(value, &end, 10);
    if (errno || *end || !n || n > 100000000) {
        fprintf(stderr, "invalid positive count: %s\n", value); exit(2);
    }
    return (uint64_t)n;
}
int main(int argc, char **argv) {
    if (argc < 2 || argc > 5) return 2;
    uint64_t n = argc > 2 ? positive(argv[2]) : 32768;
    uint64_t samples = argc > 3 ? positive(argv[3]) : 9;
    unsigned char payload[64], verify[64];
    memset(payload, 0x5a, sizeof(payload));
    int fd = open(argv[1], O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) fail("open exclusive fixture");
    if (write(fd, payload, sizeof(payload)) != sizeof(payload)) fail("initialize");
    if (lseek(fd, 0, SEEK_SET) != 0) fail("initial seek");
    const char *names[] = {"seek", "pwrite64", "write64_seek", "fstat"};
    if (argc == 5 && strcmp(argv[4], "all") && strcmp(argv[4], "seek") &&
        strcmp(argv[4], "pwrite64") && strcmp(argv[4], "write64_seek") && strcmp(argv[4], "fstat")) {
        fprintf(stderr, "unknown phase\n"); close(fd); unlink(argv[1]); return 2;
    }
    for (int mode = 0; mode < 4; ++mode) {
        if (argc == 5 && strcmp(argv[4], "all") && strcmp(argv[4], names[mode])) continue;
        /* One equal-sized warmup, excluded from output and timing acceptance. */
        for (uint64_t sample = 0; sample <= samples; ++sample) {
            struct stat st;
            uint64_t start = now_ns();
            for (uint64_t i = 0; i < n; ++i) {
                switch (mode) {
                    case 0:
                        if (lseek(fd, 0, SEEK_SET) != 0) fail("seek");
                        break;
                    case 1:
                        if (pwrite(fd, payload, sizeof(payload), 0) != sizeof(payload)) fail("pwrite");
                        break;
                    case 2:
                        if (write(fd, payload, sizeof(payload)) != sizeof(payload)) fail("write");
                        if (lseek(fd, 0, SEEK_SET) != 0) fail("rewind");
                        break;
                    case 3:
                        if (fstat(fd, &st) || st.st_size != 64) fail("fstat size");
                        break;
                }
            }
            uint64_t elapsed = now_ns() - start;
            if (sample) printf("{\"schema\":1,\"phase\":\"%s\",\"sample\":%" PRIu64
                               ",\"iterations\":%" PRIu64 ",\"calls_per_iteration\":%d,\"elapsed_ns\":%" PRIu64 "}\n",
                               names[mode], sample, n, mode == 2 ? 2 : 1, elapsed);
        }
    }
    struct stat final;
    if (fstat(fd, &final) || final.st_size != 64) fail("final size");
    if (lseek(fd, 0, SEEK_CUR) != 0) fail("final offset");
    if (pread(fd, verify, sizeof(verify), 0) != sizeof(verify)) fail("verify read");
    if (memcmp(payload, verify, sizeof(payload))) { fprintf(stderr, "bytes differ\n"); return 1; }
    if (close(fd)) fail("close");
    if (unlink(argv[1])) fail("unlink");
    puts("{\"schema\":1,\"verified\":true,\"bytes\":64,\"offset\":0,\"removed\":true}");
    return 0;
}
