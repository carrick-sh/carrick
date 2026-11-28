// apt's cache growth, through glibc (#2611). apt-get builds its package
// cache in a 24 MiB private anonymous map it fills, then grows it 1 MiB at a
// time with mremap(MREMAP_MAYMOVE), 28 times in a Debian `apt-get update`;
// Linux moves the populated map whenever the next MiB is taken. Here a
// blocker one MiB past the map makes the first growth stay in place and
// the second move, as in the native trace; later steps may move or not.
// Each step must keep every byte written so far, read 0 in the new MiB,
// and take stores there. The root runs the shape, then a forked child
// (apt's own case) beside its waiting parent.
// Prints one line per run and `apt cache growth ok`; exits 7. A failure
// prints `FAIL <run> step=<n> <what> <value>` and exits 1.
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MIB (1024UL * 1024UL)
#define PAGE 4096UL
#define START (24 * MIB)
#define STEPS 28

static void fail(const char *run, int step, const char *what, long value) {
    printf("FAIL %s step=%d %s %ld\n", run, step, what, value);
    fflush(stdout);
    _exit(1);
}

// The tag apt's cache would hold in page `page`: unique per page and run.
static uint64_t tag(uint64_t salt, size_t page) {
    return (salt << 32) ^ (page * 0x9e3779b97f4a7c15ULL) ^ page;
}

static void fill(unsigned char *map, size_t from, size_t to, uint64_t salt) {
    for (size_t off = from; off < to; off += PAGE) {
        *(volatile uint64_t *)(map + off) = tag(salt, off / PAGE);
        map[off + PAGE - 1] = (unsigned char)(off / PAGE);
    }
}

static void check(const char *run, int step, unsigned char *map, size_t len,
                  uint64_t salt) {
    for (size_t off = 0; off < len; off += PAGE) {
        if (*(volatile uint64_t *)(map + off) != tag(salt, off / PAGE))
            fail(run, step, "lost tag at page", (long)(off / PAGE));
        if (map[off + PAGE - 1] != (unsigned char)(off / PAGE))
            fail(run, step, "lost tail at page", (long)(off / PAGE));
    }
}

static void grow_cache(const char *run, uint64_t salt) {
    // Reserve the map, a free MiB after it, then a blocker.
    unsigned char *map = mmap(NULL, START + 2 * MIB, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) fail(run, 0, "mmap errno", errno);
    if (munmap(map + START, 2 * MIB) != 0) fail(run, 0, "munmap errno", errno);
    void *blocker = mmap(map + START + MIB, PAGE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (blocker != map + START + MIB) fail(run, 0, "blocker errno", errno);
    fill(map, 0, START, salt);
    size_t len = START;
    int moves = 0;
    for (int step = 1; step <= STEPS; step++) {
        unsigned char *grown = mremap(map, len, len + MIB, MREMAP_MAYMOVE);
        if (grown == MAP_FAILED) fail(run, step, "mremap errno", errno);
        if (step == 1 && grown != map) fail(run, step, "moved, free MiB", 0);
        if (step == 2 && grown == map) fail(run, step, "in place, blocked", 0);
        if (grown != map) moves++;
        check(run, step, grown, len, salt);
        for (size_t off = len; off < len + MIB; off += PAGE)
            if (*(volatile uint64_t *)(grown + off) != 0 || grown[off + PAGE - 1] != 0)
                fail(run, step, "growth not zero at page", (long)(off / PAGE));
        fill(grown, len, len + MIB, salt);
        map = grown;
        len += MIB;
    }
    check(run, STEPS, map, len, salt);
    if (munmap(map, len) != 0) fail(run, STEPS, "munmap errno", errno);
    if (munmap(blocker, PAGE) != 0) fail(run, STEPS, "munmap blocker errno", errno);
    printf("%s steps=%d bytes=%lu in_place_then_moved moved=%s\n", run, STEPS,
           (unsigned long)len, moves >= 1 ? "yes" : "no");
    fflush(stdout);
}

int main(void) {
    grow_cache("root", 1);
    pid_t pid = fork();
    if (pid < 0) fail("root", 0, "fork errno", errno);
    if (pid == 0) {
        grow_cache("child", 2);
        _exit(0);
    }
    int status = -1;
    if (waitpid(pid, &status, 0) != pid) fail("root", 0, "waitpid errno", errno);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fail("root", 0, "child status", status);
    printf("apt cache growth ok\n");
    return 7;
}
