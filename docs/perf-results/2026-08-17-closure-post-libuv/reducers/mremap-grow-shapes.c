#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

static long PS;

static void one(const char *name, int prot, int flags, int use_fd, unsigned long mvflags,
               int touch_tail)
{
    int fd = -1;
    if (use_fd) {
        char tmpl[] = "/tmp/mrXXXXXX";
        fd = mkstemp(tmpl);
        if (fd < 0) { printf("%-34s SETUP-FAIL mkstemp %d\n", name, errno); return; }
        unlink(tmpl);
        if (ftruncate(fd, PS * 4) != 0) { printf("%-34s SETUP-FAIL ftruncate\n", name); return; }
    }
    void *p = mmap(NULL, PS, prot, flags, fd, 0);
    if (p == MAP_FAILED) { printf("%-34s SETUP-FAIL mmap %d\n", name, errno); return; }
    ((char *)p)[0] = 'a';
    errno = 0;
    void *q = mremap(p, PS, PS * 2, mvflags);
    if (q == MAP_FAILED) {
        printf("%-34s FAIL errno=%d\n", name, errno);
    } else {
        char first = ((char *)q)[0];
        char tail = '-';
        if (touch_tail) { ((char *)q)[PS] = 'z'; tail = ((char *)q)[PS]; }
        printf("%-34s ok moved=%d first=%c tail=%c\n", name, q != p, first, tail);
        munmap(q, PS * 2);
    }
    if (fd >= 0) close(fd);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    PS = sysconf(_SC_PAGESIZE);
    printf("pagesize=%ld\n", PS);
    one("priv-anon grow MAYMOVE",   PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, MREMAP_MAYMOVE, 1);
    one("priv-anon grow noflag",    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0, 1);
    one("shared-anon grow MAYMOVE", PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS,  0, MREMAP_MAYMOVE, 0);
    one("shared-anon grow noflag",  PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS,  0, 0, 0);
    one("shared-file grow MAYMOVE", PROT_READ|PROT_WRITE, MAP_SHARED,                1, MREMAP_MAYMOVE, 1);
    one("priv-file grow MAYMOVE",   PROT_READ|PROT_WRITE, MAP_PRIVATE,               1, MREMAP_MAYMOVE, 1);
    return 0;
}
