#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>

/* Exact ltp-mremap01 shape, captured from the Docker oracle with bpftrace:
   open(O_RDWR|O_CREAT,0666) -> write ONE byte -> mmap 0x3e8000 PROT_WRITE
   MAP_SHARED -> write one more byte -> mremap to 0x7d0000 MREMAP_MAYMOVE. */
static int body(void);

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getenv("FORK")) {
        pid_t c = fork();
        if (c == 0) { _exit(body()); }
        int st = 0; waitpid(c, &st, 0);
        printf("child status=%d\n", st);
        return 0;
    }
    return body();
}

static int body(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    unsigned long osz = 0x3e8000UL, nsz = 0x7d0000UL;
    int fd = open("mremapfile", O_RDWR | O_CREAT, 0666);
    if (fd < 0) { printf("open FAIL %d\n", errno); return 1; }
    if (write(fd, "a", 1) != 1) { printf("write FAIL %d\n", errno); return 1; }
    void *p = mmap(NULL, osz, PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { printf("mmap FAIL %d\n", errno); return 1; }
    printf("mmap ok %p\n", p);
    ((char *)p)[0] = 'Z';   /* offset 0 is the only byte inside EOF */
    if (write(fd, "b", 1) != 1) { printf("write2 FAIL %d\n", errno); return 1; }
    if (getenv("INTERPOSE")) {
        void *x = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        printf("interposed %p\n", x);
    }
    errno = 0;
    if (getenv("NOREMAP")) {
        if (munmap(p, osz) != 0) { printf("munmap FAIL errno=%d\n", errno); return 1; }
        printf("munmap ok (no remap)\n");
        goto check;
    }
    void *q = mremap(p, osz, nsz, MREMAP_MAYMOVE);
    if (q == MAP_FAILED) { printf("mremap FAIL errno=%d\n", errno); return 1; }
    printf("mremap ok %p moved=%d\n", q, q != p);
    if (munmap(q, nsz) != 0) { printf("munmap FAIL errno=%d\n", errno); return 1; }
    printf("munmap ok\n");
check:
    {   /* Did the shared write reach the file? */
        char c = '?';
        int rfd = open("mremapfile", O_RDONLY);
        if (rfd >= 0) { if (read(rfd, &c, 1) != 1) c = '!'; close(rfd); }
        printf("writeback byte0=%c\n", c);
    }
    unlink("mremapfile");
    return 0;
}
