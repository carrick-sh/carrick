#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static void result(const char *name, ssize_t rc) {
    printf("%s rc=%zd errno=%d\n", name, rc, rc < 0 ? errno : 0);
}

int main(void) {
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *remote = mmap(NULL, page * 3, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (remote == MAP_FAILED) return 2;
    memset(remote, 'A', page);
    memset(remote + page, 'B', page);
    memset(remote + page * 2, 'Z', page);
    if (mprotect(remote + page * 2, page, PROT_NONE) != 0) return 3;

    int ready[2], release[2];
    if (pipe(ready) || pipe(release)) return 4;
    pid_t child = fork();
    if (child < 0) return 5;
    if (child == 0) {
        close(ready[0]); close(release[1]);
        char byte = 'R';
        if (write(ready[1], &byte, 1) != 1) _exit(6);
        if (read(release[0], &byte, 1) != 1) _exit(7);
        _exit(0);
    }
    close(ready[1]); close(release[0]);
    char byte;
    if (read(ready[0], &byte, 1) != 1) return 8;

    unsigned char *local = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (local == MAP_FAILED) return 9;
    memset(local, 'L', page * 2);

    struct iovec liov = { .iov_base = local, .iov_len = page * 2 };
    struct iovec riov = { .iov_base = remote + page, .iov_len = page * 2 };
    errno = 0;
    result("read_remote_midfault", process_vm_readv(child, &liov, 1, &riov, 1, 0));
    printf("read_remote_midfault_bytes first=%u last=%u\n", local[0], local[page - 1]);

    memset(local, 'W', page * 2);
    errno = 0;
    result("write_remote_midfault", process_vm_writev(child, &liov, 1, &riov, 1, 0));
    printf("write_remote_midfault_bytes first=%u last=%u\n", remote[page], remote[page * 2 - 1]);

    if (mprotect(local + page, page, PROT_NONE) != 0) return 10;
    riov.iov_base = remote;
    errno = 0;
    result("read_local_midfault", process_vm_readv(child, &liov, 1, &riov, 1, 0));
    errno = 0;
    result("write_local_midfault", process_vm_writev(child, &liov, 1, &riov, 1, 0));
    if (mprotect(local + page, page, PROT_READ | PROT_WRITE) != 0) return 11;

    pid_t missing = 2000000000;
    struct iovec zero_local = { .iov_base = local, .iov_len = 0 };
    struct iovec four_local = { .iov_base = local, .iov_len = 4 };
    struct iovec zero_remote = { .iov_base = remote, .iov_len = 0 };
    errno = 0;
    result("both_counts_zero_missing", process_vm_readv(missing, NULL, 0, NULL, 0, 0));
    errno = 0;
    result("both_counts_zero_bad_flags", process_vm_readv(missing, NULL, 0, NULL, 0, 1));
    errno = 0;
    result("local_total_zero_bad_remote_array_missing", process_vm_readv(missing, &zero_local, 1, (void *)1, 1, 0));
    errno = 0;
    result("remote_total_zero_missing", process_vm_readv(missing, &four_local, 1, &zero_remote, 1, 0));
    errno = 0;
    result("bad_local_array_remote_count_zero_missing", process_vm_readv(missing, (void *)1, 1, NULL, 0, 0));
    errno = 0;
    result("valid_vectors_missing", process_vm_readv(missing, &four_local, 1, &riov, 1, 0));

    if (write(release[1], "X", 1) != 1) return 12;
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 13;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 14;
}
