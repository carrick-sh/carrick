#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int identity(void) {
    errno = 0;
    long uid = syscall(SYS_getuid);
    int uid_errno = errno;

    errno = 0;
    long pid = syscall(SYS_getpid);
    int pid_errno = errno;

    struct timespec now = {0};
    errno = 0;
    int clock_rc = clock_gettime(CLOCK_REALTIME, &now);
    int clock_errno = errno;

    char output[256];
    int length = snprintf(output, sizeof(output),
                          "uid=%ld uid_errno=%d\n"
                          "pid=%ld pid_errno=%d\n"
                          "clock_rc=%d clock_errno=%d\n",
                          uid, uid_errno, pid, pid_errno, clock_rc, clock_errno);
    if (length < 0 || (size_t)length >= sizeof(output)) {
        return 2;
    }
    return syscall(SYS_write, STDOUT_FILENO, output, (size_t)length) == length ? 0 : 3;
}

static int write_markers(void) {
    static const char stdout_marker[] = "INTERCEPT_STDOUT\n";
    static const char stderr_marker[] = "NATIVE_STDERR\n";

    long stdout_written = syscall(SYS_write, STDOUT_FILENO, stdout_marker,
                                  sizeof(stdout_marker) - 1);
    long stderr_written = syscall(SYS_write, STDERR_FILENO, stderr_marker,
                                  sizeof(stderr_marker) - 1);
    return stdout_written == (long)(sizeof(stdout_marker) - 1) &&
                   stderr_written == (long)(sizeof(stderr_marker) - 1)
               ? 0
               : 4;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 64;
    }
    if (strcmp(argv[1], "identity") == 0) {
        return identity();
    }
    if (strcmp(argv[1], "write") == 0) {
        return write_markers();
    }
    return 64;
}
