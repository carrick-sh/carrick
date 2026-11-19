// Build with cc -static -no-pie. The default path is the guest mount point.
#define _GNU_SOURCE
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char *path = argc > 1 ? argv[1] : "/fork-exec-child";
    char *const child_argv[] = {path, NULL};
    char *const child_envp[] = {NULL};

    pid_t child = fork();
    if (child < 0)
        return 32 + errno;
    if (child == 0) {
        execve(path, child_argv, child_envp);
        _exit(128 + errno);
    }

    int status = 0;
    if (wait4(child, &status, 0, NULL) != child)
        return 64 + errno;
    if (!WIFEXITED(status))
        return 3;
    if (WEXITSTATUS(status) != 7)
        return WEXITSTATUS(status) >= 128 ? WEXITSTATUS(status) : 4;

    static const char message[] = "parent reaped exit 7\n";
    return write(STDOUT_FILENO, message, sizeof(message) - 1) ==
           sizeof(message) - 1 ? 0 : 5;
}
