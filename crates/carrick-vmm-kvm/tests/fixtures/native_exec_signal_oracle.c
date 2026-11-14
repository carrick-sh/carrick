/* Native Linux authority for parked exec signals. Uses only Linux seccomp(2),
 * signal(7), and wait(2) API descriptions; no outside implementation source. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int report_fd;
static int tid_fd;
static void caught(int sig) { (void)sig; (void)write(report_fd, "H\n", 2); }
static void *sibling(void *unused) {
    (void)unused;
    int tid = (int)syscall(SYS_gettid);
    if (write(tid_fd, &tid, sizeof(tid)) != sizeof(tid)) _exit(90);
    for (;;) pause();
}
static int listener(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = 4, .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int two = strcmp(argv[1], "two") == 0;
    /* Sender and target share one CPU: the target cannot run between the
     * caught and fatal kill(2) calls merely because the host has spare CPUs. */
    cpu_set_t allowed, one_cpu;
    if (sched_getaffinity(0, sizeof(allowed), &allowed)) return 13;
    int cpu = -1;
    for (int index = 0; index < CPU_SETSIZE; ++index) {
        if (CPU_ISSET(index, &allowed)) { cpu = index; break; }
    }
    if (cpu < 0) return 14;
    CPU_ZERO(&one_cpu);
    CPU_SET(cpu, &one_cpu);
    if (sched_setaffinity(0, sizeof(one_cpu), &one_cpu)) return 15;
    int report[2], tids[2];
    if (pipe(report) || pipe(tids)) return 3;
    int notify = listener();
    if (notify < 0) { perror("seccomp listener"); return 4; }
    pid_t child = fork();
    if (child < 0) return 5;
    if (child == 0) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL)) _exit(93);
        close(report[0]); close(tids[0]);
        report_fd = report[1]; tid_fd = tids[1];
        if (two) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, sibling, NULL)) _exit(91);
        } else {
            struct sigaction action = { .sa_handler = caught };
            sigemptyset(&action.sa_mask);
            if (sigaction(SIGUSR1, &action, NULL)) _exit(92);
        }
        char *const args[] = { "/bin/true", NULL };
        execve(args[0], args, NULL);
        (void)write(report_fd, "R\n", 2);
        _exit(197);
    }
    close(report[1]); close(tids[1]);
    int sibling_tid = 0;
    if (two && read(tids[0], &sibling_tid, sizeof(sibling_tid)) != sizeof(sibling_tid)) return 6;
    struct seccomp_notif request = {0};
    if (ioctl(notify, SECCOMP_IOCTL_NOTIF_RECV, &request)) { perror("notif recv"); return 7; }
    if (request.pid != (unsigned)child) return 8;
    if (two) {
        if (syscall(SYS_tgkill, child, sibling_tid, SIGTERM)) return 9;
    } else {
        if (kill(child, SIGUSR1) || kill(child, SIGTERM)) return 11;
    }
    int status;
    if (waitpid(child, &status, 0) != child) return 12;
    char output[32] = {0};
    ssize_t bytes = read(report[0], output, sizeof(output));
    printf("case=%s seccomp_exec_parked=1 threads=%d signaled=%d signal=%d old_image_bytes=%zd\n",
           two ? "sibling_fatal" : "caught_then_fatal", two ? 2 : 1,
           WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0, bytes);
    return !(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM && bytes == 0);
}
