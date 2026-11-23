// CPU affinity on x86_64 (#1906): `sched_getaffinity` and
// `sched_setaffinity` by the run root, by a second live thread, and by a
// fork child. The Go runtime sizes its scheduler from `sched_getaffinity`
// at startup, so a refusal here is on every Go row. Every line is
// `who.name result`, with a failure printed as `-errno`; the native run is
// the oracle. Only facts both worlds share are printed: never a CPU count
// or a mask value.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *who;

static long call(long ret) { return ret < 0 ? -errno : ret; }

static void value(const char *name, long ret) { printf("%s.%s %ld\n", who, name, ret); }

static long get(long pid, unsigned long size, void *mask) {
    return call(syscall(SYS_sched_getaffinity, pid, size, mask));
}

static long set(long pid, unsigned long size, void *mask) {
    return call(syscall(SYS_sched_setaffinity, pid, size, mask));
}

// The reads every caller makes: its own mask by pid 0 and by its tid, the
// size rules, and the pid and pointer errors.
static unsigned long reads(void) {
    unsigned long mask = 0, by_tid = 0;
    value("get.self", get(0, sizeof mask, &mask));
    value("get.self.nonempty", mask != 0);
    value("get.by_tid", get(syscall(SYS_gettid), sizeof by_tid, &by_tid));
    value("get.by_tid.same", by_tid == mask);
    value("get.size0", get(0, 0, &mask));
    value("get.size7", get(0, 7, &mask));
    value("get.no_such_pid", get(0x7ffffff0, sizeof mask, &mask));
    value("get.negative_pid", get(-1, sizeof mask, &mask));
    value("get.bad_address", get(0, sizeof mask, (void *)8));
    return mask;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t turn = PTHREAD_COND_INITIALIZER;
static int stage;
static long worker_tid;
static unsigned long worker_mask;

static void advance(int to) {
    pthread_mutex_lock(&lock);
    stage = to;
    pthread_cond_broadcast(&turn);
    pthread_mutex_unlock(&lock);
}

static void await(int want) {
    pthread_mutex_lock(&lock);
    while (stage < want) {
        pthread_cond_wait(&turn, &lock);
    }
    pthread_mutex_unlock(&lock);
}

static void *worker(void *unused) {
    (void)unused;
    worker_tid = syscall(SYS_gettid);
    get(0, sizeof worker_mask, &worker_mask);
    advance(1);
    // Stay alive while the main thread reads and narrows this thread's mask.
    await(2);
    unsigned long now = 0;
    long ret = get(0, sizeof now, &now);
    pthread_mutex_lock(&lock);
    worker_mask = ret < 0 ? 0 : now;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    who = "root";
    unsigned long mask = reads();
    unsigned long lowest = mask & -mask;

    // A second live thread: the mask is per thread, and one thread may read
    // and set another's.
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0) {
        return 2;
    }
    await(1);
    unsigned long other = 0;
    value("thread.inherits", worker_mask == mask);
    value("thread.get", get(worker_tid, sizeof other, &other));
    value("thread.get.same", other == mask);
    value("thread.set", set(worker_tid, sizeof lowest, &lowest));
    unsigned long mine = 0;
    get(0, sizeof mine, &mine);
    value("thread.set.leaves_caller", mine == mask);
    advance(2);
    pthread_join(thread, NULL);
    value("thread.sees_its_set", worker_mask == lowest);

    // Set errors, then narrow the caller itself.
    unsigned long none = 0;
    value("set.empty", set(0, sizeof none, &none));
    value("set.bad_address", set(0, sizeof none, (void *)8));
    value("set.no_such_pid", set(0x7ffffff0, sizeof lowest, &lowest));
    value("set.self", set(0, sizeof lowest, &lowest));
    unsigned long narrowed = 0;
    value("set.self.get", get(0, sizeof narrowed, &narrowed));
    value("set.self.took", narrowed == lowest);

    // A fork child inherits the narrowed mask and serves the same calls.
    pid_t child = fork();
    if (child < 0) {
        return 3;
    }
    if (child == 0) {
        who = "child";
        unsigned long inherited = reads();
        value("inherits", inherited == lowest);
        value("set.widen", set(0, sizeof mask, &mask));
        unsigned long widened = 0;
        get(0, sizeof widened, &widened);
        value("set.widen.took", widened == mask);
        _exit(0);
    }
    int status = 0;
    waitpid(child, &status, 0);
    value("child.status", status);
    unsigned long after = 0;
    get(0, sizeof after, &after);
    value("child.set.leaves_parent", after == lowest);
    return 0;
}
