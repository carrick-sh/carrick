#define _GNU_SOURCE
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* MAP_FIXED|MAP_PRIVATE fork-privacy lock (Task 9).
 *
 * carrick backs a guest MAP_SHARED mapping with the shared aperture, whose host
 * backing is inherited across fork(2) AND visible to sibling carrick processes.
 * A guest mmap(addr, len, PROT_*, MAP_FIXED|MAP_PRIVATE|MAP_ANON) over such a VA
 * must REPOINT that VA's stage-1 leaf to a PER-PROCESS PRIVATE overlay page, so
 * the guest's "private" stores stay COW-isolated and do NOT leak through the
 * shared backing.
 *
 * On the KVM bug (repoint_private was the trait DEFAULT no-op), the stage-1 leaf
 * is never redirected: the "private" page still aliases the shared backing, so a
 * child's write propagates back to the parent.
 *
 * The test distinguishes SHARED from PRIVATE using a SECOND page that STAYS
 * shared as the cross-process signal:
 *   - page 0 ("test") is repointed PRIVATE — a child write to it must NOT be
 *     visible to the parent (COW isolation).
 *   - page 1 ("sync") stays SHARED — the child writes it to signal the parent
 *     that it has done its (private) write, and that write DOES propagate
 *     (proving the shared path itself works and we are not just racing). */

int main(void) {
  long ps = sysconf(_SC_PAGESIZE);
  if (ps <= 0) {
    return 2;
  }
  /* Two contiguous shared-aperture pages. */
  char *base = mmap(NULL, (size_t)(2 * ps), PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    return 2;
  }
  volatile char *test = base;            /* page 0 — repointed PRIVATE below */
  volatile char *sync = base + ps;       /* page 1 — stays SHARED            */
  *sync = 0;

  /* Repoint ONLY page 0 to a per-process private overlay. */
  if (mmap(base, (size_t)ps, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
    return 4;
  }
  test[0] = 0x42;                        /* private baseline */

  pid_t pid = fork();
  if (pid < 0) {
    return 2;
  }
  if (pid == 0) {                        /* CHILD */
    test[0] = 0x99;                      /* write the (now private) page */
    __sync_synchronize();
    *sync = 1;                           /* signal via the still-shared page */
    _exit(0);
  }

  /* Wait for the child's write via the SHARED sync page (it must propagate). */
  while (*sync == 0) {
    sched_yield();
  }
  int st;
  waitpid(pid, &st, 0);

  /* page 0 is PRIVATE: the child's 0x99 was COW-isolated, so the parent still
   * sees its own 0x42. If the repoint LEAKED to the shared backing, the parent
   * now sees the child's 0x99 (the bug). */
  if (test[0] == 0x42) {
    ssize_t _ = write(1, "private-ok", 10);
    (void)_;
    _exit(0);
  }
  _exit(3);
}
