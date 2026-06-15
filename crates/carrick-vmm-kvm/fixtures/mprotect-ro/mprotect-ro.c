#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

/* Stage-1 re-protect TLBI lock (Task 8).
 *
 * mmap a PROT_READ|PROT_WRITE page and TOUCH it (`p[0]=1`) so the guest
 * establishes a WRITABLE stage-1 TLB entry for that VA. Then mprotect it
 * PROT_READ and store again (`p[0]=2`). On a correct system the store faults
 * (the descriptor is now read-only AND the stale writable TLB entry was
 * invalidated) -> the SIGSEGV handler runs and prints "segv-ok".
 *
 * On the KVM bug (no stage-1 TLBI after pt_edit), the mprotect updates the
 * descriptor but the stale WRITABLE TLB entry survives, so the store SILENTLY
 * SUCCEEDS, no signal fires, and the program prints "no-segv" + exits 3. */

static void on_segv(int sig, siginfo_t *si, void *uc) {
  (void)sig;
  (void)si;
  (void)uc;
  /* async-signal-safe: raw write(2) + _exit(2), no stdio. */
  ssize_t _ = write(1, "segv-ok", 7);
  (void)_;
  _exit(0);
}

int main(void) {
  long ps = sysconf(_SC_PAGESIZE);
  if (ps <= 0) {
    return 2;
  }
  char *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    return 2;
  }
  /* TOUCH the page so the guest walks the tables and caches a WRITABLE TLB
   * entry for this VA. This is what makes the re-protect below a stale-TLB
   * test rather than a fresh-page test. */
  p[0] = 1;

  struct sigaction sa;
  __builtin_memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = on_segv;
  sa.sa_flags = SA_SIGINFO;
  if (sigaction(SIGSEGV, &sa, NULL) != 0) {
    return 2;
  }

  /* Re-protect the ALREADY-TOUCHED page read-only. */
  if (mprotect(p, (size_t)ps, PROT_READ) != 0) {
    return 2;
  }

  /* Store to the now-read-only page. MUST fault -> on_segv -> "segv-ok". */
  p[0] = 2;

  /* Only reached if the store SILENTLY SUCCEEDED (the KVM stale-TLB bug). */
  ssize_t _ = write(1, "no-segv", 7);
  (void)_;
  _exit(3);
}
