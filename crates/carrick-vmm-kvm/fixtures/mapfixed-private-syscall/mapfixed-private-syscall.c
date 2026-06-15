#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

/* MAP_FIXED|MAP_PRIVATE syscall-buffer correctness (repoint_private follow-up).
 *
 * carrick backs a guest MAP_SHARED mapping with the shared aperture (a window
 * at LINUX_SHARED_FILE_BASE = 576 GiB). A guest mmap(MAP_FIXED|MAP_PRIVATE|
 * MAP_ANON) over such a VA REPOINTS that VA's stage-1 leaf to a per-process
 * PRIVATE overlay page (at LINUX_PRIVATE_OVERLAY_BASE = 608 GiB). So the guest's
 * own EL0 loads/stores to the VA correctly hit the PRIVATE overlay.
 *
 * BUT carrick's SYSCALL path historically read/wrote a guest buffer by treating
 * the guest pointer as a GPA directly (identity VA==GPA) WITHOUT stage-1
 * translating. The shared aperture (576 GiB) is below the 1-TiB high-VA
 * translate threshold, so neither backend translated it — read_bytes(va)/
 * write_bytes(va) for a syscall buffer at the repointed VA resolved to the
 * SHARED-aperture backing (which still covers the VA by VA), NOT the overlay.
 * Result: a syscall READING from the VA saw STALE SHARED data (not the guest's
 * private writes); a syscall WRITING to the VA wrote the SHARED backing (a leak,
 * and the guest's private reads did not see it).
 *
 * This fixture proves the syscall path now translates the repointed VA to its
 * overlay IPA — using a pipe(2) as the syscall buffer carrier. */

int main(void) {
  long ps = sysconf(_SC_PAGESIZE);
  if (ps <= 0) {
    return 2;
  }
  /* A shared-aperture VA. */
  char *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    return 2;
  }
  memset(p, 0xAA, (size_t)ps); /* shared baseline */

  /* Repoint the VA to a per-process PRIVATE overlay. */
  if (mmap(p, (size_t)ps, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
    return 4;
  }
  memset(p, 0xBB, (size_t)ps); /* PRIVATE content (overlay) */

  /* Use p as a SYSCALL READ buffer: write it down a pipe, read it back, and
   * check the syscall saw 0xBB (private overlay), not 0xAA (stale shared). */
  int fd[2];
  if (pipe(fd)) {
    return 5;
  }
  if (write(fd[1], p, 16) != 16) {
    return 6; /* carrick read_bytes(p) MUST read the overlay (0xBB) */
  }
  unsigned char buf[16];
  if (read(fd[0], buf, 16) != 16) {
    return 7;
  }
  for (int i = 0; i < 16; i++) {
    if (buf[i] != 0xBB) {
      return 3; /* saw shared 0xAA -> the bug */
    }
  }

  /* Use p as a SYSCALL WRITE buffer: read(pipe) INTO p must land in the overlay,
   * and a subsequent guest load of p must observe it (same overlay backing). */
  unsigned char src[16];
  memset(src, 0xCC, 16);
  if (write(fd[1], src, 16) != 16) {
    return 8;
  }
  if (read(fd[0], p, 16) != 16) {
    return 9; /* carrick write_bytes(p) MUST write the overlay */
  }
  if (p[0] != (char)0xCC) {
    return 10; /* guest load of p sees the syscall's write -> same backing */
  }

  ssize_t _ = write(1, "syscall-priv-ok", 15);
  (void)_;
  _exit(0);
}
