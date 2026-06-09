#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>

/* POST-FORK repoint_private syscall-buffer correctness (the KVM fork regression
 * the mapfixed-private-syscall fixture MISSED because it never forks).
 *
 * Background (see mapfixed-private-syscall.c): a guest mmap(MAP_FIXED|MAP_PRIVATE
 * |MAP_ANON) over a SHARED-aperture VA (576 GiB) REPOINTS that VA's stage-1 leaf
 * to a per-process PRIVATE overlay (608 GiB). carrick's syscall path stage-1-
 * translates such a buffer VA to the overlay IPA via the live page-table manager
 * (KvmTrapEngine::syscall_buffer_ipa -> page_tables.lock().translate(va)).
 *
 * THE BUG (KVM-only): KVM fork RESET the manager to None (intending a lazy
 * rebuild on the child's first pt_edit). But syscall_buffer_ipa is &self and
 * cannot rebuild — so in a FORKED CHILD that uses a repointed buffer BEFORE its
 * first mmap/mprotect/munmap, translate returned None -> unwrap_or(va) -> the
 * syscall resolved to the STALE SHARED backing (0xAA), not the child's PRIVATE
 * overlay (0xBB the COW copy inherited). HVF does NOT have this bug: it CLONES
 * the manager into the child at fork, so it can translate immediately.
 *
 * This fixture forks and, in the child, uses the repointed VA as a syscall READ
 * buffer (write down a pipe) WITHOUT any prior mmap/mprotect. Pre-fix the child
 * reads 0xAA (shared) and exits 3; post-fix it reads 0xBB (overlay) and the
 * parent prints "fork-syscall-priv-ok". */

int main(void) {
  long ps = sysconf(_SC_PAGESIZE);
  if (ps <= 0) {
    _exit(2);
  }
  /* A shared-aperture VA. */
  char *p = mmap(NULL, (size_t)ps, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    _exit(2);
  }
  memset(p, 0xAA, (size_t)ps); /* shared baseline */

  /* Repoint the VA to a per-process PRIVATE overlay. */
  if (mmap(p, (size_t)ps, PROT_READ | PROT_WRITE,
           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
    _exit(4);
  }
  memset(p, 0xBB, (size_t)ps); /* PRIVATE overlay content */

  pid_t pid = fork();
  if (pid == 0) {
    /* CHILD: do NOT mmap/mprotect first. Immediately use p as a syscall buffer.
     * The child's overlay is COW; it holds the parent's 0xBB until it writes. */
    int fd[2];
    if (pipe(fd)) {
      _exit(20);
    }
    if (write(fd[1], p, 16) != 16) {
      _exit(21); /* read_bytes(p) in the forked child MUST hit the overlay */
    }
    unsigned char buf[16];
    if (read(fd[0], buf, 16) != 16) {
      _exit(22);
    }
    for (int i = 0; i < 16; i++) {
      if (buf[i] != 0xBB) {
        _exit(3); /* saw shared 0xAA -> the post-fork bug */
      }
    }
    _exit(0);
  }
  if (pid < 0) {
    _exit(40);
  }
  int st;
  if (waitpid(pid, &st, 0) != pid) {
    _exit(41);
  }
  if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
    ssize_t _ = write(1, "fork-syscall-priv-ok", 20);
    (void)_;
    _exit(0);
  }
  _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 30);
}
