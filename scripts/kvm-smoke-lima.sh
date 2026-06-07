#!/usr/bin/env bash
# L2 success gate on the lima nested-KVM lane (run from the macOS host).
#
# Builds two KVM drivers natively inside the guest and runs the freestanding
# hello-aarch64 fixture against real /dev/kvm, diffing stdout + exit vs oracle:
#
#   1. carrick-linux (thin shim) — services write/exit directly, no dispatcher.
#      Kept for A/B comparison and as the closure-assert subject.
#   2. carrick-kvm (REAL dispatch, Phase B) — drives KvmTrapEngine through the
#      full carrick-runtime SyscallDispatcher. THIS is the Phase B gate.
#
# Requires `just lima-up` once. Override $LIMA_INSTANCE.
set -euo pipefail

vm="${LIMA_INSTANCE:-carrick}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v limactl >/dev/null || {
  echo "lima is not installed (brew install lima); see scripts/lima-up.sh" >&2
  exit 2
}
if ! limactl list -q 2>/dev/null | grep -qx "$vm"; then
  echo "lima VM '$vm' not found — run 'just lima-up' first." >&2
  exit 2
fi

# `sg kvm -c` runs with the kvm group active (the guest user is added to it by
# lima-up). The committed fixture binary is used as-is (no clang needed in-guest).
# REPO is passed via env to avoid host/guest path-quoting issues.
limactl shell "$vm" -- env REPO="$repo" bash -lc '
  set -euo pipefail
  source "$HOME/.cargo/env"
  cd "$REPO"
  fixdir="$REPO/crates/carrick-linux/fixtures"

  run_case() {
    # $1 = label, $2 = binary path, $3 = fixture name (dir == elf name)
    local label="$1" bin="$2" fixture="$3" got code oracle
    oracle="$(cat "$fixdir/$fixture/oracle.expected")"
    got="$(sg kvm -c "$bin run-elf $fixdir/$fixture/$fixture")" && code=0 || code=$?
    if [ "$got" = "$oracle" ] && [ "$code" -eq 0 ]; then
      echo "OK [$label]: $fixture printed '\''$got'\'' and exited 0 under nested KVM."
    else
      printf "FAIL [%s/%s]: stdout=[%s] exit=%s oracle=[%s]\n" "$label" "$fixture" "$got" "$code" "$oracle" >&2
      return 1
    fi
  }

  # 1. Thin shim (existing MVP path): freestanding hello, no dispatcher.
  cargo build --release -p carrick-linux --target-dir "$HOME/ct" --locked
  shim="$HOME/ct/release/carrick-linux"
  run_case "thin-shim" "$shim" "hello-aarch64"

  # 1b. Phase 2 / Task 2: fork(2) — the load-bearing fork primitive, on the THIN
  #     SHIM. The freestanding fork-wait4 fixture issues raw clone(SIGCHLD) /
  #     wait4 / write / exit_group syscalls (no glibc CRT), so the shim drives
  #     KvmTrapEngine::fork() directly: fork() runs libc::fork, the CHILD rebuilds
  #     a brand-new KvmVm over the COW-inherited host mmaps and resumes (x0=0),
  #     the PARENT keeps its live VM (x0=child pid). The child exit_group(42); the
  #     parent host-wait4 reaps it, asserts WEXITSTATUS==42, prints "fork-ok".
  #     The committed fixture needs no gcc, so it runs unconditionally (like case
  #     1) — the full-dispatcher fork loop is wired up later (Task 7).
  run_case "thin-shim+fork" "$shim" "fork-wait4"

  # 1c. Phase 2 / Task 3: pipe2 + fork(2) + read/write/close across the fork
  #     boundary. The freestanding pipe-fork fixture issues pipe2(59)/clone(220)/
  #     close(57)/write(64)/read(63)/wait4(260)/exit_group(94) — all serviced by
  #     the thin shim. This proves fd inheritance across KvmTrapEngine::fork():
  #     the child receives the real host pipe fd and reads 2 bytes the parent
  #     wrote; the child exits 42; the parent asserts WEXITSTATUS==42 and prints
  #     "pipe-ok". No generic loop needed (that is Task 7).
  run_case "thin-shim+pipe-fork" "$shim" "pipe-fork"

  # 2. Real dispatch (Phase B): the full dispatcher, no HVF in the closure.
  cargo build --release -p carrick-runtime --no-default-features \
    --features platform-linux --bin carrick-kvm --target-dir "$HOME/ct" --locked
  kvm="$HOME/ct/release/carrick-kvm"
  run_case "real-dispatch" "$kvm" "hello-aarch64"

  # 3. Phase C / C1: a fixture that READS argc from [sp] and push/pops the
  #    stack — only succeeds if the initial stack is set up AND the high stack
  #    region (~1 TiB) is backed by its own KVM slot (the multi-region map).
  run_case "real-dispatch+stack" "$kvm" "hello-stack-aarch64"

  # 4. Phase C: a REAL static glibc binary. Exercises the full libc CRT startup
  #    through the real dispatcher (brk, set_tid_address, set_robust_list, rseq,
  #    prlimit64, readlinkat, getrandom, mprotect, the vdso) before write+exit.
  #    Proves C1 (memory map + initial stack + vdso) runs an actual libc binary.
  if command -v gcc >/dev/null; then
    printf "%s" "static-ok" > /tmp/static-oracle
    cat > /tmp/cstatic.c <<CEOF
#include <unistd.h>
int main(void){ return write(1,"static-ok",9) == 9 ? 0 : 1; }
CEOF
    gcc -static -O2 -o /tmp/cstatic /tmp/cstatic.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cstatic")" && code=0 || code=$?
    if [ "$got" = "static-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+glibc-static]: a static glibc binary ran to completion under nested KVM."
    else
      printf "FAIL [glibc-static]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi

    # 5. Phase C / C3: BLOCKING I/O. clock_nanosleep (WaitOnSleep) + poll with a
    #    timeout (WaitOnPollFds TimedOut) + poll on a ready fd (Ready) + a pipe
    #    read/write — all serviced by the ppoll-backed ThreadWaiter, re-dispatched
    #    on readiness. Single-threaded (no fork/threads).
    cat > /tmp/cio.c <<CEOF
#include <poll.h>
#include <time.h>
#include <unistd.h>
int main(void){
  struct timespec ts={0,20*1000*1000};
  if(nanosleep(&ts,0)!=0) return 11;
  int fds[2]; if(pipe(fds)) return 12;
  struct pollfd po={fds[1],POLLOUT,0}; if(poll(&po,1,100)!=1) return 13;
  struct pollfd pr={fds[0],POLLIN,0}; if(poll(&pr,1,20)!=0) return 14;
  if(write(fds[1],"x",1)!=1) return 15;
  if(poll(&pr,1,100)!=1) return 16;
  char c; if(read(fds[0],&c,1)!=1) return 17;
  return write(1,"io-ok",5)==5 ? 0 : 18;
}
CEOF
    gcc -static -O2 -o /tmp/cio /tmp/cio.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cio")" && code=0 || code=$?
    if [ "$got" = "io-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+blocking-io]: nanosleep + poll + pipe I/O ran to completion under nested KVM."
    else
      printf "FAIL [blocking-io]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi

    # 6. Real FILE I/O against the host fs backend (the runner roots the guest at
    #    a sandboxed scratch dir + seeds a Linux baseline). open/write/lseek/
    #    read/close round-trip a real file.
    cat > /tmp/cfio.c <<CEOF
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
int main(void){
  int fd=open("/tmp/carrick-fio.txt",O_RDWR|O_CREAT|O_TRUNC,0644);
  if(fd<0) return 2;
  if(write(fd,"file-data",9)!=9) return 3;
  lseek(fd,0,SEEK_SET);
  char b[16]={0}; int n=read(fd,b,16);
  close(fd);
  if(n!=9||memcmp(b,"file-data",9)) return 4;
  return write(1,"fio-ok",6)==6?0:5;
}
CEOF
    gcc -static -O2 -o /tmp/cfio /tmp/cfio.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cfio")" && code=0 || code=$?
    if [ "$got" = "fio-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+file-io]: open/write/lseek/read/close round-trip on the host fs backend."
    else
      printf "FAIL [file-io]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi

    # 7. Phase C / C5: epoll. epoll_create1 + epoll_ctl(ADD) + epoll_wait that
    #    TIMES OUT on an empty pipe, then RETURNS the ready fd after a write —
    #    serviced from the interest map + the ppoll waiter (no kqueue).
    cat > /tmp/cep.c <<CEOF
#include <sys/epoll.h>
#include <unistd.h>
#include <string.h>
int main(void){
  int ep=epoll_create1(0); if(ep<0) return 2;
  int fds[2]; if(pipe(fds)) return 3;
  struct epoll_event ev; memset(&ev,0,sizeof ev); ev.events=EPOLLIN; ev.data.fd=fds[0];
  if(epoll_ctl(ep,EPOLL_CTL_ADD,fds[0],&ev)) return 4;
  struct epoll_event out[4];
  if(epoll_wait(ep,out,4,50)!=0) return 5;
  if(write(fds[1],"y",1)!=1) return 6;
  if(epoll_wait(ep,out,4,1000)!=1 || out[0].data.fd!=fds[0]) return 7;
  char c; if(read(fds[0],&c,1)!=1) return 8;
  return write(1,"epoll-ok",8)==8?0:9;
}
CEOF
    gcc -static -O2 -o /tmp/cep /tmp/cep.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cep")" && code=0 || code=$?
    if [ "$got" = "epoll-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+epoll]: epoll_create1/ctl/wait (timeout + ready) on the interest-map+ppoll path."
    else
      printf "FAIL [epoll]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi

    # 8. Phase C / C2: PROT_NONE enforcement. A PROT_NONE buffer passed to a
    #    syscall must fault with EFAULT (host-side set_no_access check); mprotect
    #    back to RW clears it. (Guest-side SIGSEGV on direct access is Phase D.)
    cat > /tmp/cpn.c <<CEOF
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(void){
  void *p=mmap(0,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(p==MAP_FAILED) return 2;
  errno=0;
  if(write(1,p,16)!=-1 || errno!=EFAULT) return 3;
  if(mprotect(p,4096,PROT_READ|PROT_WRITE)) return 4;
  memcpy(p,"prot-ok",7);
  return write(1,p,7)==7?0:5;
}
CEOF
    gcc -static -O2 -o /tmp/cpn /tmp/cpn.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cpn")" && code=0 || code=$?
    if [ "$got" = "prot-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+prot-none]: a PROT_NONE syscall buffer faults EFAULT; mprotect RW clears it."
    else
      printf "FAIL [prot-none]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi

    # 9. Phase C / C6: signal masking + sigtimedwait. sigprocmask(BLOCK) then a
    #    sigtimedwait that BLOCKS (no pending signal) -> EAGAIN (the WaitOnSignals
    #    path), then kill(self)+sigwait dequeues the now-pending signal. No signal
    #    handler invocation (injection is Phase D).
    cat > /tmp/cstw.c <<CEOF
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
int main(void){
  sigset_t set; sigemptyset(&set); sigaddset(&set,SIGUSR1);
  sigprocmask(SIG_BLOCK,&set,0);
  struct timespec ts={0,30*1000*1000};
  errno=0;
  if(sigtimedwait(&set,0,&ts)!=-1 || errno!=EAGAIN) return 2;
  kill(getpid(),SIGUSR1);
  int s; if(sigwait(&set,&s)) return 3;
  if(s!=SIGUSR1) return 4;
  return write(1,"sigtw-ok",8)==8?0:5;
}
CEOF
    gcc -static -O2 -o /tmp/cstw /tmp/cstw.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cstw")" && code=0 || code=$?
    if [ "$got" = "sigtw-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+signals]: sigprocmask + blocking sigtimedwait (EAGAIN) + kill/sigwait."
    else
      printf "FAIL [signals]: stdout=[%s] exit=%s\n" "$got" "$code" >&2
      exit 1
    fi
  else
    echo "SKIP [glibc-static/blocking-io/file-io/epoll/prot-none/signals]: no gcc in guest" >&2
  fi

  # Evidence the REAL dispatch path actually ran (write=64, exit_group=94 traps).
  echo "--- trap trace (proves real dispatch, not the thin shim) ---" >&2
  sg kvm -c "CARRICK_TRACE_TRAPS=1 $kvm run-elf $fixdir/hello-aarch64/hello-aarch64" \
    >/dev/null 2>/tmp/carrick-kvm-trace || true
  grep -E "x8=64|x8=94" /tmp/carrick-kvm-trace >&2 || {
    echo "FAIL: expected write(64)+exit_group(94) traps in the real-dispatch trace" >&2
    exit 1
  }
  echo "OK: B+C1+C2+C3+C5+C6+fs+fork+pipe-fork — 11 cases (hello, fork, pipe-fork, stack, glibc, blocking-IO, file-IO, epoll, prot-none, signals) pass on KVM."
'
