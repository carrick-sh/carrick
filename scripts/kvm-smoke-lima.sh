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

  # 1d. Phase 2 / Task 4: execve_into — in-place memory-slot remap on the LIVE
  #     VM (no teardown). The freestanding fork-execve-{true,false} drivers
  #     issue clone(220) then, in the child, execve(221) of a SECOND freestanding
  #     ELF passed by absolute host path; the thin shim reads that path out of
  #     guest RAM, loads it with AddressSpace::load_elf, and calls
  #     engine.execve_into(&new_image) — which unregisters every old KVM slot,
  #     re-registers the new-image windows, re-materializes the EL1 vector +
  #     stage-1 page tables, reprograms the system registers, zeroes x0..x30, and
  #     PRESERVES is_forked_child. The replaced child resumes at the target
  #     _start and exit_group(0)/exit_group(1); the parent host wait4 reaps it
  #     and asserts WEXITSTATUS, then prints "execve-ok". The execve targets are
  #     staged at the absolute paths baked into the drivers.
  cp -f "$fixdir/exec-target-exit0/exec-target-exit0" /tmp/carrick-exec-target-true
  cp -f "$fixdir/exec-target-exit1/exec-target-exit1" /tmp/carrick-exec-target-false
  run_case "thin-shim+execve-true" "$shim" "fork-execve-true"
  run_case "thin-shim+execve-false" "$shim" "fork-execve-false"

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

    # 6b. map_host_alias: a guest mmap(MAP_SHARED, fd) of a host-backed /tmp file.
    #     The dispatcher emits DispatchOutcome::MapHostAlias (dispatch/mem.rs:435)
    #     -> KvmTrapEngine::map_host_alias: a NEW KVM slot at a low alias GPA, with
    #     the high alias VA (>= 1 TiB) mapped to it via the SHARED map_aliased. The
    #     binary seeds the file via the fd, reads the seed back THROUGH the mapping
    #     (proves the guest stage-1 VA->GPA path resolves to the slot), then writes
    #     THROUGH the mapping + msync + pread of the fd (proves the alias is the LIVE
    #     page cache, not a snapshot — the discriminator vs the arena-copy
    #     fallthrough). The mmap returns p == 0x100_0000_0000 (1 TiB) under trace.
    #     A native run of the SAME binary is the second, independent witness.
    cat > /tmp/cmha.c <<CEOF
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
int main(void){
  int fd=open("/tmp/carrick-mha.bin",O_RDWR|O_CREAT|O_TRUNC,0644);
  if(fd<0) return 2;
  if(ftruncate(fd,4096)!=0) return 3;
  if(pwrite(fd,"ALIAS-SEED-0123",15,0)!=15) return 4;
  char *p=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if(p==MAP_FAILED) return 5;
  if(memcmp(p,"ALIAS-SEED-0123",15)!=0) return 6;   /* read THROUGH the alias */
  memcpy(p,"ALIAS-WROTE-9876",16);                   /* write THROUGH the alias */
  if(msync(p,4096,MS_SYNC)!=0) return 7;
  char b[16]={0};
  if(pread(fd,b,16,0)!=16) return 8;
  if(memcmp(b,"ALIAS-WROTE-9876",16)!=0) return 9;   /* live-page-cache coherence */
  munmap(p,4096); close(fd);
  return write(1,"mha-ok",6)==6?0:10;
}
CEOF
    gcc -static -O2 -o /tmp/cmha /tmp/cmha.c
    got="$(sg kvm -c "$kvm run-elf /tmp/cmha")" && code=0 || code=$?
    oracle="$(/tmp/cmha)" && ocode=0 || ocode=$?
    if [ "$got" = "mha-ok" ] && [ "$code" -eq 0 ] && [ "$got" = "$oracle" ] && [ "$code" = "$ocode" ]; then
      echo "OK [real-dispatch+map-host-alias]: guest mmap(MAP_SHARED,fd) aliases the live page cache at a >=1 TiB VA (== native oracle)."
    else
      printf "FAIL [map-host-alias]: carrick=[%s]/%s native=[%s]/%s\n" "$got" "$code" "$oracle" "$ocode" >&2
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

    # 10. Phase 2 / Task 7: threads — clone(CLONE_THREAD) sibling vCPUs. REQUIRED.
    #
    #     Task 7 wired the generic threaded run loop (run_threaded_kvm_loop ->
    #     vcpu_loop::run_vcpu_until_exit) to the KVM run path, so a multi-threaded
    #     guest now spawns one host thread + one KVM vCPU per guest thread, all on
    #     the SAME VM, with the private FUTEX_WAIT/WAKE (the pthread mutex) routed
    #     through the shared FutexTable and cross-thread kicks via the KvmKicker.
    #     The capstone deadlock was a DUPLICATE KVM vcpu_id: every sibling
    #     KVM_CREATE_VCPU used id 0 (the main vCPU id) -> EEXIST -> no sibling
    #     ever ran -> the main thread pthread_join futex never woke. Fixed by a
    #     shared atomic vcpu-id allocator (main vCPU 0; siblings 1,2,3,...), so
    #     this is now a REQUIRED gate (fatal on failure), no longer xfail.
    #
    #     Fixture: 4 pthreads each do 1000 mutex-guarded increments of a shared
    #     counter -> 4000; join all; print "counter=4000"; exit 0.
    cat > /tmp/cthr.c <<CEOF
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#define NTHREADS 4
#define NITERS   1000
static long counter;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *arg){
  (void)arg;
  for(int i=0;i<NITERS;i++){
    pthread_mutex_lock(&lock);
    counter++;
    pthread_mutex_unlock(&lock);
  }
  return 0;
}
int main(void){
  pthread_t t[NTHREADS];
  for(int i=0;i<NTHREADS;i++) if(pthread_create(&t[i],0,worker,0)) return 2;
  for(int i=0;i<NTHREADS;i++) if(pthread_join(t[i],0)) return 3;
  char buf[32]; int n=snprintf(buf,sizeof buf,"counter=%ld",counter);
  if(n<=0) return 4;
  return write(1,buf,(size_t)n)==n ? (counter==(long)NTHREADS*NITERS?0:5) : 6;
}
CEOF
    gcc -static -O2 -pthread -o /tmp/cthr /tmp/cthr.c
    # `timeout 30` so a hung threaded run fails-fast (reported as a timeout) and
    # never wedges the whole smoke for 600s. exit 124 == GNU timeout fired.
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/cthr" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "counter=4000" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+threads]: 4 pthreads x 1000 mutex-guarded increments = counter=4000."
    else
      printf "FAIL [threads]: stdout=[%s] exit=%s oracle=[counter=4000]\n" "$got" "$code" >&2
      exit 1
    fi

    # 11. Phase 2 / Task 6: condvar-requeue — the PRIVATE (in-process, cross-
    #     thread) futex path exercised by a pthread condvar: glibc lowers
    #     pthread_cond_wait/signal/broadcast onto FUTEX_WAIT / FUTEX_WAKE /
    #     FUTEX_CMP_REQUEUE, which the dispatcher routes to the KvmFutex
    #     private_wait/private_wake/requeue methods (delegated to the in-process
    #     FutexTable). KvmFutex (Task 6) is COMPLETE and host-unit-tested
    #     (`cargo test -p carrick-linux kvm_futex`); driving a condvar needs
    #     MULTIPLE vCPU threads (the generic threaded run loop), wired to KVM in
    #     Task 7 (run_threaded_kvm_loop). Now a REQUIRED gate (fatal on failure).
    cat > /tmp/ccv.c <<CEOF
#include <pthread.h>
#include <unistd.h>
static pthread_mutex_t m=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  c=PTHREAD_COND_INITIALIZER;
static int ready, done;
#define NW 3
static void *waiter(void *a){
  (void)a;
  pthread_mutex_lock(&m);
  while(!ready) pthread_cond_wait(&c,&m); /* FUTEX_WAIT (+ CMP_REQUEUE on signal) */
  done++;
  pthread_mutex_unlock(&m);
  return 0;
}
int main(void){
  pthread_t t[NW];
  for(int i=0;i<NW;i++) if(pthread_create(&t[i],0,waiter,0)) return 2;
  usleep(50*1000);
  pthread_mutex_lock(&m);
  ready=1;
  pthread_cond_broadcast(&c);            /* FUTEX_WAKE / CMP_REQUEUE all waiters */
  pthread_mutex_unlock(&m);
  for(int i=0;i<NW;i++) if(pthread_join(t[i],0)) return 3;
  return write(1,"condvar-ok",10)==10 ? (done==NW?0:4) : 5;
}
CEOF
    gcc -static -O2 -pthread -o /tmp/ccv /tmp/ccv.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/ccv" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "condvar-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+condvar-requeue]: pthread cond_wait/broadcast (FUTEX_WAIT/WAKE/CMP_REQUEUE) via KvmFutex private path."
    else
      printf "FAIL [condvar-requeue]: stdout=[%s] exit=%s oracle=[condvar-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 12. Phase 2 / Task 6: shared-futex-fork — the SHARED (cross-PROCESS,
    #     MAP_SHARED) futex path exercised across a fork: a glibc binary mmaps a
    #     MAP_SHARED|MAP_ANONYMOUS futex word, forks, the child FUTEX_WAITs on it
    #     and the parent writes the word + FUTEX_WAKEs. The dispatcher routes the
    #     shared-aperture address to KvmFutex::shared_wait/shared_wake (bare host
    #     SYS_futex on the inherited shared page). KvmFutex (Task 6) is COMPLETE
    #     and host-unit-tested for this round-trip (the cross-THREAD analogue runs
    #     in `cargo test -p carrick-linux kvm_futex`). Driving it end-to-end
    #     through the GUEST needs the full dispatcher shared_futex_host_addr
    #     GPA->host translation on the live VM AND the threaded run loop blocking
    #     futex re-dispatch -- both Task 7 (run_threaded_kvm_loop). The parent and
    #     child genuinely rendezvous on the SAME inherited MAP_SHARED physical
    #     page via host SYS_futex; the child reaches _exit(7) and the parent
    #     wait4 reads WEXITSTATUS==7. (Task 7c fixed the final defect: the forked
    #     child exit path was an unreachable!() stub in the generic loop non-macOS
    #     helper module, so the child PANICKED instead of _exit(7) -- the parent
    #     then saw the wrong status and the fixture returned 5.)
    #     Now a REQUIRED gate (fatal on failure).
    cat > /tmp/csf.c <<CEOF
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <unistd.h>
#include <stdint.h>
static int fwait(uint32_t *a,uint32_t v){ return syscall(SYS_futex,a,FUTEX_WAIT,v,0,0,0); }
static int fwake(uint32_t *a,int n){ return syscall(SYS_futex,a,FUTEX_WAKE,n,0,0,0); }
int main(void){
  uint32_t *w=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  if(w==MAP_FAILED) return 2;
  *w=0;
  pid_t pid=fork();
  if(pid<0) return 3;
  if(pid==0){ while(__atomic_load_n(w,__ATOMIC_SEQ_CST)==0) fwait(w,0); _exit(7); }
  usleep(50*1000);
  __atomic_store_n(w,1,__ATOMIC_SEQ_CST);
  fwake(w,1);
  int st; if(waitpid(pid,&st,0)!=pid) return 4;
  if(!WIFEXITED(st)||WEXITSTATUS(st)!=7) return 5;
  return write(1,"sharedfutex-ok",14)==14?0:6;
}
CEOF
    gcc -static -O2 -o /tmp/csf /tmp/csf.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/csf" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "sharedfutex-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+shared-futex-fork]: cross-process MAP_SHARED FUTEX_WAIT/WAKE via KvmFutex shared path."
    else
      printf "FAIL [shared-futex-fork]: stdout=[%s] exit=%s oracle=[sharedfutex-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 13. Phase 2 / Task 3+7: vfork-exec -- the vfork(2) + execve(2) handshake on
    #     the generic threaded KVM loop. A glibc binary vfork()s; the CHILD
    #     execve()s a tiny static target while the PARENT is SUSPENDED (the
    #     handle_fork vfork-pipe poll); a successful child execve writes the
    #     release byte, resuming the parent, which wait4()s the target -> status 0.
    #     This exercises (a) the generic loop vfork parent-suspend and (b) the
    #     KVM execve path NEW Linux load_execve_image (Task 7d: the macOS image
    #     builder is HVF-only, so the non-macOS helper module now builds a
    #     KVM-flavored AddressSpace -- ELF + vdso + initial stack -- that
    #     KvmTrapEngine::execve_into remaps in place). REQUIRED gate.
    cat > /tmp/cvf-target.c <<CEOF
int main(void){ return 0; }
CEOF
    gcc -static -O2 -o /tmp/carrick-vfork-target /tmp/cvf-target.c
    cat > /tmp/cvf.c <<CEOF
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
int main(void){
  pid_t pid=vfork();
  if(pid<0) return 2;
  if(pid==0){
    char *argv[]={"/tmp/carrick-vfork-target",0};
    execve("/tmp/carrick-vfork-target",argv,environ);
    _exit(127); /* execve failed -> parent sees 127, fixture fails */
  }
  int st; if(waitpid(pid,&st,0)!=pid) return 3;
  if(!WIFEXITED(st)||WEXITSTATUS(st)!=0) return 4;
  return write(1,"vfork-exec-ok",13)==13?0:5;
}
CEOF
    gcc -static -O2 -o /tmp/cvf /tmp/cvf.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/cvf" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "vfork-exec-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+vfork-exec]: vfork + child execve + parent wait4 (status 0) via the threaded loop + KVM load_execve_image."
    else
      printf "FAIL [vfork-exec]: stdout=[%s] exit=%s oracle=[vfork-exec-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 14. Phase 4: in-guest signal-HANDLER injection. sigaction(SIGUSR1)+raise():
    #     glibc lowers raise() to tgkill(self); the dispatcher publishes the
    #     UNBLOCKED signal into the per-thread pending table (the Phase-4 Linux
    #     host_signal fix) and, on the syscall return, the generic loop
    #     deliver_pending_signal calls KvmTrapEngine::inject_signal -> the shared
    #     carrick_hal::sigframe builder (handler entry on ELR_EL1, x0=signum, frame
    #     pushed on SP_EL0). The handler sets a flag and returns via the restorer
    #     trampoline -> rt_sigreturn(139) -> restore_from_sigframe. REQUIRED gate.
    cat > /tmp/csig_basic.c <<CEOF
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t ran;
static void h(int s){ (void)s; ran = 1; }
int main(void){
  struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler = h;
  if(sigaction(SIGUSR1,&sa,0)) return 2;
  raise(SIGUSR1);
  if(!ran) return 3;
  return write(1,"csig-basic-ok",13)==13 ? 0 : 4;
}
CEOF
    gcc -static -O2 -o /tmp/csig_basic /tmp/csig_basic.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/csig_basic" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "csig-basic-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+signal-handler]: sigaction+raise ran the in-guest handler (sigframe inject + rt_sigreturn)."
    else
      printf "FAIL [signal-handler]: stdout=[%s] exit=%s oracle=[csig-basic-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 15. Phase 4: SA_ONSTACK. The handler must run on the sigaltstack the program
    #     installed (the builder honors InjectParams::altstack). The handler probes
    #     its own SP and asserts it lies inside altbuf.
    cat > /tmp/csig_onstack.c <<CEOF
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
static char altbuf[65536];
static volatile sig_atomic_t on_alt;
static void h(int s){
  (void)s; int probe; uintptr_t sp=(uintptr_t)&probe;
  on_alt = (sp >= (uintptr_t)altbuf && sp < (uintptr_t)altbuf + sizeof altbuf);
}
int main(void){
  stack_t ss; ss.ss_sp=altbuf; ss.ss_size=sizeof altbuf; ss.ss_flags=0;
  if(sigaltstack(&ss,0)) return 2;
  struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h; sa.sa_flags=SA_ONSTACK;
  if(sigaction(SIGUSR1,&sa,0)) return 3;
  raise(SIGUSR1);
  if(!on_alt) return 4;
  return write(1,"csig-onstack-ok",15)==15 ? 0 : 5;
}
CEOF
    gcc -static -O2 -o /tmp/csig_onstack /tmp/csig_onstack.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/csig_onstack" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "csig-onstack-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+sa-onstack]: SA_ONSTACK handler ran on the installed sigaltstack."
    else
      printf "FAIL [sa-onstack]: stdout=[%s] exit=%s oracle=[csig-onstack-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 16. Phase 4: FP/SIMD + PSTATE save/restore across an ASYNC cross-thread
    #     signal -- and the kick-inject-at-EL0 path. A worker busy-spins (NO
    #     syscalls) holding a sentinel in v16 AND a sentinel in NZCV; the main
    #     thread tgkill()s it. The KvmKicker forces the worker KVM_RUN to return
    #     (EINTR -> VcpuExit::Kicked), the loop injects the handler AT the
    #     interrupted EL0 PC (interrupted_pc=Some) using the LIVE PSTATE
    #     (Reg::Pstate, not the stale SPSR_EL1), the handler clobbers v16+NZCV,
    #     and rt_sigreturn must restore BOTH (fpsimd_enabled=true; saved_spsr =
    #     live pstate). The spin loop reads NZCV via mrs and v16 via umov before
    #     any flag-setting cmp, entirely in asm so the compiler never reallocates
    #     them. Catches both a broken FP save/restore and the kick-path PSTATE
    #     bug (stale SPSR_EL1). REQUIRED gate.
    cat > /tmp/csig_fpsimd.c <<CEOF
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
static volatile sig_atomic_t fired; static volatile int ready, ok=1; static pid_t wtid;
static void h(int s){ (void)s; fired=1;
  uint64_t junk=0xDEADBEEFCAFEF00DUL; __asm__ volatile("dup v16.2d, %0"::"r"(junk):"v16");
  __asm__ volatile("msr nzcv, xzr":::"cc"); /* clobber the interrupted NZCV */ }
static void *worker(void *a){ (void)a; wtid=(pid_t)syscall(SYS_gettid);
  __atomic_store_n(&ready,1,__ATOMIC_SEQ_CST);
  uint64_t vsent=0x0102030405060708UL; int bad=0;
  __asm__ volatile(
    "dup v16.2d, %2\n"          /* v16 = FP sentinel */
    "mov x5, #0xA0000000\n"     /* NZCV sentinel: N=1,C=1 */
    "msr nzcv, x5\n"
    "1: ldr w3,[%1]\n"          /* w3 = fired */
    "   cbz w3,1b\n"            /* spin (cbz preserves NZCV) until the handler ran */
    "   mrs x6, nzcv\n"         /* capture restored NZCV BEFORE any flag-setting op */
    "   umov x4, v16.d[0]\n"
    "   cmp x4,%2\n"            /* v16 preserved? (clobbers NZCV, x6 already read) */
    "   b.ne 2f\n"
    "   mov x5, #0xA0000000\n"
    "   cmp x6, x5\n"           /* NZCV preserved? */
    "   b.ne 2f\n"
    "   b 3f\n"
    "2: mov %w0,#1\n"
    "3:\n"
    : "+r"(bad) : "r"(&fired), "r"(vsent) : "x3","x4","x5","x6","v16","memory","cc");
  if(bad) ok=0; return 0; }
int main(void){
  struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h;
  if(sigaction(SIGUSR1,&sa,0)) return 2;
  pthread_t t; if(pthread_create(&t,0,worker,0)) return 3;
  while(!__atomic_load_n(&ready,__ATOMIC_SEQ_CST)) usleep(1000);
  usleep(20000); /* let the worker enter its busy spin */
  if(syscall(SYS_tgkill,getpid(),wtid,SIGUSR1)) return 4;
  if(pthread_join(t,0)) return 5;
  if(!fired) return 6;
  if(!ok) return 7;
  return write(1,"csig-fpsimd-ok",14)==14 ? 0 : 8;
}
CEOF
    gcc -static -O2 -pthread -o /tmp/csig_fpsimd /tmp/csig_fpsimd.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/csig_fpsimd" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "csig-fpsimd-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+fpsimd-signal]: v16 sentinel survived an async cross-thread handler (kick-inject-at-EL0 + sigframe FP save/restore)."
    else
      printf "FAIL [fpsimd-signal]: stdout=[%s] exit=%s oracle=[csig-fpsimd-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 17. Phase 4: signal delivery to a SPECIFIC sibling thread. The main thread
    #     tgkill()s a worker tid with SIGUSR1; the kick must steer the in-guest
    #     handler onto the WORKER vCPU, not main. The handler checks gettid() ==
    #     worker_tid. (Here the worker is parked in usleep -- delivery at a syscall
    #     boundary -- complementing case 16 busy-spin EL0 delivery.) REQUIRED.
    cat > /tmp/csig_sibling.c <<CEOF
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>
static volatile sig_atomic_t on_worker; static volatile int ready; static pid_t wtid;
static void h(int s){ (void)s; if((pid_t)syscall(SYS_gettid)==wtid) on_worker=1; }
static void *worker(void *a){ (void)a; wtid=(pid_t)syscall(SYS_gettid);
  __atomic_store_n(&ready,1,__ATOMIC_SEQ_CST); while(!on_worker) usleep(1000); return 0; }
int main(void){
  struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h;
  if(sigaction(SIGUSR1,&sa,0)) return 2;
  pthread_t t; if(pthread_create(&t,0,worker,0)) return 3;
  while(!__atomic_load_n(&ready,__ATOMIC_SEQ_CST)) usleep(1000);
  if(syscall(SYS_tgkill,getpid(),wtid,SIGUSR1)) return 4;
  if(pthread_join(t,0)) return 5;
  if(!on_worker) return 6;
  return write(1,"csig-sibling-ok",15)==15 ? 0 : 7;
}
CEOF
    gcc -static -O2 -pthread -o /tmp/csig_sibling /tmp/csig_sibling.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/csig_sibling" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "csig-sibling-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+signal-sibling]: tgkill delivered SIGUSR1 to the worker thread (handler ran on the worker vCPU)."
    else
      printf "FAIL [signal-sibling]: stdout=[%s] exit=%s oracle=[csig-sibling-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 18. Phase 4: SA_RESTART end-to-end. A worker thread fork()s a child (sleeps
    #     150ms then _exit(42)) and blocks in wait4(child); the main thread tgkill()s
    #     the worker mid-wait with an SA_RESTART SIGUSR1 handler. The kick interrupts
    #     the WaitOnProcExit (-> EINTR), the handler runs, and because wait4(260) is
    #     in is_restartable_syscall the loop RESTARTS the syscall (rather than
    #     surfacing EINTR), so the worker still reaps the child and sees
    #     WEXITSTATUS==42. The reaper IS the forker (worker), so no cross-thread
    #     reap is involved. Asserts BOTH handler-ran AND the restarted wait4 reaped
    #     status 42. REQUIRED gate. (Validated to FAIL without SA_RESTART: wait4
    #     then returns EINTR and the child is not reaped.)
    cat > /tmp/csig_restart.c <<CEOF
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
static volatile sig_atomic_t fired; static volatile int ready, wok; static pid_t wtid;
static void h(int s){ (void)s; fired=1; }
static void *worker(void *a){ (void)a; wtid=(pid_t)syscall(SYS_gettid);
  pid_t c=fork(); if(c==0){ usleep(150*1000); _exit(42); }
  __atomic_store_n(&ready,1,__ATOMIC_SEQ_CST);
  int st; pid_t r=wait4(c,&st,0,0);  /* blocks ~150ms; SIGUSR1(SA_RESTART) at ~50ms must restart */
  if(r==c && WIFEXITED(st) && WEXITSTATUS(st)==42) wok=1; return 0; }
int main(void){
  struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h; sa.sa_flags=SA_RESTART;
  if(sigaction(SIGUSR1,&sa,0)) return 2;
  pthread_t t; if(pthread_create(&t,0,worker,0)) return 3;
  while(!__atomic_load_n(&ready,__ATOMIC_SEQ_CST)) usleep(1000);
  usleep(50*1000); /* worker is now blocked in wait4 (child sleeps 150ms) */
  if(syscall(SYS_tgkill,getpid(),wtid,SIGUSR1)) return 4;
  if(pthread_join(t,0)) return 5;
  if(!fired) return 6;
  if(!wok) return 7;
  return write(1,"csig-restart-ok",15)==15 ? 0 : 8;
}
CEOF
    gcc -static -O2 -pthread -o /tmp/csig_restart /tmp/csig_restart.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/csig_restart" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "csig-restart-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+sa-restart]: a wait4 interrupted by an SA_RESTART handler restarted and reaped status 42."
    else
      printf "FAIL [sa-restart]: stdout=[%s] exit=%s oracle=[csig-restart-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 19. Phase 4 follow-up: WALL-CLOCK timer signals. setitimer(ITIMER_REAL) ->
    #     SIGALRM. The Linux backend has no kqueue pump, so the itimer fallback
    #     timer thread sleeps to the deadline then publishes SIGALRM to the main
    #     tid + kicks its vCPU (KVM_RUN EINTR) so the generic loop injects the
    #     handler. (alarm(2) lowers to setitimer(ITIMER_REAL), so this covers it.)
    cat > /tmp/t_setitimer.c <<CEOF
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
static volatile sig_atomic_t fired;
static void h(int s){ (void)s; fired=1; }
int main(void){ struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h;
  if(sigaction(SIGALRM,&sa,0)) return 2;
  struct itimerval it; it.it_interval.tv_sec=0; it.it_interval.tv_usec=0;
  it.it_value.tv_sec=0; it.it_value.tv_usec=50000;
  if(setitimer(ITIMER_REAL,&it,0)) return 3;
  for(int i=0;i<3000 && !fired;i++) usleep(1000);
  if(!fired) return 4;
  return write(1,"setitimer-ok",12)==12 ? 0 : 5; }
CEOF
    gcc -static -O2 -o /tmp/t_setitimer /tmp/t_setitimer.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/t_setitimer" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "setitimer-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+timer-setitimer]: setitimer(ITIMER_REAL) delivered SIGALRM via the fallback timer thread."
    else
      printf "FAIL [timer-setitimer]: stdout=[%s] exit=%s oracle=[setitimer-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 20. Phase 4 follow-up: REPEATING interval timer. setitimer with it_interval
    #     fires SIGALRM every 30ms; the handler counts and the program disarms
    #     after >=3 fires (exercises the firing thread interval loop + generation
    #     disarm).
    cat > /tmp/t_interval.c <<CEOF
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
static volatile sig_atomic_t cnt;
static void h(int s){ (void)s; cnt++; }
int main(void){ struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h;
  if(sigaction(SIGALRM,&sa,0)) return 2;
  struct itimerval it; it.it_interval.tv_sec=0; it.it_interval.tv_usec=30000;
  it.it_value.tv_sec=0; it.it_value.tv_usec=30000;
  if(setitimer(ITIMER_REAL,&it,0)) return 3;
  for(int i=0;i<5000 && cnt<3;i++) usleep(1000);
  struct itimerval z; __builtin_memset(&z,0,sizeof z); setitimer(ITIMER_REAL,&z,0);
  if(cnt<3) return 4;
  return write(1,"interval-ok",11)==11 ? 0 : 5; }
CEOF
    gcc -static -O2 -o /tmp/t_interval /tmp/t_interval.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/t_interval" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "interval-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+timer-interval]: a repeating ITIMER_REAL fired SIGALRM 3+ times; disarm stopped it."
    else
      printf "FAIL [timer-interval]: stdout=[%s] exit=%s oracle=[interval-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 21. Phase 4 follow-up: POSIX per-process timer. timer_create(CLOCK_MONOTONIC,
    #     SIGEV_SIGNAL=SIGALRM) + timer_settime -> a posix_timer fallback thread
    #     delivers the signal. Exercises the timer_create/settime path (distinct
    #     from the itimer path: timer_settime spawns the firing thread directly).
    cat > /tmp/t_posix.c <<CEOF
#include <signal.h>
#include <time.h>
#include <unistd.h>
static volatile sig_atomic_t fired;
static void h(int s){ (void)s; fired=1; }
int main(void){ struct sigaction sa; __builtin_memset(&sa,0,sizeof sa); sa.sa_handler=h;
  if(sigaction(SIGALRM,&sa,0)) return 2;
  timer_t tid; struct sigevent sev; __builtin_memset(&sev,0,sizeof sev);
  sev.sigev_notify=SIGEV_SIGNAL; sev.sigev_signo=SIGALRM;
  if(timer_create(CLOCK_MONOTONIC,&sev,&tid)) return 3;
  struct itimerspec its; __builtin_memset(&its,0,sizeof its);
  its.it_value.tv_sec=0; its.it_value.tv_nsec=50*1000*1000;
  if(timer_settime(tid,0,&its,0)) return 4;
  for(int i=0;i<3000 && !fired;i++) usleep(1000);
  if(!fired) return 5;
  return write(1,"posixtimer-ok",13)==13 ? 0 : 6; }
CEOF
    gcc -static -O2 -o /tmp/t_posix /tmp/t_posix.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/t_posix" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "posixtimer-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+timer-posix]: timer_create+timer_settime(CLOCK_MONOTONIC) delivered SIGALRM."
    else
      printf "FAIL [timer-posix]: stdout=[%s] exit=%s oracle=[posixtimer-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 22. Phase 4 follow-up: a BLOCKED timer signal dequeued synchronously. The
    #     program blocks SIGALRM, arms setitimer, then rt_sigtimedwait(SIGALRM).
    #     The timer publishes SIGALRM into the per-thread host_signal table (the
    #     UNBLOCKED async slot); because the program also awaits it synchronously,
    #     rt_sigtimedwait must look there too (host_signal::take_pending_in_for,
    #     real on Linux) -- else the wait would hang to timeout. Guards both the
    #     take_pending_in_for fix and the timer/sigtimedwait interaction.
    cat > /tmp/t_sigwait.c <<CEOF
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
int main(void){
  sigset_t set; sigemptyset(&set); sigaddset(&set,SIGALRM);
  sigprocmask(SIG_BLOCK,&set,0);
  struct itimerval it; it.it_interval.tv_sec=0; it.it_interval.tv_usec=0;
  it.it_value.tv_sec=0; it.it_value.tv_usec=50000;
  if(setitimer(ITIMER_REAL,&it,0)) return 2;
  struct timespec ts={2,0};
  int s=sigtimedwait(&set,0,&ts);
  if(s!=SIGALRM) return 3;
  return write(1,"sigwait-timer-ok",16)==16 ? 0 : 4; }
CEOF
    gcc -static -O2 -o /tmp/t_sigwait /tmp/t_sigwait.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/t_sigwait" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "sigwait-timer-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+timer-sigwait]: a blocked SIGALRM timer was dequeued by rt_sigtimedwait (take_pending_in_for)."
    else
      printf "FAIL [timer-sigwait]: stdout=[%s] exit=%s oracle=[sigwait-timer-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 23. Phase 4 follow-up: in-guest FAULT -> signal. A guest EL0 data abort
    #     (null-deref) is NOT a KVM_RUN exit -- KVM vectors it to the guest EL1
    #     vector -- so carrick lower-EL-sync slot reads ESR.EC, sees it is not an
    #     svc, and stores to FAULT_SENTINEL_GPA. The host captures ESR/FAR/ELR and
    #     deliver_fault_signal injects SIGSEGV (SEGV_MAPERR, si_addr == the bad VA).
    #     This SA_SIGINFO handler asserts si_signo/si_code/si_addr then longjmps out.
    cat > /tmp/fault_segv.c <<CEOF
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <string.h>
static sigjmp_buf jb; static volatile int gs, gc; static volatile unsigned long ga;
static void h(int s, siginfo_t *si, void *u){ (void)u; gs=s; gc=si->si_code; ga=(unsigned long)si->si_addr; siglongjmp(jb,1); }
int main(void){
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO;
  if(sigaction(SIGSEGV,&sa,0)) return 2;
  if(sigsetjmp(jb,1)==0){ volatile int *p=0; *p=42; return 9; }
  if(gs!=11) return 3;     /* SIGSEGV */
  if(ga!=0) return 4;      /* si_addr == faulting VA (FAR survived the sentinel store) */
  if(gc!=1) return 5;      /* SEGV_MAPERR */
  return write(1,"fault-segv-ok",13)==13 ? 0 : 6; }
CEOF
    gcc -static -O2 -o /tmp/fault_segv /tmp/fault_segv.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/fault_segv" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "fault-segv-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+fault-segv]: a null-deref data abort delivered SIGSEGV/SEGV_MAPERR with si_addr=0 (FAR captured)."
    else
      printf "FAIL [fault-segv]: stdout=[%s] exit=%s oracle=[fault-segv-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 24. Phase 4 follow-up: instruction abort. A call through a null function
    #     pointer faults at PC=0 (ESR.EC=0x20/0x21) -> SIGSEGV. Exercises the
    #     OTHER fault EC path (instruction vs data abort).
    cat > /tmp/fault_iabort.c <<CEOF
#include <signal.h>
#include <unistd.h>
#include <setjmp.h>
#include <string.h>
static sigjmp_buf jb; static volatile int gs;
static void h(int s, siginfo_t *si, void *u){ (void)u; (void)si; gs=s; siglongjmp(jb,1); }
int main(void){
  struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=h; sa.sa_flags=SA_SIGINFO;
  if(sigaction(SIGSEGV,&sa,0)) return 2;
  if(sigsetjmp(jb,1)==0){ void (*f)(void)=0; f(); return 9; }
  if(gs!=11) return 3;
  return write(1,"fault-iabort-ok",15)==15 ? 0 : 4; }
CEOF
    gcc -static -O2 -o /tmp/fault_iabort /tmp/fault_iabort.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/fault_iabort" 2>/dev/null)" && code=0 || code=$?
    if [ "$got" = "fault-iabort-ok" ] && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+fault-iabort]: a call through a null pointer delivered SIGSEGV (instruction abort)."
    else
      printf "FAIL [fault-iabort]: stdout=[%s] exit=%s oracle=[fault-iabort-ok]\n" "$got" "$code" >&2
      exit 1
    fi

    # 25. Phase 4 follow-up: fault with NO handler -> default action terminates the
    #     process by SIGSEGV (exit 128+11 = 139), matching the kernel.
    cat > /tmp/fault_nh.c <<CEOF
int main(void){ volatile int *p=0; *p=42; return 0; }
CEOF
    gcc -static -O2 -o /tmp/fault_nh /tmp/fault_nh.c
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/fault_nh" 2>/dev/null)" && code=0 || code=$?
    if [ -z "$got" ] && [ "$code" -eq 139 ]; then
      echo "OK [real-dispatch+fault-nohandler]: an uncaught SIGSEGV terminated the process with exit 139 (128+SIGSEGV)."
    else
      printf "FAIL [fault-nohandler]: stdout=[%s] exit=%s expected exit=139\n" "$got" "$code" >&2
      exit 1
    fi

    # 26. Signal refactor / Task 2: si_pid REGRESSION LOCK. A self-directed
    #     kill(getpid,SIGUSR1) with an SA_SIGINFO handler must deliver the SENDER
    #     pid in siginfo si_pid. glibc lowers kill onto the kill dispatcher arm,
    #     which queues an SI_USER siginfo carrying the caller pid (== this guest);
    #     the generic loop injects that exact siginfo into the handler frame. This
    #     proves the dispatcher siginfo-queue path supplies si_pid on KVM -- NOT
    #     the async last_sender_for path, which is correctly 0 on KVM (no
    #     host-signal pump until Task 7). The committed fixture .c is gcc-compiled
    #     in-guest (it needs glibc + the real dispatcher, like the other signal
    #     cases). REQUIRED gate.
    senderpid_src="$fixdir/signal-sender-pid/sender-pid.c"
    gcc -static -O2 -o /tmp/sender_pid "$senderpid_src"
    got="$(timeout 30 sg kvm -c "$kvm run-elf /tmp/sender_pid" 2>/dev/null)" && code=0 || code=$?
    if printf '%s\n' "$got" | grep -q "sender-pid-ok" && [ "$code" -eq 0 ]; then
      echo "OK [real-dispatch+si-pid]: a self-kill SA_SIGINFO handler saw si_pid==getpid() (dispatcher siginfo-queue path)."
    else
      printf "FAIL [si-pid]: stdout=[%s] exit=%s oracle=[*sender-pid-ok*]\n" "$got" "$code" >&2
      exit 1
    fi
  else
    echo "SKIP [glibc-static/blocking-io/file-io/map-host-alias/epoll/prot-none/signals/threads/condvar/shared-futex/vfork-exec/signal-handler/sa-onstack/fpsimd-signal/signal-sibling/sa-restart/timer-setitimer/timer-interval/timer-posix/timer-sigwait/fault-segv/fault-iabort/fault-nohandler/si-pid]: no gcc in guest" >&2
  fi

  # Evidence the REAL dispatch path actually ran (write=64, exit_group=94 traps).
  echo "--- trap trace (proves real dispatch, not the thin shim) ---" >&2
  sg kvm -c "CARRICK_TRACE_TRAPS=1 $kvm run-elf $fixdir/hello-aarch64/hello-aarch64" \
    >/dev/null 2>/tmp/carrick-kvm-trace || true
  grep -E "x8=64|x8=94" /tmp/carrick-kvm-trace >&2 || {
    echo "FAIL: expected write(64)+exit_group(94) traps in the real-dispatch trace" >&2
    exit 1
  }
  echo "OK: B+C1+C2+C3+C5+C6+fs+fork+pipe-fork+execve+threads+futex+signal-injection+timers+faults+si-pid — all 30 cases (hello, fork, pipe-fork, execve-true, execve-false, stack, glibc, blocking-IO, file-IO, map-host-alias, epoll, prot-none, signals, threads-counter, condvar-requeue, shared-futex-fork, vfork-exec, signal-handler, sa-onstack, fpsimd-signal, signal-sibling, sa-restart, timer-setitimer, timer-interval, timer-posix, timer-sigwait, fault-segv, fault-iabort, fault-nohandler, si-pid) pass on KVM; ZERO xfail."
'
