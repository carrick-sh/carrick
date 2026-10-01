#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option ustackframes=40

/*
 * WHO BLOCKS (NEARLY) EVERY HOST SIGNAL ON A CARRIER THREAD, AND WHICH
 * THREADS ARE BORN UNDER THAT MASK?
 *
 * (a) What it measures: every `__pthread_sigmask`/`sigprocmask` in carrick's
 *     process tree that blocks a set of 16 or more host signals (SIG_BLOCK
 *     or SIG_SETMASK), with pid, tid and user stack; the matching restores;
 *     and every `bsdthread_create` issued by a thread whose tracked mask is
 *     that wide (a thread created then inherits the mask). Written for the
 *     2026-10-01 go-build failure with EL1 reservations on: an executor's
 *     boundary audit found host signals 1..31 newly blocked
 *     ("host-signal-mask: added=[1..31]"), then SnapshotRestoreFailed. The
 *     HVF private-thread guard (`block_hvf_private_thread_signals`) blocks
 *     exactly the guest-routed host set around `hv_vm_create`; the stacks
 *     say whether that guard, or another blocker, leaked onto a worker.
 *
 * (b) Provider ABI facts (macOS 26 / arm64): `syscall::__pthread_sigmask`
 *     and `syscall::sigprocmask` take (how, user set pointer, user old-set
 *     pointer); SIG_BLOCK=1, SIG_UNBLOCK=2, SIG_SETMASK=3; `sigset_t` is a
 *     32-bit mask with bit (signo - 1). The syscall provider follows forked
 *     children under the progeny predicate. The tracked mask starts at 0 for
 *     a thread first seen here, so an INHERITED wide mask shows only through
 *     the creating thread's `bsdthread_create` record.
 *
 *     Finding (2026-10-01, go-build, reservations on): no traced syscall
 *     widened an executor's mask. Its own boundary read (WIDE-QUERY,
 *     `current_signal_mask`) saw 0xfffefeff, every catchable signal, on
 *     two executors at once, right after another thread's `carrick_fatal`
 *     began `abort()` (its 0xffffffff / 0xffffffdf SETMASKs). So the audit
 *     failure was the abort's fallout, not a leak: read stderr for
 *     `carrick fatal` before chasing a mask writer. The fatal there was the
 *     host fault classifier answering a root held by EL1 with `Busy`.
 *     ustack() frames in carrick print unsymbolized when the carrier has
 *     exited; `atos -o target/release/carrick -l <load>` recovers them (the
 *     load address is the frame of `thread_start` minus its nm offset,
 *     page-rounded).
 *
 * (c) Perturbation: low. Mask changes are rare on the carrier (VM and vCPU
 *     creation, tty paths); only wide ones take a ustack().
 *
 * Usage (run as the carrier; `$target` is the carrick process):
 *   target/release/carrick trace --script scripts/dtrace/host-signal-mask-wide-blocks.d \
 *     -- run ... <workload>
 */

inline int WIDE = 16;

self uint32_t mask;
self uint32_t set;
self int how;
self int armed;
self int wide;
this uint32_t old;
this uint32_t seen;
self uint64_t query;

syscall::__pthread_sigmask:entry,
syscall::sigprocmask:entry
/(pid == $target || progenyof($target)) && arg1 != 0/
{
    self->how = arg0;
    self->set = *(uint32_t *)copyin(arg1, 4);
    self->armed = 1;
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/self->armed && errno == 0/
{
    this->old = self->mask;
    self->mask = self->how == 1 ? (self->mask | self->set)
        : self->how == 2 ? (self->mask & ~self->set)
        : self->how == 3 ? self->set : self->mask;
    this->x = self->mask;
    this->x = this->x - ((this->x >> 1) & 0x55555555);
    this->x = (this->x & 0x33333333) + ((this->x >> 2) & 0x33333333);
    this->x = (this->x + (this->x >> 4)) & 0x0f0f0f0f;
    this->bits = (this->x * 0x01010101) >> 24;
    self->wide = this->bits >= WIDE;
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/self->armed && errno == 0 && self->wide/
{
    printf("WIDE-BLOCK pid=%d tid=%d how=%d set=0x%08x mask=0x%08x\n",
        pid, tid, self->how, self->set, self->mask);
    ustack();
    @wide[pid, tid] = count();
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/self->armed && errno == 0 && !self->wide && this->old != 0/
{
    printf("NARROW pid=%d tid=%d how=%d mask=0x%08x\n", pid, tid, self->how, self->mask);
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/self->armed/
{
    self->armed = 0;
}

/*
 * A query (`set == NULL`) that READS a wide mask: the reader's stack names
 * the thread that holds it, even when no traced syscall set it (a thread
 * born with a wide kernel mask, e.g. a workqueue thread).
 */
syscall::__pthread_sigmask:entry,
syscall::sigprocmask:entry
/(pid == $target || progenyof($target)) && arg1 == 0 && arg2 != 0/
{
    self->query = arg2;
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
{
    this->seen = 0;
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/self->query && errno == 0/
{
    this->seen = *(uint32_t *)copyin(self->query, 4);
}

syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/self->query/
{
    self->query = 0;
}

/* SIGHUP (bit 0) and SIGTERM (bit 14) both blocked: a wide mask. */
syscall::__pthread_sigmask:return,
syscall::sigprocmask:return
/(this->seen & 0x4001) == 0x4001/
{
    printf("WIDE-QUERY pid=%d tid=%d mask=0x%08x\n", pid, tid, this->seen);
    ustack();
}

syscall::bsdthread_create:entry
/(pid == $target || progenyof($target)) && self->wide/
{
    printf("THREAD-UNDER-WIDE-MASK pid=%d tid=%d mask=0x%08x\n", pid, tid, self->mask);
    ustack();
    @born[pid, tid] = count();
}

END
{
    printa("wide blocks pid=%d tid=%d: %@d\n", @wide);
    printa("threads born under a wide mask, creator pid=%d tid=%d: %@d\n", @born);
}

proc:::exit
/pid == $target/
{
    exit(0);
}
