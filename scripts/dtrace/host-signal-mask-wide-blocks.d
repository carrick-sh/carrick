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
 * (c) Perturbation: low. Mask changes are rare on the carrier (VM and vCPU
 *     creation, tty paths); only wide ones take a ustack().
 *
 * Usage (run as the carrier; `$target` is the carrick process):
 *   target/release/carrick trace --script scripts/dtrace/host-signal-mask-wide-blocks.d \
 *     -- run ... <workload>
 */

inline int WIDE = 16;

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
