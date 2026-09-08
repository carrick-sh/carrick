#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-first-touch-segv.d — WHICH ARM of the runtime fault path lowered a
 * guest data abort to a delivered SIGSEGV, on the kernel (hvpatch) lane.
 *
 * (a) WHAT IT MEASURES
 * -------------------
 * The Go startup `SIGSEGV: segmentation violation … sigcode=1` (SEGV_MAPERR)
 * in `runtime.persistentalloc1` is the first touch of a 256 KiB chunk the SAME
 * thread just obtained from `mmap` (Go's `sysAlloc`; the write at the chunk
 * base is `*(*uintptr)(persistent.base) = chunks`). The runtime has five ways
 * to deliver that fault instead of resolving it (`resolve_mutating_fault`,
 * `crates/carrick-runtime/src/vcpu_loop/signal.rs`): the page is not in
 * `resident_tracked_ranges`, not in `resident_fault_ranges`, its arming
 * protection denies the access class, the backend `protect_range` (sparse
 * materialization) REFUSED it, or the stale-leaf retry found a valid leaf
 * and did not retry. Only the refusal has a probe
 * (`resident-fault-protection-error`); this script pairs it with the fault
 * and the delivery so a SIGSEGV record says whether the backend refused the
 * page or the dispatcher never had a plan for it.
 *
 * Per host thread it latches the last `vcpu-fault` (ESR/ELR/FAR), the last
 * serialized stage-1 walk (`pt-fault-walk` L0..L3, `pt-fault-ttbr`), the last
 * mmap-family syscall entry/return (222=mmap, 215=munmap, 226=mprotect,
 * 233=madvise, 216=mremap) and whether a `resident-fault-protection-error`
 * or `hvpatch-stale-stage1-retry` fired since the fault. It prints ONE line
 * per `resident-fault-protection-error` (immediately, with the backend's
 * formatted error) and ONE line per `signal-deliver` of signum 11.
 *
 * (b) PROVIDER ABI (qualified live on macOS 26 / arm64, 2026-09-07,
 *     binary 1536e789…)
 * -------------------
 * carrick*:::vcpu-fault (esr, elr, far, x30, sp, host_pid) fires on every
 * EL0 abort HVF surfaces, both the direct-exit and the EL1-vector route.
 * carrick*:::pt-fault-walk (va, l0, l1, l2, l3) and pt-fault-ttbr (va,
 * ttbr0) fire from the engine's `resolve_frame_cow_fault` before the runtime
 * decides. carrick*:::resident-fault-protection-error (page, prot, error C
 * string) fires only when the backend refuses a logically allowed first
 * touch. carrick*:::hvpatch-stale-stage1-retry (far, access, linux_tid).
 * carrick*:::signal-deliver (linux_tid, signum) fires in
 * `inject_fault_signal` for a synchronous fault AND in ordinary signal
 * delivery; the signum filter keeps only SIGSEGV. syscall-entry (nr, name,
 * host pointer to six u64 args) / syscall-return (nr, name, retval, errno).
 * macOS zeroes arg5, so no probe here reads it.
 *
 * (c) PERTURBATION
 * ---------------
 * Low but nonzero: every EL0 abort (one per first-touched 4 KiB page under
 * the 64 KiB fault window) costs three probe fires and a few thread-local
 * stores; mmap-family syscalls cost one `copyin`. No syscall hot path other
 * than the mmap family is instrumented. Zero SIGSEGV lines means the
 * probes did not fire — read the `ticks` and `faults` counters in the END
 * summary before believing an empty capture.
 *
 * Usage: sudo dtrace -Zqs scripts/dtrace/hvpatch-first-touch-segv.d <seconds>
 * (no $target: every `carrick*` provider on the host is matched; bound the
 * capture with the seconds argument so the consumer ends on its own and
 * never has to be killed under a live tracee).
 */

#pragma D option quiet
#pragma D option strsize=512

uint64_t last_far[int];
uint64_t same_far[int];
uint64_t last_munmap_ts[int];
uint64_t last_munmap_tid[int];
uint64_t last_munmap_addr[int];
uint64_t last_munmap_len[int];

dtrace:::BEGIN
{
    printf("FTSEGV|header|version=1|bound_s=%d\n", $1);
    ticks = 0;
    faults = 0;
    segvs = 0;
    refusals = 0;
    binds = 0;
    delivers = 0;
}

carrick*:::vcpu-fault
{
    faults++;
    same_far[tid] = (last_far[tid] == arg2) ? same_far[tid] + 1 : 0;
    last_far[tid] = arg2;
    self->esr = arg0;
    self->elr = arg1;
    self->far = arg2;
    self->fault_ts = timestamp;
    self->refused = 0;
    self->stale_retry = 0;
}

carrick*:::pt-fault-walk
{
    self->l0 = arg1;
    self->l1 = arg2;
    self->l2 = arg3;
    self->l3 = arg4;
}

carrick*:::pt-fault-ttbr
{
    self->ttbr0 = arg1;
}

carrick*:::syscall-entry
/arg0 == 222 || arg0 == 215 || arg0 == 226 || arg0 == 233 || arg0 == 216/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    self->sc_nr = arg0;
    self->sc_a0 = this->a[0];
    self->sc_a1 = this->a[1];
    self->sc_a2 = this->a[2];
    self->sc_a3 = this->a[3];
}

/*
 * Process-wide latch of the last munmap ANY thread of this carrier entered:
 * a first touch delivered as SIGSEGV is read against the sibling unmap that
 * preceded it (address, length, thread, age).
 */
carrick*:::syscall-entry
/arg0 == 215/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    last_munmap_ts[pid] = timestamp;
    last_munmap_tid[pid] = tid;
    last_munmap_addr[pid] = this->a[0];
    last_munmap_len[pid] = this->a[1];
}

carrick*:::syscall-return
/arg0 == 222 || arg0 == 215 || arg0 == 226 || arg0 == 233 || arg0 == 216/
{
    self->sc_ret = arg2;
    self->sc_ts = timestamp;
}

carrick*:::resident-fault-protection-error
{
    refusals++;
    self->refused = 1;
    printf("FTSEGV|refusal|ts=%d|host_pid=%d|host_tid=%d|page=%x|prot=%x|far=%x|esr=%x|elr=%x|err=%s\n",
        timestamp, pid, tid, arg0, arg1, self->far, self->esr, self->elr,
        copyinstr(arg2));
}

carrick*:::hvpatch-stale-stage1-retry
{
    self->stale_retry++;
}

/*
 * The runtime's decision to deliver: reason 0 not tracked, 1 no pending edit,
 * 2 arming protection denies the access, 3 backend refused, 4 stale leaf not
 * retried. Printed at once with the latched fault and the process-wide last
 * munmap so the arm and its neighbourhood read from one line.
 */
carrick*:::hvpatch-first-touch-deliver
{
    delivers++;
    printf("FTSEGV|deliver|ts=%d|host_pid=%d|host_tid=%d|linux_tid=%d|far=%x|reason=%d|fault_far=%x|esr=%x|elr=%x|same_far=%d|l0=%x|l1=%x|l2=%x|l3=%x|fault_age_ns=%d|last_munmap_addr=%x|last_munmap_len=%x|last_munmap_host_tid=%d|last_munmap_age_ns=%d\n",
        timestamp, pid, tid, (int32_t)arg2, arg0, (uint32_t)arg1, self->far,
        self->esr, self->elr, same_far[tid], self->l0, self->l1, self->l2,
        self->l3, timestamp - self->fault_ts, last_munmap_addr[pid],
        last_munmap_len[pid], last_munmap_tid[pid],
        timestamp - last_munmap_ts[pid]);
}

carrick*:::stage1-arena-bind,
carrick*:::stage1-arena-install,
carrick*:::stage1-arena-replace
{
    printf("FTSEGV|%s|ts=%d|host_pid=%d|host_tid=%d|a0=%x|a1=%x|a2=%x|a3=%x\n",
        probename, timestamp, pid, tid, arg0, arg1, arg2, arg3);
}

/*
 * A task offering the MM-scoped frame-COW runtime binding (mm, asid,
 * authority pointer, offering Linux tid, replaced). Every bind is printed:
 * the question is whether one lands between a sibling's `vcpu-fault` and its
 * refusal, on the SAME mm, with a different authority pointer.
 */
carrick*:::hvpatch-cow-runtime-bind
{
    binds++;
    printf("FTSEGV|bind|ts=%d|host_pid=%d|host_tid=%d|mm=%d|asid=%d|authority=%x|linux_tid=%d|replaced=%d\n",
        timestamp, pid, tid, arg0, (uint32_t)arg1, arg2, (int32_t)arg3,
        (uint32_t)arg4);
}

carrick*:::signal-deliver
/arg1 == 11/
{
    segvs++;
    printf("FTSEGV|segv|ts=%d|host_pid=%d|host_tid=%d|linux_tid=%d|esr=%x|elr=%x|far=%x|l0=%x|l1=%x|l2=%x|l3=%x|ttbr0=%x|refused=%d|stale_retries=%d|same_far=%d|fault_age_ns=%d|last_sc_nr=%d|last_sc_a0=%x|last_sc_a1=%x|last_sc_a2=%x|last_sc_a3=%x|last_sc_ret=%x|last_sc_age_ns=%d\n",
        timestamp, pid, tid, (int32_t)arg0, self->esr, self->elr, self->far,
        self->l0, self->l1, self->l2, self->l3, self->ttbr0, self->refused,
        self->stale_retry, same_far[tid], timestamp - self->fault_ts, self->sc_nr,
        self->sc_a0, self->sc_a1, self->sc_a2, self->sc_a3, self->sc_ret,
        timestamp - self->sc_ts);
}

profile:::tick-1s
{
    ticks++;
}

profile:::tick-1s
/ticks >= $1/
{
    exit(0);
}

dtrace:::END
{
    printf("FTSEGV|end|ticks=%d|faults=%d|segvs=%d|refusals=%d|binds=%d|delivers=%d\n",
        ticks, faults, segvs, refusals, binds, delivers);
}
