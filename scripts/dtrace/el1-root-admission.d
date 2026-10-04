#!/usr/sbin/dtrace -qs
/*
 * WHICH ADDRESS SPACES DID GUEST EL1 GET TO SERVE?
 *
 * (a) What it measures: every reservation root admission decided at an
 *     address space's publication, one line each, and a per-(origin,
 *     outcome) count at exit. It includes first-load candidate phases
 *     before reservation admission can fire. It also counts syscall-return
 *     as a positive control for the same traced child/provider; zero of both means this
 *     trace cannot establish whether publication occurred. An MM whose root
 *     is admitted (`delegated`)
 *     has its anonymous brk/mmap/munmap/mprotect served by EL1; every other
 *     outcome keeps the host serving them (correct, slower). A zero-event
 *     run means no address space was published (no EL1 zone, switching
 *     off, or a non-switchable memory model), never "all delegated".
 *
 * (b) Provider ABI: `hvpatch-el1-root-admission(u64 mm, u32 origin,
 *     u32 outcome)`. origin: 0 = the MM's first load (initial runner or
 *     exec), 1 = fork commit. outcome (`HvpatchEl1RootAdmission`):
 *     0 delegated, 1 host_setup (CARRICK_EL1_RESERVATIONS=0 or no
 *     provider), 2 no_authority, 3 refused_busy, 4 refused_stale,
 *     5 refused_invalid, 6 refused_metadata_required, 7 refused_other.
 *     Live-qualified on signed /bin/true on 2026-10-03: origin=0/outcome=0,
 *     candidate phases 0,1,5, prepublish phases 0,9,4, and six syscall
 *     returns on one traced child (run-id n1e-root5-20261003).
 *     `hvpatch-el1-root-candidate(u64 asid, u32 phase, u64 ttbr0,
 *     u64 ttbr1)` phases: 0 first unsettled lease attempt, 1 loaded-root
 *     closure entered, 2 no switchable roots, 3 lease/root mismatch,
 *     4 closed publication refused, 5 publication opened. This probe is
 *     Live qualification requires a phase and the syscall positive control
 *     to fire on the same signed artifact.
 *     `hvpatch-el1-root-prepublish(u64 mm, u32 phase)` phases:
 *     0 admission requested, 1 executor authority refused, 2 unpublished
 *     slot refused, 3 root publication refused, 4 owner publication returned,
 *     5 duplicate MM slot, 6 address-space slot refused, 7 reservation-root
 *     installation refused, 8 fence binding refused, 9 closed root published.
 *
 * (c) Perturbation: admission probes fire a bounded number of times per
 *     published address space; the positive control counts every guest
 *     syscall return, so use this script only to diagnose admission.
 *
 * Usage: target/release/carrick trace --script scripts/dtrace/el1-root-admission.d -- run ...
 */

#pragma D option quiet

carrick*:::hvpatch-el1-root-admission
/pid == $target || progenyof($target)/
{
    printf("EL1ROOTADMISSION1|mm=%llu|origin=%u|outcome=%u|pid=%d\n",
        (uint64_t)arg0, (uint32_t)arg1, (uint32_t)arg2, pid);
    @admissions[(uint32_t)arg1, (uint32_t)arg2] = count();
}

carrick*:::hvpatch-el1-root-candidate
/pid == $target || progenyof($target)/
{
    printf("EL1ROOTADMISSION1|candidate|asid=%llu|phase=%u|ttbr0=%llx|ttbr1=%llx|pid=%d\n",
        (uint64_t)arg0, (uint32_t)arg1, (uint64_t)arg2, (uint64_t)arg3, pid);
    @candidates[(uint32_t)arg1] = count();
}

carrick*:::hvpatch-el1-root-prepublish
/pid == $target || progenyof($target)/
{
    printf("EL1ROOTADMISSION1|prepublish|mm=%llu|phase=%u|pid=%d\n",
        (uint64_t)arg0, (uint32_t)arg1, pid);
    @prepublish[(uint32_t)arg1] = count();
}

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{
    @syscall_returns = count();
}

proc:::exit
/pid == $target/
{
    exit(0);
}

dtrace:::END
{
    printa("EL1ROOTADMISSION1|summary|origin=%u|outcome=%u|count=%@d\n", @admissions);
    printa("EL1ROOTADMISSION1|candidate-summary|phase=%u|count=%@d\n", @candidates);
    printa("EL1ROOTADMISSION1|prepublish-summary|phase=%u|count=%@d\n", @prepublish);
    printa("EL1ROOTADMISSION1|positive-control|syscall-returns=%@d\n", @syscall_returns);
}
