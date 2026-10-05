#!/usr/sbin/dtrace -qs
/*
 * WHICH OWNER FORK SERVICE STAGE REFUSED THE CLOSED CHILD?
 *
 * (a) Count closed child publications and print each owner Fork refusal's
 *     raw Linux errno, service stage and exact parent/child MM identity.
 *     A closed publication with no refusal is not proof of a successful
 *     fork; compare the guest exit and the host fork runtime stages too.
 *
 * (b) Provider ABI declared by carrick-observability for Darwin/arm64:
 *     hvpatch-owner-fork-refusal(u32 errno, u64 stage, u64 parent_mm,
 *     u64 child_mm, u64 parent_generation). Stages: 0 slot, 1 operation,
 *     2 parent space, 3 table pool/live words, 4 census, 5 prepare,
 *     6 physical custody, 7 owner publication, 8 detached receipt.
 *     hvpatch-el1-root-prepublish(u64 mm, u32 phase) phase 9 records the
 *     closed child publication before this service starts. Live-qualified
 *     2026-10-05 on e1435e4e0: VMA/ptrace each emitted two controls and
 *     errno=22/stage=3 with errors=0, bounded=0, consumer drops rejected.
 *     Receipt: docs/perf-results/2026-10-05-n1-maintenance-gate.md. Zero
 *     refusal events do not prove a successful owner Fork. Darwin has no
 *     dtrace:::DROP probe (live-qualified 2026-10-05); carrick trace rejects
 *     all libdtrace consumer drop counters. Require --require-script-exit
 *     and a zero CLI exit in addition to this script summary.
 *     hvpatch-owner-fork-stage3-refusal(u64 check, u64 parent_ttbr0,
 *     u64 child_base, u64 parent_base, u64 packed_lengths)
 *     fires only on stage-3 EINVAL. Check 1=child arena, 2=parent arena,
 *     3=parent root. Packed lengths are child high/parent low 32 bits;
 *     TTBR0 includes the ASID in its high bits. Five arguments fit the
 *     Darwin USDT provider limit.
 *     trace-witness-exit(i32 raw_unix_wait_status)
 *     fires after the external witness has completed, including its carrier
 *     cleanup. guest-exit(u32 host_pid, i32 code) records runtime results.
 *     SIP on cloudmac blocks proc:::exit (qualified 2026-10-05); under -Z
 *     that absent probe made captures reach their bound. VM-destroy-success
 *     also does not fire on the retained 299b19ca1 test's exit: the cached
 *     carrier outlives its guest roots. Use the launcher's witness-exit USDT
 *     for external tests. The wait-status companion is the witness verdict;
 *     the trace CLI's successful script receipt qualifies the capture only.
 *     Inspect both the libtest result and that raw wait status, never infer
 *     a workload pass from a zero trace CLI status.
 *     Product invocations keep their proc:::exit control and fail closed if
 *     that provider is unavailable. Never interpret a bounded trace as zero
 *     refusals or increase the workload/trace bound to conceal this failure.
 *
 * (c) Perturbation: one failure-only scalar probe per refused owner Fork,
 *     plus one low-frequency publication probe per child. No syscall or
 *     descriptor hot-path probe is enabled. The 45 s bound prevents a
 *     wedged guest from leaving this capture running indefinitely.
 *
 * Usage: target/release/carrick trace --script scripts/dtrace/hvpatch-owner-fork-refusal.d -- run ...
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    refusals = 0;
    children = 0;
    errors = 0;
    bounded = 0;
    results = 0;
    witness_closed = 0;
}

carrick*:::hvpatch-el1-root-prepublish
/(pid == $target || progenyof($target)) && arg1 == 9/
{
    children++;
    carrier_children[pid]++;
    printf("OWNERFORKREFUSAL1|closed-child|mm=%llu|pid=%d\n",
        (uint64_t)arg0, pid);
}

carrick*:::hvpatch-owner-fork-refusal
/pid == $target || progenyof($target)/
{
    refusals++;
    printf("OWNERFORKREFUSAL1|refused|errno=%u|stage=%llu|parent_mm=%llu|child_mm=%llu|generation=%llu|pid=%d\n",
        (uint32_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4, pid);
}

carrick*:::hvpatch-owner-fork-stage3-refusal
/pid == $target || progenyof($target)/
{
    printf("OWNERFORKREFUSAL1|stage3|check=%llu|parent_ttbr0=0x%llx|child_base=0x%llx|child_len=0x%llx|parent_base=0x%llx|parent_len=0x%llx|pid=%d\n",
        (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)(arg4 >> 32), (uint64_t)arg3,
        (uint64_t)(arg4 & 0xffffffff), pid);
}

dtrace:::ERROR
{
    errors++;
}

carrick*:::guest-exit
/(pid == $target || progenyof($target)) && carrier_children[pid] != 0/
{
    results++;
    printf("OWNERFORKREFUSAL1|guest-result|code=%d|pid=%d\n",
        (int32_t)arg1, pid);
}

carrick*:::trace-witness-exit
/pid == $target/
{
    witness_closed++;
    printf("OWNERFORKREFUSAL1|witness-closed|wait_status=%d|pid=%d\n",
        (int32_t)arg0, pid);
    exit(children == 0 || results == 0 || errors != 0 ? 3 : 0);
}

proc:::exit
/pid == $target/
{
    exit(children == 0 || errors != 0 ? 3 : 0);
}

profile:::tick-1sec
/timestamp - started > 45 * 1000000000/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("OWNERFORKREFUSAL1|summary|closed_children=%d|refusals=%d|guest_results=%d|witness_closed=%d|errors=%d|bounded=%d\n",
        children, refusals, results, witness_closed, errors, bounded);
}
