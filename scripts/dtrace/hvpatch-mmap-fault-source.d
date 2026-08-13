#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-mmap-fault-source.d — WHICH carrick code faults the pages that a
 * guest `mmap` costs, on the kernel (hvpatch) lane.
 *
 * (a) WHAT IT MEASURES
 * -------------------
 * Zero-fill faults (`vminfo:::zfod`) taken while carrick is SERVICING a guest
 * `mmap`, keyed by the faulting user PC and by user stack. The guest is
 * stopped inside its service window, so every fault this attributes is
 * carrick's own host-side page touching — not the guest touching its memory.
 *
 * It exists because the AMP1 census
 * (docs/perf-results/2026-08-13-hvpatch-kernel-lane-amp-ledger.md) found the
 * kernel lane's largest CPU term is faults, not syscalls: 150,749 in-window
 * `zfod` on a cold `go build` at 76.7 per guest `mmap`, while that syscall's
 * host-call amplification is already 1.04x. This script is what turned that
 * number into a cause, and it is the verification instrument for KF, the
 * phase that has to remove it.
 *
 * FINDING AS OF 2026-08-13 (commit 342ac750f): 145,429 of 146,531 in-window
 * faults have exactly one caller —
 *     libsystem_platform.dylib`__bzero
 *     carrick`carrick_runtime::dispatch::mem::…::mmap+0xda0
 * which is `let mut bytes = vec![0; length_usize]` (dispatch/mem.rs:2792),
 * the eager snapshot buffer for a file mapping that was not lowered to a host
 * file mapping. A rerun that does NOT show `__bzero` dominating means KF
 * landed; a rerun that shows a different dominant caller means the cost moved
 * rather than went away, which is the outcome this script exists to catch.
 *
 * (b) PROVIDER ABI FACTS, qualified rather than assumed
 * ----------------------------------------------------
 *   1. `carrick*:::hvpatch-syscall-service-begin` and `-clear` publish
 *      (pid, tid, asid, number) — so the canonical AArch64 syscall number is
 *      **arg3**, NOT arg0, which is the guest pid
 *      (crates/carrick-observability/src/probes.rs:4622 and :4658). Screening
 *      on arg0 would select by pid and silently measure the wrong thing.
 *      222 is `mmap` on the canonical AArch64 table.
 *   2. `-begin` is the identity-bearing probe and fires only when a consumer
 *      is attached, so `-clear` may arrive without a matching `-begin` on a
 *      thread that inherited a span. That closes the window either way here,
 *      which is the conservative direction: it can only UNDER-attribute.
 *   3. `dtrace -Z` is REQUIRED. The USDT probes live in a process that has not
 *      started when this program compiles; without `-Z` it fails to compile
 *      rather than silently measuring nothing.
 *
 * (c) THE TRAP THAT COSTS AN HOUR
 * -------------------------------
 * **Symbolication must happen while the traced process is still ALIVE.** At
 * `dtrace:::END` the workload has already exited and every `ustack()`/`usym()`
 * frame comes back as a bare hexadecimal address, which reads exactly like a
 * stripped binary and is easy to misdiagnose as one. Hence the `tick-5s`
 * snapshot: take the LAST block printed before the workload finishes.
 *
 * Under `hvpatch` there is ONE host process for all guest processes, so
 * `ustack()` is trustworthy here — unlike the native lane, where ~70
 * self-re-exec'd processes carry independent ASLR slides and stacks come back
 * corrupted.
 *
 * (d) PERTURBATION
 * ---------------
 * HIGH — the fault probes fire hundreds of thousands of times. COUNTS and
 * their PROPORTIONS are the claim. Wall time under this script is not
 * performance authority and must never be compared against an untraced run.
 *
 * (e) RUNNING IT
 * -------------
 * `-c` does not work: dtrace cannot exec the codesigned, entitled carrick
 * binary and fails with "Operation not permitted". Arm the script first, wait
 * for its first snapshot, then start the workload separately:
 *
 *   sudo dtrace -Zqs scripts/dtrace/hvpatch-mmap-fault-source.d > out.txt &
 *   until grep -q SNAPSHOT out.txt; do sleep 2; done
 *   target/release/carrick run --exec-backend hvpatch <image> <workload>
 */
#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=64m
#pragma D option bufsize=64m

dtrace:::BEGIN
{
	printf("hvpatch-mmap-fault-source: arming; start the workload now\n");
}

/* 222 == canonical AArch64 `mmap`; arg3 is the number on BOTH probes. */
carrick*:::hvpatch-syscall-service-begin
/arg3 == 222/
{
	self->in_mmap = 1;
}

carrick*:::hvpatch-syscall-service-clear
{
	self->in_mmap = 0;
}

vminfo:::zfod
/self->in_mmap/
{
	@by_symbol[usym(uregs[R_PC])] = count();
	@by_stack[ustack(7)] = count();
	@total = count();
}

tick-5s
{
	printf("=== SNAPSHOT (take the LAST one; see header (c)) ===\n");
	printa("%@8d  %A\n", @by_symbol);
	printf("--- top stacks ---\n");
	trunc(@by_stack, 3);
	printa(@by_stack);
	printa("INWINDOW_MMAP_ZFOD %@d\n", @total);
}
