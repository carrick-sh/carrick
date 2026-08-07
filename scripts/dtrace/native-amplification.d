#!/usr/sbin/dtrace -s
/*
 * Darwin kernel amplification ledger for the native (DSR) lane -- protocol AMP1.
 *
 * (a) WHAT IT MEASURES
 * -------------------
 * How much Darwin kernel work ONE Linux guest operation costs, in the four
 * currencies the fs census could not supply, all keyed on the same guest-op
 * service window (`carrick*:::native-syscall-service-entry`/`-end`):
 *
 *   section=host-syscalls        (guest_slot, host_call) -> count
 *   section=host-syscall-cpu     (guest_slot, host_call) -> vtimestamp sum, max
 *   section=mach-traps           (guest_slot, trap)      -> count
 *   section=mach-trap-cpu        (guest_slot, trap)      -> vtimestamp sum
 *   section=faults               (guest_slot, kind)      -> count
 *   section=guest-syscalls       guest_slot              -> count (denominator)
 *   section=totals               each of the above, ungrouped (closure inputs)
 *
 * `guest_slot` is an ENCODED key, not a syscall number, and exactly one Rust
 * decoder is allowed to read it:
 *     slot == 1            -> `carrick-only`: host work outside any guest
 *                             service window (image setup, supervision,
 *                             teardown, park/wake). Real cost, but NOT
 *                             amplification of any guest op -- it must never
 *                             enter a per-op ratio.
 *     slot >= 2            -> canonical AArch64 Linux syscall number == slot - 2.
 *     slot == 0            -> impossible; the reader rejects the stream.
 * The +2 bias exists because canonical number 0 is a real syscall (`io_setup`)
 * and because DTrace deallocates an associative entry the moment it is assigned
 * zero -- see (b).
 *
 * Deliberately NOT here: `ustack()`. ~70 self-re-exec'd guest processes carry
 * independent ASLR slides, so stacks come back corrupted rather than empty.
 * Call-site attribution is `carrick debug alloc-owner-census`'s job, joined
 * offline. Also NOT here: `copyinstr()` of the guest-op NAME. The number is the
 * typed domain (`carrick_abi::syscall::lookup_aarch64`); copying a string per
 * guest syscall would add ~88k copyins and a string key-space to a program whose
 * declared risk is exactly unqualified key-space pressure.
 *
 * (b) PROVIDER ABI FACTS
 * ---------------------
 * Qualified from committed receipts WITHOUT a capture:
 *
 *   1. `carrick*:::native-syscall-service-entry` arg0 IS the canonical AArch64
 *      syscall number and arg1 is a name pointer
 *      (`crates/carrick-observability/src/probes.rs:2282`,
 *      `native_syscall_service_entry(number: u64, name: &str)`; the call site
 *      `crates/carrick-runtime/src/native_darwin.rs:3932` takes the number from
 *      `SyscallRequest::number.raw()`). AMP1 reads arg0 only.
 *   2. That USDT pair is UNCONDITIONAL -- `NativeSyscallServiceSpan::open`
 *      (`native_darwin.rs:3168`) calls an `#[inline(always)]` wrapper straight
 *      onto the probe macro, with no `CARRICK_DSR_PROFILE` gate. The profile is
 *      therefore `requires_runtime_profile() == false`; requiring the runtime
 *      profile arm would charge this ledger host CPU that only exists because
 *      the ledger asked for it.
 *   3. Under the VMM backend those probes NEVER fire, so every host call would
 *      land in `carrick-only`. A guest-syscall total of 0 is a named
 *      `wrong-backend` error, not an empty result (`native-fs-amplification.d`
 *      header (b)).
 *   3a. THE SERVICE WINDOW IS NOT A BALANCED entry/end PAIR, and assuming it is
 *      refuses every real build. Two shipped asymmetries:
 *        - INHERITED SPANS. `NativeSyscallServiceSpan::inherited_open`
 *          (`native_darwin.rs:3181`) fires NO entry probe -- the parent already
 *          fired one for that guest op -- yet the clone child closes it from a
 *          NEW tid (`:5240`) and the fork child from a NEW pid (`:4275`). So an
 *          `-end` whose (pid, tid) has never been seen is EXPECTED, not a drop.
 *          Synthesizing an entry there would double-count `@guest_total`.
 *        - TERMINAL HANDOFF. `terminal_handoff()` (`:3214`) abandons the span
 *          WITHOUT an `-end`, because the handoff may still fail and reopen
 *          (`reopen_after_failed_terminal_handoff`). All six sites end in
 *          process death or a successful exec, so `proc:::exec-success` and
 *          `proc:::lwp-exit` are where the slot retires; post-terminal host
 *          work is `carrick-only`.
 *      The never-seen (0) versus idle (1) sentinel is what keeps a genuine
 *      double close distinguishable from both.
 *   4. Scope is the `tracked[]` table seeded from `$target` and grown through
 *      `proc:::create`, NEVER `execname`: `carrick trace` runs libdtrace
 *      IN-PROCESS inside a `carrick` binary, and AGENTS.md records a profile
 *      that was 54% profiler for exactly that reason.
 *   5. `vtimestamp` advances only while the current thread is ON-CPU, so an
 *      entry/return delta is host CPU-ns and a blocked call does not masquerade
 *      as kernel work (`native-syscall-cpu-directional.d:15-16,49-62`, the house
 *      idiom this inherits verbatim).
 *   6. `mach_trap:::entry`/`return` exist and pair per thread on this build
 *      (`native-terminal-qualify.d:69-98`). Mach traps are NOT syscalls: the
 *      2026-08-01 audit found libmalloc's large zone allocating via
 *      `mach_vm_allocate`, which is why a `syscall:::`-only instrument missed
 *      two thirds of the fault mass.
 *   7. `vminfo:::as_fault` / `:::zfod` / `:::cow_fault` fire in the FAULTING
 *      thread's context and may be keyed `[pid, tid]`
 *      (`native-fault-attribution.d:453-470` predicates a zfod clause on
 *      `memory_number[pid, tid]`, and that export contract reconciles against
 *      the exact provider totals). `probename` names the kind. AMP1 is
 *      count-only, so the arg2 page-base qualification is not relied upon here.
 *   8. Assigning 0 to a thread-local or an associative entry DEALLOCATES it onto
 *      DTrace's dirty list (`native-wall.d`'s shipped idle-sentinel contract,
 *      asserted in `crates/carrick-cli/tests/trace_profile.rs`). Every hot slot
 *      here therefore retires to a NONZERO sentinel: `service_slot` 1 = idle,
 *      `amp_cpu` 1 = consumed.
 *   9. `printa` on an EMPTY aggregation prints NOTHING. A section that printed
 *      no rows must stay distinguishable from a section that never ran, so every
 *      required total is seeded `sum(0)` in BEGIN (`native-shape-census.d`'s
 *      shipped idiom) and every section marker is an unconditional `printf`.
 *  10. DTrace's own drop counters -- principal, aggregation, dynamic,
 *      dynamic-rinse, dynamic-dirty -- are NOT readable from D. They arrive
 *      through libdtrace's drop handler
 *      (`crates/carrick-runtime/src/dtrace_consumer.rs:120-124,187-207`), which
 *      carrick already captures into `DTraceRunReport`. `section=drops` below
 *      therefore carries the counters this PROGRAM owns; the consumer-side
 *      counters are enforced by the Rust reader, which rejects any nonzero.
 *      Both halves are required: drops are silent, and on this instrument a
 *      silent drop reads as LOWER amplification and would be banked as good news.
 *
 * COMPILE-QUALIFIED WITHOUT A CAPTURE. `dtrace -e -s <this file>` fails at the
 * first clause with "args[ ] may not be referenced because probe description
 * proc:::create matches an unstable set of probes" -- and so do
 * `native-fault-attribution.d`, `native-wall.d` and `native-fs-amplification.d`
 * verbatim, because carrick compiles in-process with `DTRACE_C_ZDEFS |
 * DTRACE_C_PSPEC` and a real `$target`. Since that first error aborts the
 * compile, it also hides every later one. To qualify the REST of the program,
 * substitute `args[0]->pr_pid` -> `(pid_t)1` and `$target` -> `1` into a scratch
 * copy and compile that: this program, and the fully rendered form (header,
 * terminal roster and a substituted bound), both compile clean. That covers the
 * aggregation shapes, the `printa` key arity and formats, and the multi-probe
 * fault clause -- everything except behaviour.
 *
 * QUALIFY AT FIRST ARMING (Task 4 -- these cannot be settled without a capture):
 *   - whether `vtimestamp` advances across `mach_trap:::entry`/`return` on this
 *     build (the syscall provider is receipted above; the mach_trap one is not);
 *   - whether the fault-to-service-window join reproduces `native-fault`'s
 *     independent per-process totals (fact 7 is receipted for keying, not for
 *     this particular join);
 *   - the actual drop counters at the declared buffer sizes on the cold
 *     go-build: the sizes below are ARGUED from key-space, not measured;
 *   - the real perturbation multiple (the 2-4x in (c) is an estimate);
 *   - whether any host call shows entries without returns outside the qualified
 *     terminal roster printed in `section=terminal-calls`;
 *   - whether `section=window-events`' `inherited-end` count tracks the guest's
 *     actual `clone(CLONE_THREAD)` + `fork` count. It should be close to it; a
 *     large excess means a handoff path was missed, and ZERO on a threaded
 *     build means the inherited close is not reaching the probe at all;
 *   - whether a fork child's `-end` is ever observed BEFORE the parent's
 *     `proc:::create` admits it to `tracked[]`. If it is, those closes are
 *     silently dropped rather than counted (no false rejection either way);
 *   - whether Darwin's `tid` survives `execve`. Exec quiesces every sibling
 *     first, so at most ONE slot can be stranded, and only if the tid changes;
 *     `proc:::lwp-exit` retiring to never-seen is what bounds the tid-reuse
 *     case, and it is unqualified.
 *
 * (c) PERTURBATION: YES, AND MORE THAN ANY EXISTING PROFILE
 * --------------------------------------------------------
 * Four probe families fire in one program -- every host syscall, every mach
 * trap and every fault in a ~70-process tree. The fault probes alone are ~2M
 * events on the cold go-build workload and `native-fault-attribution.d` already
 * declares itself VERY HIGH on those alone. Expect a traced run at 2-4x untraced
 * wall.
 *
 *   - COUNTS and SAME-INSTRUMENT RATIOS are citable. WALL IS NEVER. The
 *     `elapsed_ns` in the completion record is diagnostic metadata.
 *   - The instrument's own cost is identifiable rather than hidden: libdtrace's
 *     `kdebug_trace64` / `kdebug_trace_string` land in `carrick-only`, where the
 *     reader subtracts them into a named sub-bucket (the fs entry found 3,182 of
 *     them, 6.4% of its run).
 *   - A capture with the fault join and one without are DIFFERENT INSTRUMENTS.
 *     The header records `joins=` and the comparator refuses to cross it.
 *
 * Buffer sizing, stated against `native-fs-amplification.d`'s 32m/64m/16m:
 *   aggsize=64m    2x. Bounded key-space: ~30 live guest ops x ~50 host calls x
 *                  3 keyed aggregations, plus mach and fault keys -- order 10k
 *                  records, order 1 MB per CPU. 64m is ~64x that and matches
 *                  what `native-fault-attribution.d` already carries through 2M
 *                  fault events.
 *   dynvarsize=256m 4x, the largest multiple because this is the genuinely
 *                  unqualified pressure: four u64 thread-locals plus
 *                  `service_slot[pid, tid]` across a ~70-process tree.
 *                  `native-syscall-cpu-directional.d` already runs a
 *                  syscall entry/return vtimestamp join on this workload at
 *                  exactly 256m.
 *   bufsize=32m    2x. Principal traffic is END-only here (all steady-state data
 *                  is aggregated), so the risk is the final `printa` flush
 *                  rather than the run.
 *   strsize=256    Inherited verbatim, NOT tuned down: a shorter `strsize`
 *                  truncates aggregation string keys, and two host calls sharing
 *                  a truncated key is precisely the silent-merge failure this
 *                  instrument exists to avoid.
 */
#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=256m
#pragma D option bufsize=32m
#pragma D option strsize=256

dtrace:::BEGIN
{
	started = timestamp;
	bound_elapsed_s = (uint64_t)0;
	bound_limit_s = (uint64_t)600;
	timed_out = 0;
	target_exit_reason = 0;
	probe_errors = 0;

	/* Fix retained dynamic-array values at their intended widths. */
	tracked[(pid_t)0] = 0;
	service_slot[(pid_t)0, (uint64_t)0] = (uint64_t)0;

	/*
	 * Seed every required total so an empty run prints an explicit zero
	 * instead of nothing at all (fact 9). `sum(1)` on the hot path is the
	 * counterpart of these `sum(0)` seeds.
	 */
	@guest_total = sum(0);
	@host_entry_total = sum(0);
	@host_return_total = sum(0);
	@host_cpu_total = sum(0);
	@mach_entry_total = sum(0);
	@mach_return_total = sum(0);
	@mach_cpu_total = sum(0);
	@fault_total["as_fault"] = sum(0);
	@fault_total["zfod"] = sum(0);
	@fault_total["cow_fault"] = sum(0);
	@drop_service_reentry = sum(0);
	@drop_service_unmatched = sum(0);
	@window_inherited_end = sum(0);
	/*
	 * An aggregation, not a plain global increment. `dtrace:::ERROR` fires on
	 * any CPU and D globals are unsynchronized, so a lost read-modify-write at
	 * the 0->1 boundary would make a corrupted stream read as clean --
	 * fail-OPEN, in the one counter whose whole job is to fail closed.
	 */
	@probe_errors = sum(0);

	tracked[$target] = 1;

	/* Substituted from the lossless native launch receipts. */
	/* CARRICK_AMP1_HEADER */

	/*
	 * The declared capture bound. Left as the shipped default when
	 * unrendered so the bundled template stays a legal D program; the
	 * completion record always reports the bound that was in force.
	 */
	/* CARRICK_AMP1_BOUND */
}

/* A D action fault makes the exact stream non-authoritative. */
dtrace:::ERROR
{
	@probe_errors = sum(1);
}

proc:::create
/tracked[pid]/
{
	tracked[args[0]->pr_pid] = 1;
}

proc:::exit
/tracked[pid] && pid != $target/
{
	tracked[pid] = 0;
}

proc:::exit
/pid == $target/
{
	target_exit_reason = arg0;
	tracked[pid] = 0;
	exit(0);
}

/*
 * The guest-op service window. Every join below reads `service_slot[pid, tid]`,
 * so this is the single point where a guest operation becomes attributable.
 */
carrick*:::native-syscall-service-entry
/tracked[pid]/
{
	@drop_service_reentry =
	    sum(service_slot[pid, tid] > (uint64_t)1 ? 1 : 0);
	service_slot[pid, tid] = (uint64_t)arg0 + (uint64_t)2;
	@guest_by_slot[(uint64_t)arg0 + (uint64_t)2] = sum(1);
	@guest_total = sum(1);
}

/*
 * Closing a window has THREE outcomes, and conflating them is what would make
 * this instrument refuse every real build. One clause, so the reads all happen
 * before the single write (a second clause on the same probe would observe the
 * first clause's mutation in its own predicate).
 *
 *   slot >  1  a window this thread opened, closing normally.
 *   slot == 0  this (pid, tid) has NEVER opened a window and its first event is
 *              an `-end`. That is exactly the inherited span:
 *              `NativeSyscallServiceSpan::inherited_open` fires no entry probe
 *              on purpose -- the PARENT fired it -- and the spawned child
 *              thread (`native_darwin.rs:5240`) and the fork child
 *              (`:4275`) then close it on their own tid/pid. EXPECTED on every
 *              `clone(CLONE_THREAD)` and every fork, so it gets its own class
 *              and is never a drop. Firing a synthetic entry there instead
 *              would double-count `@guest_total`, i.e. corrupt the denominator
 *              every amplification ratio divides by.
 *   slot == 1  a window on this thread already closed and another `-end`
 *              arrived. THAT is a pairing corruption, and the never-seen-vs-idle
 *              sentinel is what keeps it distinguishable from the line above.
 */
carrick*:::native-syscall-service-end
/tracked[pid]/
{
	@window_inherited_end =
	    sum(service_slot[pid, tid] == (uint64_t)0 ? 1 : 0);
	@drop_service_unmatched =
	    sum(service_slot[pid, tid] == (uint64_t)1 ? 1 : 0);
	service_slot[pid, tid] = (uint64_t)1;
}

/*
 * A TERMINAL HANDOFF emits no `-end` at all: `terminal_handoff()`
 * (`native_darwin.rs:3214`) moves the span to a state `Drop` deliberately does
 * not close, because the handoff can still FAIL and reopen
 * (`reopen_after_failed_terminal_handoff`), and an `-end` followed by a resume
 * would be a lie. Every one of the six handoff sites is followed by either
 * process death or a successful exec -- process exit (`:4055`), last-thread
 * (`:4091`), fork retirement (`:4283`), host self-exec (`:4379`), exec
 * retirement (`:4503`), signal death (`:4671`) -- so retiring the slot on those
 * two events covers all of them.
 *
 * Without this the abandoned slot keeps naming the guest op that handed off:
 * the successor image's entire startup would be charged to the guest's
 * `execve`, and that image's first guest syscall would count as a
 * `service-window-reentry`. Post-terminal host work is `carrick-only` -- image
 * setup, which is what that bucket has always meant.
 */
proc:::exec-success
/tracked[pid]/
{
	service_slot[pid, tid] = (uint64_t)0;
}

/*
 * Thread death retires the slot to NEVER-SEEN, not to idle, and here the
 * deallocation that zero performs is the POINT rather than the hazard: it is
 * once per thread, not on a hot path, and a later thread reusing this tid must
 * look like a fresh thread. Retiring to 1 instead would make a reused tid's
 * INHERITED end read as a double close -- a false rejection, which is the worse
 * failure of the two.
 */
proc:::lwp-exit
/tracked[pid]/
{
	service_slot[pid, tid] = (uint64_t)0;
}

/*
 * Host syscalls: count at entry, CPU-ns at return. `probefunc` is identical in
 * both clauses, so the host-call name never has to occupy a thread-local; only
 * the guest slot and the entry `vtimestamp` do.
 */
syscall:::entry
/tracked[pid]/
{
	self->amp_slot = service_slot[pid, tid] > (uint64_t)1 ?
	    service_slot[pid, tid] : (uint64_t)1;
	self->amp_cpu = vtimestamp + (uint64_t)1;
	@host_by_slot[self->amp_slot, probefunc] = sum(1);
	@host_entry_total = sum(1);
}

syscall:::return
/tracked[pid] && self->amp_cpu > (uint64_t)1/
{
	this->cpu = vtimestamp - (self->amp_cpu - (uint64_t)1);
	@host_cpu_by_slot[self->amp_slot, probefunc] = sum(this->cpu);
	@host_cpu_max_by_slot[self->amp_slot, probefunc] = max(this->cpu);
	@host_return_by_call[probefunc] = sum(1);
	@host_cpu_total = sum(this->cpu);
	@host_return_total = sum(1);
	self->amp_cpu = (uint64_t)1;
}

/*
 * Mach traps. Not syscalls, and invisible to every `syscall:::`-only census --
 * the reason two thirds of the large-zone allocation mass has never been joined
 * to a guest operation.
 */
mach_trap:::entry
/tracked[pid]/
{
	self->amp_mach_slot = service_slot[pid, tid] > (uint64_t)1 ?
	    service_slot[pid, tid] : (uint64_t)1;
	self->amp_mach_cpu = vtimestamp + (uint64_t)1;
	@mach_by_slot[self->amp_mach_slot, probefunc] = sum(1);
	@mach_entry_total = sum(1);
}

mach_trap:::return
/tracked[pid] && self->amp_mach_cpu > (uint64_t)1/
{
	this->cpu = vtimestamp - (self->amp_mach_cpu - (uint64_t)1);
	@mach_cpu_by_slot[self->amp_mach_slot, probefunc] = sum(this->cpu);
	@mach_return_by_call[probefunc] = sum(1);
	@mach_cpu_total = sum(this->cpu);
	@mach_return_total = sum(1);
	self->amp_mach_cpu = (uint64_t)1;
}

/*
 * Faults -- the non-syscall kernel half, 20.09% of all CPU, which no
 * syscall-entry join can see. `probename` is the exact fault kind.
 */
vminfo:::as_fault,
vminfo:::zfod,
vminfo:::cow_fault
/tracked[pid]/
{
	@fault_by_slot[service_slot[pid, tid] > (uint64_t)1 ?
	    service_slot[pid, tid] : (uint64_t)1, probename] = sum(1);
	@fault_total[probename] = sum(1);
}

tick-10s
{
	bound_elapsed_s += (uint64_t)10;
}

/*
 * Safety net only -- the census normally ends on the target's own exit. A
 * truncated census is an ERROR, so say so in-band and exit non-zero: the
 * marker, not the exit status, is what the reader gates on.
 */
tick-10s
/bound_elapsed_s >= bound_limit_s/
{
	timed_out = 1;
	printf("AMP1|section=truncated|reason=bound-limit|elapsed_s=%d|bound_limit_s=%d\n",
	    bound_elapsed_s, bound_limit_s);
	exit(1);
}

dtrace:::END
{
	printf("AMP1|section=terminal-calls\n");
	/* Substituted from the lossless native launch receipts. */
	/* CARRICK_AMP1_TERMINALS */

	printf("AMP1|section=totals\n");
	printa("AMP1|metric=guest-syscall-total|count=%@d\n", @guest_total);
	printa("AMP1|metric=host-syscall-entry-total|count=%@d\n",
	    @host_entry_total);
	printa("AMP1|metric=host-syscall-return-total|count=%@d\n",
	    @host_return_total);
	printa("AMP1|metric=host-syscall-cpu-ns|count=%@d\n", @host_cpu_total);
	printa("AMP1|metric=mach-trap-entry-total|count=%@d\n",
	    @mach_entry_total);
	printa("AMP1|metric=mach-trap-return-total|count=%@d\n",
	    @mach_return_total);
	printa("AMP1|metric=mach-trap-cpu-ns|count=%@d\n", @mach_cpu_total);

	printf("AMP1|section=fault-totals\n");
	printa("AMP1|kind=%s|count=%@d\n", @fault_total);

	printf("AMP1|section=guest-syscalls\n");
	printa("AMP1|guest_slot=%u|count=%@d\n", @guest_by_slot);

	printf("AMP1|section=host-syscalls\n");
	printa("AMP1|guest_slot=%u|host=%s|count=%@d\n", @host_by_slot);

	printf("AMP1|section=host-syscall-cpu\n");
	printa("AMP1|guest_slot=%u|host=%s|cpu_ns=%@d\n", @host_cpu_by_slot);
	printa("AMP1|guest_slot=%u|host=%s|max_ns=%@d\n",
	    @host_cpu_max_by_slot);

	printf("AMP1|section=host-syscall-returns\n");
	printa("AMP1|host=%s|count=%@d\n", @host_return_by_call);

	printf("AMP1|section=mach-traps\n");
	printa("AMP1|guest_slot=%u|trap=%s|count=%@d\n", @mach_by_slot);

	printf("AMP1|section=mach-trap-cpu\n");
	printa("AMP1|guest_slot=%u|trap=%s|cpu_ns=%@d\n", @mach_cpu_by_slot);

	printf("AMP1|section=mach-trap-returns\n");
	printa("AMP1|trap=%s|count=%@d\n", @mach_return_by_call);

	printf("AMP1|section=faults\n");
	printa("AMP1|guest_slot=%u|kind=%s|count=%@d\n", @fault_by_slot);

	/*
	 * Expected service-window control flow that is NOT a drop. Reported
	 * because a build with zero inherited ends is a single-threaded one,
	 * which is itself worth knowing when a ledger looks unusually clean.
	 */
	printf("AMP1|section=window-events\n");
	printa("AMP1|window|class=inherited-end|count=%@d\n", @window_inherited_end);

	/*
	 * Program-owned integrity counters. The libdtrace drop counters are not
	 * readable from D (fact 10); the Rust reader enforces those separately
	 * and rejects any nonzero. A MISSING drop section is itself a rejection
	 * -- absent is not zero.
	 */
	printf("AMP1|section=drops\n");
	printa("AMP1|drop|source=dtrace-error|count=%@d\n", @probe_errors);
	printa("AMP1|drop|source=service-window-reentry|count=%@d\n",
	    @drop_service_reentry);
	printa("AMP1|drop|source=service-end-unmatched|count=%@d\n",
	    @drop_service_unmatched);

	/*
	 * `timed_out`, `target_exit_reason` and `bound_limit_s` stay plain
	 * globals: each is written from exactly one clause that fires at most
	 * once, or from `tick-10s`, which DTrace fires on a single CPU once per
	 * interval, so no two firings overlap and the read-modify-write cannot
	 * race. `probe_errors` was the one counter that could -- `dtrace:::ERROR`
	 * fires on any CPU -- and it is an aggregation above, reported in the
	 * drop section only, so there is exactly one spelling of it.
	 */
	printf("AMP1|complete|profile=native-amplification|timed_out=%d|target_exit_reason=%d|bound_limit_s=%d|elapsed_ns=%d\n",
	    timed_out, target_exit_reason, bound_limit_s,
	    timestamp - started);
}
