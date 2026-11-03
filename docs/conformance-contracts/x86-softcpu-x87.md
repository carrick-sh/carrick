# x87 and CMPXCHG16B execution prerequisite (#1472)

This slice extends `x86.softcpu.level0`. The authority is Intel SDM volume 1,
chapter 8 (extended precision, stack, control/status, deferred exceptions),
volume 2 (x87 instructions and CMPXCHG8B/CMPXCHG16B), and native x86 execution.
No emulator or kernel implementation source is used.

The existing checked FP leaf executes one x87 instruction between nonwaiting
FXRSTOR/FXSAVE instructions. Guest exceptions remain in the guest image until
the next waiting instruction; CR0.EM/TS produces #NM. Control and arithmetic
status, eight 80-bit stack registers, tags, integer conversions, comparisons,
conditional moves and transcendental instructions retain native precision.
Host FP state is restored before Rust resumes. FIP/FDP/FOP use guest addresses
and instruction bytes, never native leaf or bounce-buffer addresses. Legacy
FLDENV/FRSTOR also check pending #MF now that arithmetic can create it.

Memory operands are at most ten bytes. The helper authenticates at most two
page spans before executing, retains store destinations, and publishes neither
pops nor bytes on a page fault. Leaves are cached by normalized instruction;
the allocation test requires exactly one leaf at repetition scales 1, 4, 16.
No per-instruction executable allocation, polling or retry is introduced.
The existing larger REP memory budgets remain unchanged.

CMPXCHG16B uses the existing translated native memory path. Sixteen-byte
alignment is mandatory, even without LOCK, so a valid operand never crosses
a page and never takes the non-atomic bounce path. LOCK reaches the actual
backing word. Failed comparisons still require write permission. Hosts without
CX16 are refused before native execution rather than taking a host SIGILL.

The red-first `cmpxchg16b_success_failure_and_alignment` and
`x87_extended_precision_load_arithmetic_store` tests failed at the production
`SoftCpu::step_block` entry point on the admitted main: both stopped at #UD.
The latter requires the exact extended-precision value 2^63+1 and a store
crossing a page. The native differential covers register and memory forms,
all three defined precision controls, four rounding modes, full and partially populated stacks, and masked/unmasked
exceptions, comparing control/status, all 80-bit registers, output bytes,
AX and arithmetic flags. Fault tests cover deferred #MF, nonwaiting status,
FNCLEX, FNINIT, #NM, and fault-atomic page-crossing stores. The integer round-trip binding drives FLDCW/FNSTCW, FILD, FXAM, FNSTSW
and FISTP through `SoftCpu::step_block` in all four rounding modes. It
requires exact signed 64-bit extrema and values beyond binary64 precision.
CMPXCHG16B also preserves every arithmetic flag other than ZF. The concurrent
CMPXCHG16B test competes with native LOCK CMPXCHG16B on the same backing word.
The native peer runs until soft completion. The soft loop makes 2,000 bounded
attempts and records failed comparisons before DEC overwrites ZF; the final
word must equal native updates plus successful soft updates. Requiring a
fixed number of successes against an unthrottled peer would instead test
scheduler fairness: the peer can legitimately invalidate every comparison.
A failed comparison after the first soft attempt is mandatory: it requires
a native update after the soft CPU has already sampled the word, rather than
merely observing an initially stale zero.

The installed guest CPUID view gates x87 data/control instructions (FPU),
CMPXCHG16B (CX16), and FISTTP (both FPU and SSE3) before operand translation.
The Level0 view retains its negative witnesses. Positive fixtures install
only the additional advertised bits they exercise; replacing the view revokes
execution of the same bytes. The new gate witness failed with exit 101 before
the planner gate: an unadvertised FLD executed instead of raising #UD.

## CPUID switch remains blocked

The admitted base still rejects FMA/F16C, BMI, AES/PCLMUL and other instructions
promised by `GuestCpuidView`; `avx::supported` admits only AVX/AVX2 features and
the legacy decoder has a narrower allowlist. Accordingly this prerequisite
slice leaves the default view unchanged. It does not claim shared-view adoption
or live leaf-by-leaf KVM/soft equality. Those require the other #1439/#1469
instruction slices, host qualification, and matching configured optional-feature
populations. Advertising v3 now would violate execute-before-advertise.

Native differentials and the soft CPU tests are VM-free execution evidence.
They do not replace signed HVF, Docker workload ratios, the KVM merge-queue
gate, or a full Linux-userland integration verdict. Those remain unrun here.

## Round-two native environment witnesses

`x87_environment_load_save_matches_native_tags_and_exception_summary` compares
14/28-byte FLDENV/FNSTENV and 94/108-byte FRSTOR/FNSAVE against native execution,
including nonzero TOP, mixed physical tags, and inconsistent input summary bits.
The native oracle exposed missing ES/B recomputation on restore and missing
live ES/B clearing after FNSTENV masks exceptions. The stored image retains the
pre-mask summary. `x87_fxrstor_fxsave_matches_native_with_pending_exceptions`
independently covers FXRSTOR/FXSAVE, all eight extended registers, and pending
#MF before an operand page fault or FWAIT, while FNSTCW remains nonwaiting.
Both witnesses failed on the inherited implementation before the fixes.

Shared-view adoption is a separate follow-up gated on #1487 and an advertised
instruction audit. This slice does not change `GuestCpuidView` or CPUID output.

The native CMPXCHG16B peer has scoped thread custody and a bounded completion
notification. An assertion cannot release its backing allocation before the
peer exits. The two actors start through a handshake and validate the combined
2,002,000 updates; this is a concurrency stress witness, not a deterministic
claim that their individual accesses overlap on every scheduler.
