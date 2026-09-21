# Raw AArch64 clock_gettime without a host exit

Status: implementation design, not executed proof. Reviewed against the current
mailbox/vector and clock code after `567e88955`. No runtime source changes.

## Scope and expected benefit

Intercept AArch64 syscall 113 at EL1, redirect to a dedicated immutable EL0
clock/copyout stub, and complete its marker SVC at EL1. Eligible calls execute
two guest exception round trips but no HVC, host dispatch, mailbox request, or
HVF exit. This removes the roughly three million raw-clock exits reported for
inotify09; it does not establish that the remaining workload meets its timing
contract. Measure that independently on the final signed artifact.

The first implementation should serve CLOCK_MONOTONIC (1) only, provided the
recorded inotify09 clock-id census confirms this is the hot ID. REALTIME (0)
can use the same stub with the per-MM vvar offset once coherence tests cover
clock adjustment. CLOCK_MONOTONIC_RAW (4) is eligible only under the same
already-supported counter model. Leave BOOTTIME, coarse, CPU, negative dynamic
and unknown clocks on ordinary dispatch until their exact clock model is
qualified. A broad `clock_id <= 7` test is incorrect.

## Existing seams

- `crates/carrick-mem/src/memory.rs:3550`: vector shim generation;
  `el1_vectors_bytes_shim_inner` dispatches identity calls, then fstat's
  argument-preserving gate. Its tail is bounded by `MAILBOX_HANDLER_OFFSET`
  (0xA00); add an explicit clock-handler allocation after the mailbox code,
  with overlap assertions, rather than squeezing it into the existing gap.
- `memory.rs:3786`: mailbox vector assembly and normal capture/restore.
  Both mailbox and legacy paths need consistent dispatch offsets; an added
  syscall comparison changes the current computed mailbox-entry address.
- `crates/carrick-aarch64/src/mailbox.rs:9`: the 256-byte per-vCPU slot,
  generation/sequence metadata, state machine, and cross-crate offset assertions.
- `crates/carrick-runtime/tools/vdso_fns.s`: counter conversion reference;
  `crates/carrick-mem/src/vdso.rs:21`: vvar/vDSO addresses and offsets.
- `crates/carrick-kernel/src/dispatch/seccomp_observer.rs:416`:
  `requires_syscall_traps`; `container_policy.rs:320`: policy fast-path
  visibility currently names only identity and fd-ceiling calls.
- `crates/carrick-runtime/src/vcpu_loop/fd_ceiling.rs:12`: existing precedent
  for closing a fast path when an observer, interceptor or budget needs host
  dispatch. The clock gate must additionally encode clock-domain eligibility.
- `crates/carrick-kernel/src/dispatch/proc.rs:959`: guest seccomp closes the
  current identity gate. New clock admission must also close before a filter
  becomes effective, including TSYNC and shared-MM cases.
- `crates/carrick-aarch64/src/engine.rs:2473`: kicks inside EL1 vectors are
  currently deferred; a private EL0 stub must become a recognized in-flight
  syscall boundary too.
- `crates/carrick-kernel/src/dispatch/time.rs:1332`: existing EL1 synthetic
  system-time accounting; `runtime/src/vcpu_loop/lifecycle.rs:884` handles
  counter reset/folding across process lifecycle.

## Mailbox layout and exact register contract

Keep the slot size and arena geometry unchanged. Bump the protocol version and
replace part of `reserved[72]` (currently offsets 184..255) with:

| Offset | Field |
| --- | --- |
| 184 | saved x9 |
| 192 | saved x10 |
| 200 | saved x11 |
| 208 | saved x12 |
| 216..255 | remain reserved for this change |

The clock stub uses only x0..x5 and x9..x12. Rewrite the conversion's final
quotient into x3 instead of the existing vDSO's x7; do not touch x6, x7,
x13..x15, x18..x30, SP_EL0, TLS or SIMD state. Existing fields retain x0..x5,
x8, x16/x17, original ELR_EL1, SPSR_EL1 and ESR_EL1. x16/x17 are EL1-only
scratch and are restored before every ERET. Preserve all argument registers
on fallback; unlike getpid, clock_gettime has meaningful x0 and x1.

Add `MailboxState::ClockActive = 3`, with legal transitions Idle -> ClockActive
-> Idle and a separately defined ClockActive -> RequestReady slow fallback.
Do not let generic mailbox validation interpret ClockActive as RequestReady.
Initialize/reset all new fields whenever a slot generation is assigned.

EL1 admission sequence:

1. Preserve x16 and prove ESR.EC is SVC64, as today.
2. Recognize completion/fault for an already-active clock operation before
   ordinary syscall-number dispatch. Never recognize a marker by x8 alone.
3. For nr113, acquire-load a kernel-only per-MM clock gate. Require an eligible
   ID, Idle mailbox, valid owned slot generation and installed stub/vvar.
4. Save the original frame and x9..x12. Increment the operation sequence and
   publish ClockActive only after the saved frame is complete.
5. Set ELR_EL1 to the dedicated clock stub entry. Preserve original user SPSR
   for completion. ERET enters EL0 with x0=clock ID and x1=user timespec pointer.

EL0 stub sequence (no stack or function call):

1. Read CNTVCT_EL0 and CNTFRQ_EL0 with the same ordered counter-read convention
   as the qualified clock path. An ISB before the counter read is appropriate
   for a syscall boundary; qualify this against the current vDSO output.
2. Divide counter into seconds/remainder, convert remainder with integer
   `rem * 1000000000 / freq`, form nanoseconds, and optionally add the current
   MM's realtime vvar word. Use integer operations only.
3. Divide into tv_sec/tv_nsec, then two normal EL0 STRs to [x1] and [x1,#8].
4. Execute a dedicated marker SVC (proposed immediate 0xc10c); no RET.

EL1 completion authenticates all of: ClockActive, matching current slot
generation, ESR SVC immediate, and ELR_EL1 equal to the one marker instruction's
address plus four. Set result zero, account once, restore the saved frame and
all clobbered registers except x0, clear ClockActive, and ERET to the original
post-SVC PC. A guest-forged marker with no active operation must go through
ordinary dispatch, never gain access to saved mailbox contents.

## Faults, interruptions and lifecycle

The redirect avoids PAN and privileged-copy permission bypass: stores execute
with real EL0 access permissions. It does not make all guest faults EFAULT.

- An EL0 stage-1 data fault at exactly one of the two stub store PCs is a
  candidate syscall copyout fault. Genuine unmapped/PROT_NONE/read-only output
  must become -EFAULT, preserving whatever partial copy Linux permits.
- COW, deferred backing and other recoverable write faults must first use
  the existing host memory-fault service and resume the stub. Treating every
  store abort as -EFAULT would break valid first writes and forked buffers.
  The conservative first implementation can restore the original SVC frame
  and forward nr113 to normal host dispatch on every store fault. That path
  already authenticates memory and decides success/EFAULT, and it runs only
  on the exceptional path. Direct EL1 EFAULT needs an independently sound
  distinction between a semantic denial and a recoverable backing fault.
- Preserve the original SVC ESR/ELR/SPSR before the nested exception overwrites
  them. Error forwarding must not expose the stub's abort as an application
  SIGSEGV or the marker SVC as a second guest syscall.
- Instruction faults or vvar-read faults inside the dedicated stub are not
  user-buffer EFAULT. Restore the original syscall and use host dispatch;
  surface corrupted runtime mapping authority through the existing fatal
  diagnostic path where appropriate.
- An external kick while ClockActive must not produce a signal frame whose
  PC is in the stub, nor permit scheduler migration/reuse of its mailbox.
  Normalize to the saved original syscall at the host boundary or finish the
  bounded stub before exposing the pending signal/control request. Finish
  must not silently lose that request: the completion path must arrange a
  host boundary if the kick was deferred. Extending the existing vector-PC
  `continue` alone is insufficient for this no-HVC completion path.
- Slot retirement, fork/exec projection and detach must either complete or
  normalize ClockActive before recycling the exact vCPU slot/generation.
  No guest state snapshot may silently contain private-stub scratch registers.

Place the stub in a dedicated runtime-owned EL0 RX mapping rather than an
ordinary exported vDSO function that ends in RET. Its backing and address must
remain protected against guest MAP_FIXED, munmap and writable mprotect while
admission is enabled. If that protection cannot be established, do not enable
the path. Bounds checks alone do not authenticate executable bytes.

## Gate and accounting

Use a separate kernel-only clock gate, not the identity flag. Initialize it to
disabled; publish enabled only after the exact MM's stub, vvar, slot and policy
are ready. Re-evaluate at initial boot, fork/shared-MM admission, exec and
container attachment. Per-MM sharing requires the restrictive union of all
tasks sharing that MM. A disabled gate cannot be accidentally reopened by a
later sibling bootstrap.

Disable for any guest seccomp, a syscall interceptor, an observer requesting
full fast-path visibility, a policy denying nr113, any resource budget, and
frozen/scaled/deterministic clocks. Honor no-fastpaths/clock-syscalls diagnostic
modes: a request to see raw clock traps must not be bypassed by a new EL1 path.
Ordinary system clocks can enable monotonic. Offset domains need clock-specific
eligibility and REALTIME must consume the current vvar delta; start conservatively
with system-only rather than silently ignoring a domain's semantics.

Count successful/error EL1 completions exactly once; do not count an operation
forwarded to ordinary dispatch, which already charges system CPU. Reuse the
existing nominal EL1 syscall system-time convention and folding hooks, but do
not introduce an independent clock ledger. The existing shared counter uses
non-atomic read/add/write and can lose concurrent increments. For a new exact
accounting contract, use a qualified atomic increment (feature-gated LSE on the
actual AArch64 host lane) or a separate designed per-owner ledger. Do not claim
exact concurrent counts from the existing non-atomic mechanism. Per-thread
CPU-clock accounting also needs explicit qualification; process totals alone
do not prove CLOCK_THREAD_CPUTIME_ID.

## Red-first contract and acceptance

Add `kernel.time.raw-clock-fastpath` at scales 1/8/32/128:

1. VM-free vector/mailbox tests execute or decode the generated control flow:
   idle+eligible admits; disabled gates/unsupported IDs preserve all arguments
   and forward; forged marker cannot complete; valid marker restores every
   saved GPR/SPSR/PC; store fault forwards the original SVC; active slot cannot
   be reused. Static opcode existence by itself is not semantic proof.
2. A deterministic signed raw-syscall probe warms a writable timespec page,
   brackets N raw CLOCK_MONOTONIC calls, and emits monotonic/valid-timespec,
   register-preservation and syscall-return assertions. Bind a non-invasive
   carrier work counter: zero clock-service host exits/dispatches in the
   bracket, N EL1 completions, no incomplete/dropped measurement. Before
   implementation, N raw calls must show N host-service entries. A Required
   observer cannot collect the fast-path metric because it closes the gate.
3. Separate signed cases cover null, read-only, PROT_NONE, cross-page and
   COW/pristine output; seccomp denial; required observer/interceptor;
   finite budget; frozen/scaled/deterministic domains; external signal/control
   at entry, before/after each store and before completion; fork/exec and slot
   generation reuse; system-time contribution. Exceptional cases may exit.
4. Native ARM64 Docker supplies output authority. Run uninstrumented inotify09
   on the integrated signed artifact after semantic and structural gates.
   Removing three million exits is a mechanism result, not workload closure.

The smallest safe landing therefore includes the gate, mailbox state machine,
EL0 stub, exception normalization and kick/retirement handling. A bare redirect
plus marker handler omits necessary lifecycle semantics and is not acceptable.
