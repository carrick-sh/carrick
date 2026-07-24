# Loop-merge precision map (Phase 3, Task 1)

**Date:** 2026-07-24
**Status:** scouting complete — STOP ASSESSMENT below governs Task 2
**Scope:** read-only. No code touched. Re-derives both loops fresh, post-Phase-2 line shifts, against `feat/native-lane-seam-phase3` HEAD `3528eff1`.

**Loci:**
- aarch64: `crates/carrick-runtime/src/native_darwin.rs::run_native_dsr_thread_loop_profiled`, lines **2017–2870** (854 lines — matches the plan's "~855 ln").
- x86: `crates/carrick-runtime/src/native_freebsd.rs::run_x86_thread`, lines **9059–10839** (1,781 lines — matches the plan's "~1,750 ln").

## 0. The one fact that reframes everything else

The two functions are **not measuring the same layer of abstraction**, and this is not
incidental — it is documented drift from the campaign's own founding design.
`docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md` (line 99,
156) originally planned a **generic** `ProcessTranslator<L: NativeLane>` /
`ThreadTranslator<L>` living in `carrick-dsr`, with the thread loop itself generic over
`NativeLane`. What actually landed (per that doc's own "Implementation drift" section, and
confirmed by `native_darwin/dsr/mod.rs`'s doc comment: *"moved verbatim to
`carrick_dsr_aarch64::translator`"*) is two **monomorphic** copies: aarch64 got a full
extraction (`carrick-dsr-aarch64::translator`, 2,643 lines, plus `emulate.rs` for
exclusive-monitor emulation) — x86 got **none**. `run_x86_thread` still carries its entire
block-cache / translate / JIT-publish / edge-chain / xstate-policy engine **inline**,
~543 lines of it, with no callable equivalent anywhere in `carrick-dsr-x86`.

Concretely: `run_native_dsr_thread_loop_profiled`'s fetch→translate→cache→gateway-enter
step is **two function calls** (`prepare()`, `enter()` at lines 2092/2104) into an
already-hollowed-out arch crate. `run_x86_thread`'s equivalent step is a **543-line
`HashMap`-based cache lookup, `plan_block_with_reader`/`emit_block_linked` JIT
compilation, chain-edge patch/pending-edge bookkeeping, and xstate `save_required`
policy decision**, all resident in `native_freebsd.rs` itself (lines 9283–9825).

This single fact is why raw line counts (855 vs 1,750) understate how asymmetric the two
loops are, and why several of the task's suggested `GuestIsa` growth methods (decode/
classify, gateway entry/exit symbols, sensitive catalog) do **not** clear the "thin
re-front over an existing function" bar for x86 — the existing function doesn't exist yet.

---

## 1. Structural diff by control-flow region

| # | Region | aarch64 lines | x86 lines | Disposition | Rationale |
|---|---|---|---|---|---|
| 1 | Setup / initial state | 2017–2049 (33) | 9059–9172 (114) | DIVERGED | Same intent (build `Context`/snapshot from `ThreadStart`); x86 needs ~3.5x the state because its JIT bookkeeping (block cache, cflow plans, indirect-cache table, pending edges, fault-entry table, PC history ring) is **loop-resident**; aarch64's equivalent lives inside the already-constructed `ThreadTranslator`. |
| 2 | Loop-top housekeeping / fork-quiesce boundary | 2050–2085 (36) | 9173–9249 (77) | DIVERGED | Same intent (let a racing fork/exec quiesce this thread; check process-exit); aarch64 uses 2 calls (`exec_replacing_other_thread`, `park_for_fork_quiesce`); x86 uses 4+ (`fork_safe_boundary`, `exit.requested()`, `terminal_stop_for_nonowner`, `exit.exec_stop_requested()`) against a structurally different coordinator (`ExecutableEpoch`/generation admission vs a plain barrier). This is arguably a **host** (fork-safety) concern, not an ISA one — out of `GuestIsa`'s remit even if unified later. |
| 3 | Fetch → translate → cache-lookup → JIT-publish → chain | 2086–2109 (24, two calls) | 9283–9825 (~543, fully inline) | **LANE-ONLY (today)** | Not lane-only because the semantics can't be shared — lane-only because aarch64 already got the Phase-1/2017-07-17-planned extraction and x86 never did. Turning this into a `GuestIsa` callback means NEW extraction work for x86 (violates "thin re-front, not new impl"). Single largest source of the loop-size gap. |
| 4 | Gateway admission + entry + x87 FIP normalization | inside `enter()` (opaque) | 9756–9884 (~129) | LANE-ONLY (today) | Same reasoning as #3 — x86's JIT-generation admission (`Entered`/`Refresh`/`Stopped`) and x87 FIP reverse-mapping have no separated aarch64 analog to re-front against because aarch64's equivalent is inside the same opaque `enter()` call. |
| 5 | Exit-class taxonomy (the dispatch itself) | `dsr::ThreadExit`: `{Syscall, Continue, Sensitive, Fault, Kick, Unsupported}` — 6 variants, **no `Indirect`** (2130–2309, 180 ln) | `X86ExitStatus`: `{Kicked, Signal, Syscall, Indirect, Sensitive}` + unknown — 5 variants, **no `Continue`/`Unsupported`** (9888–10798, 911 ln) | **DIVERGED at the taxonomy level** | The two enums are not the same set. Indirect-branch resolution is fully internal to aarch64's `ProcessTranslator` (never becomes a `ThreadExit` variant); x86 surfaces it to the outer loop because its cache/chain engine is inline (see #3). A generic loop needs a canonical superset neither lane's code emits today — itself new speculative surface, not a re-front. |
| 5a | ↳ Sensitive dispatch | 2133–2244 (112, fully inline; register-only aarch64 catalog: `Exclusive`/`ReadTpidr`/`WriteTpidr`/`ReadCounter`/`ReadCtr`/`ReadDczid`/`DcZva`/`DcCvau`/`IcIvau`) | 10576–10793 (218; split — `XstateSave`/`XstateRestore`/`FxState`\|`LegacyX87` need `&memory` and call out; everything else calls out to `service_sensitive`, register-only) | DIVERGED / DANGER ZONE | See §3. |
| 5b | ↳ Fault dispatch | 2245–2290 (46) → **one call** `lower_dsr_fault`, `Result`-returning, propagates via `?` (aborts the whole loop with `RuntimeError` on internal failure) | 9906–10038 (133) → inline SIGBUS/ACCERR reclassification + 3 probe calls, **then one call** `deliver_synchronous_x86_fault`, enum-returning (`RetryAt`/`Fatal`), never aborts | DANGER ZONE | See §3. |
| 5c | ↳ Kick/Kicked | 2291–2303 (13) → **always** means "deliver a pending signal now"; one call, unconditional | 9889–9905 (17) → means "coordinator-issued interrupt"; branches on `exit.requested()` / `explains_kick(admitted)`; a bare kick with neither explanation is a hard error ("received a kick without an exit request") | DIVERGED (possible functional asymmetry, not confirmed) | Async pending-signal delivery for x86 happens through `run_pending_signals[_at]` (line 6016), called from inside `service_syscall`'s blocking-wait path (a bare in-JIT kick is NOT one of its call sites, per grep of all 9 call sites). This suggests x86 never expects an async signal to interrupt actively-running JIT code the way aarch64's gateway can be kicked mid-block — **flagged as an open question, not verified further** (out of this task's read-only budget). |
| 5d | ↳ Indirect-branch resolution | none (internal to `ProcessTranslator`) | 10441–10575 (135) | **LANE-ONLY** | Structural, not a naming difference: aarch64 resolves indirect branches inside the arch-crate translator and the loop never sees it. |
| 5e | ↳ Syscall arm outer wrapper | 2310–2868 (~558; builds `SyscallRequest` inline, calls `dispatch_native_syscall`, then a ~300-line inline `DispatchOutcome` match: `Returned/Errno/SigReturn/Exit/ThreadExit/CloneThread/Fork/Execve/MapHostAlias/SignalThread/SignalDeath/other`) | 10039–10440 (~400; **one call** `service_syscall` → internally resolves `DispatchOutcome` → reduces to an 8-variant `Step` enum; outer loop matches only `Step`) | **CONVERGENT-DIVERGED — the best merge candidate** | x86 *already* has the "call out, get a small enum back" shape the merge wants (`Step::{Continue, Exit, ThreadEnd, RetiredForExec, Fault, BecameForkChild, SignalDeath, Execve}`); aarch64's inline `DispatchOutcome` match could be reshaped to produce the same small enum with *modest, non-speculative* rework (moving already-written match arms into a helper), not new capability. See STOP assessment. |
| 6 | Fault-lowering support functions (outside the loop body) | `deliver_dsr_pending_signal`/`complete_dsr_syscall`/`complete_dsr_sigreturn`/`lower_dsr_fault`/`lower_dsr_fault_address`/`native_die_by_signal`, 2872–3131 (~260) | `deliver_synchronous_x86_fault`/`deliver_x86_instruction_fetch_error`/`synchronous_fault_termination`/`synchronous_fault_final_signum` + `NativeX86Trap`/`SigframeEngine` adapters, ~5506–6100 | Mixed: core is **already shared** (see §3), classification wrapper is lane-specific | The signal-delivery *decision* core (`crate::vcpu_loop::{deliver_pending_signal, inject_fault_signal}`, generic over `carrick_hal::SyscallTrap`) is **pre-existing shared infrastructure**, used unmodified today by both `NativeSignalTrap` (aarch64) and `NativeX86Trap` (x86) — zero incremental campaign work here, already works. |
| 7 | Fork/exec continuation | `handle_native_fork` (one call, defined outside the loop) + Execve inline 2596–2786 (~190) | `BecameForkChild` inline 10059–10166 (~108) + `Execve` inline 10200–10434 (~235) | DIVERGED | Same essential steps (rebuild JIT/cache state, rekey thread/signal identity, load new image, publish identity, notify vfork) at different granularities of "already extracted." x86's `Execve` arm is bigger partly because it must explicitly clear 5 separate cache/table structures aarch64's `translator.reset_for_exec()` hides. |

**Region totals:** 1 SHARED-as-is (region 6's core), 1 CONVERGENT-DIVERGED (5e, the one genuine merge opportunity), 5 DIVERGED (1, 2, 5, 5a, 5c, 7 — treating 5's taxonomy as its own line), 2 LANE-ONLY (3/4 combined as one finding, 5d) — **counting the 12 numbered rows: 1 shared / 8 diverged / 3 lane-only.**

---

## 2. `GuestIsa` growth surface — what actually clears "thin re-front"

Cross-checked against `carrick-dsr-aarch64/src/{translator,gateway,decode,types,snapshot,emulate}.rs`
and `carrick-dsr-x86/src/{block,gateway,decode,cflow}.rs`.

### Clears the bar (both lanes already have the exact data, only naming differs)

| Proposed method | aarch64 proof | x86 proof |
|---|---|---|
| `fn syscall_request(ctx: &Context) -> (u64, [u64; 6], u64 /* sp */)` | `snapshot.x[8]`, `snapshot.x[0..6]`, `snapshot.sp` — used inline at native_darwin.rs:2311–2322 | `X8664SyscallFrame{rax,rdi,rsi,rdx,r10,r8,r9}` (native_freebsd.rs:10862–10870) + `snapshot.gpr[reg::RSP]` |
| `fn pc(ctx) -> u64` / `fn set_pc(ctx, u64)` | `snapshot.pc` (`NativeUcontextSnapshot`, carrick-dsr-aarch64/src/snapshot.rs:17) | `snapshot.rip` (`X86UcontextSnapshot`, carrick-dsr-x86/src/gateway.rs) |
| `fn apply_syscall_return(ctx: &mut Context, value: i64, resume_pc: u64)` | register write inside `complete_dsr_syscall` (x[0]=value, pc=resume) | `snapshot.gpr[reg::RAX] = value; snapshot.rip = resume` (scattered call sites, e.g. 10212–10213) |

These three are legitimately sized-to-consumption: both lanes hold exactly this data in a
`repr(C)` struct today; the trait would just name the fields. Estimated new code: a few
lines of glue per lane, no new capability.

### Does NOT clear the bar (proposed in the task brief, found to require new implementation)

| Proposed surface | Why it fails the "thin re-front" test |
|---|---|
| decode/classify + instruction length | aarch64 `classify(word: u32, pc: GuestVa) -> Result<InstAction, DsrError>` (carrick-dsr-aarch64/src/decode.rs:909) operates on a **fixed 4-byte** instruction (length is a compile-time constant, never returned). x86 `classify(bytes: &[u8], va: u64) -> Result<X86Classified, X86DecodeError>` (carrick-dsr-x86/src/decode.rs:240) operates on a **variable-length byte stream** and returns `len: u8` because it must. `InstAction` (9 variants incl. aarch64-only exclusive-fusion machinery) and `X86InstClass` (4 variants, one of which — `Sensitive` — nests a 12-variant x86-only sub-taxonomy) do not correspond. Unifying requires **designing a new enum**, not re-fronting an existing one. |
| gateway entry/exit symbol surface | aarch64 exposes 6 named exit addresses (`syscall_exit_address`, `direct_exit_address`, `indirect_exit_address`, `sensitive_exit_address`, `unsupported_exit_address`, `signal_exit_address` — carrick-dsr-aarch64/src/gateway.rs:246–268), all of which are consumed **internally** by the translator and never surface as `ThreadExit` variants (see region 5's `direct`/`indirect` absence). x86 exposes `exit_stub_addresses() -> (u64,u64,u64)` + `signal_stub_addr()`/`kick_stub_addr()` (carrick-dsr-x86/src/gateway.rs:1325–1337), which **are** the addresses `X86ExitStatus` decodes. Different counts, different consumers. Unifying means either exposing aarch64's currently-hidden direct/indirect resolution (churn to a proven subsystem) or hiding x86's currently-visible one (the real prerequisite, see §4). |
| sensitive catalog (as one method) | aarch64's 9-variant catalog is 100% register-only (no guest-memory access ever needed). x86's catalog has 4 sub-kinds (`XstateSave`/`XstateRestore`/`FxState`/`LegacyX87`) that need `&NativeIdentityMemory`, plus `Cpuid`/`ProtectionKey`/`ExtendedControl`/`SegmentBase`/`SegmentPrefixed` with no aarch64 analog at all. Only the "read a virtualized time counter" sub-piece is close (see below); the rest is architecturally lane-only (§3). |

### Partial credit: the counter sub-piece

`fn read_virtual_counter(host: &Host) -> Option<u64>` — aarch64 maps to
`dsr::fallback_counter_ticks()` (macOS-gated, can return `None`/error on non-macOS, used at
native_darwin.rs:2184–2202); x86 maps to `core::arch::x86_64::_rdtsc()`/`__rdtscp()`
(unconditional hardware instruction, no failure mode, native_freebsd.rs:14321–14336). The
shapes are close enough that this ONE method could be a genuine thin re-front — but it is
optional, tiny, and not worth growing the trait for in isolation.

**Net for §2: 3 accessor methods clear the bar. Everything else the task brief suggested
(decode/classify, gateway symbols, sensitive catalog) does not, today, for x86.**

---

## 3. Danger zones

### Fault lowering — `lower_dsr_fault` vs `deliver_synchronous_x86_fault`/`deliver_x86_instruction_fetch_error`

Two independent, load-bearing divergences, not implementation-style differences:

1. **Error-shape divergence.** `lower_dsr_fault` (native_darwin.rs:2956) returns
   `Result<NativeUcontextSnapshot, RuntimeError>` and is driven with `?` — an internal
   failure **aborts the whole thread loop**. `deliver_synchronous_x86_fault`
   (native_freebsd.rs:5825) returns `SynchronousFaultDelivery::{RetryAt(u64), Fatal(i32)}`
   — a plain enum, **never aborts**; the caller always gets a resumable outcome. Collapsing
   these into one trait-callback signature means either aarch64 loses its fail-fast abort
   or x86 gains an abort path neither lane's tests have ever exercised.

2. **Process-topology divergence (confirmed, not hypothesized).** aarch64's *top-level*
   guest process is **already a forked OS process** relative to the CLI: `run_static_elf`
   (native_darwin.rs:1545) calls `libc::fork()` unconditionally at line 1553 before running
   any guest code, and the CLI-side parent `waitpid`s and converts `WIFSIGNALED` to
   `128 + signum` itself (line 1600–1606). This is why `native_die_by_signal`
   (native_darwin.rs:3119) unconditionally calls `forked_child_die_by_signal` regardless of
   whether a **guest-initiated** `fork()` ever happened — there's always a real parent
   `wait4`-ing on it. x86's top-level guest runs **inline in the CLI process itself** (no
   fork at all — confirmed at the `run_x86_thread` call site, native_freebsd.rs:8526); its
   `Step::SignalDeath` handling explicitly branches on `forked` (whether a **guest**
   `fork()` happened) precisely because at the top level there is no real parent process to
   `wait4` a host signal — the exit code must instead flow back through `Step`/`RunResult`
   to the same process's own `main()`. The doc comment at `Step::SignalDeath`
   (native_freebsd.rs:7130–7136) says this explicitly: *"The run loop decides which, since
   only it knows the `forked` flag."*

**Ruling: fault lowering MUST stay lane-specific, with the shared loop (if any) calling
out to it as an opaque per-lane function — not a single trait callback with one shared
signature.** The two lanes disagree about (a) whether internal failure aborts the loop and
(b) where the forked-vs-top-level decision is made, and (b) traces back to a genuine,
unrelated-to-this-campaign difference in how each lane spawns its top-level guest process.
Forcing one signature here risks exactly the harm the task brief names: corrupted signal
delivery (wrong process dies, or dies the wrong way).

### xstate — x86 XSAVE/XRSTOR service + residency policy vs aarch64 FP snapshot

- **aarch64 has no software xstate policy.** The complete V0–V31 register file (`v: [[u8;
  16]; 32]`, 512 bytes, `carrick-dsr-aarch64/src/snapshot.rs:19`) is unconditionally part of
  the `repr(C)` `NativeUcontextSnapshot` and is saved/restored by the **gateway assembly**
  on every single transition, with zero Rust-visible branching or decision. There is
  nothing to plug a trait method into — not a no-op default, an **absent concept**.
- **x86's xstate handling is a hard-won, extremely delicate, already-documented-as-risky
  subsystem.** `docs/superpowers/specs/2026-07-21-native-x86-xstate-transfer-strategy.md`
  (status: "Risk: high — gateway assembly, dynamically patched control flow, signal exits,
  and Linux task snapshots share the contract") records multiple real regressions from
  touching this exact policy: a target-only chain-gating experiment that silently corrupted
  a K-register classification and broke the Kaniko/apt-key/GnuTLS workload before being
  reverted to the conservative default; the gateway accounted for **61.2% of profiled
  runtime samples** in a clean kernel-only profile before Phase 2's neutral-domains policy
  brought it to 15.1%. The `save_required` decision (native_freebsd.rs:9764–9765,
  `NativeX86XstatePolicy::save_required`) is woven directly into the JIT edge-chaining data
  structures established as LANE-ONLY in region 3 (`CachedBlock.uses_fpu`, per-edge barrier
  checks) — it is not a call-time decision a trait callback could make in isolation without
  also carrying that whole cache/chain engine along.

**Ruling: xstate CANNOT be a trait callback at all — there is nothing for aarch64 to
implement, and the x86 side is independently documented as too load-bearing/fragile to
extract as a side effect of an unrelated loop-merge task.** Any `GuestIsa` method here
would be an x86-only method with an unreachable aarch64 default — exactly the speculative
trait surface the plan prohibits. It stays 100% lane-only, and it can only become cleanly
separable from the outer loop once region 3 (the cache/chain engine) is properly extracted
to `carrick-dsr-x86` on its own, independently-gated terms — not bundled into this task.

---

## 4. STOP ASSESSMENT

**Numbers.** Combined loop size: 2,635 lines (854 + 1,781).

- **Already shared, zero incremental work** (region 6's core: `vcpu_loop::{deliver_pending_signal, inject_fault_signal}` generic over pre-existing `carrick_hal::SyscallTrap`, used unmodified by both lanes today): this is why both loops are as short as they already are. Not loop code, but the reason a large potential region needs no campaign work at all.
- **Legitimately thin-re-frontable NEW surface**: 3 tiny context-accessor methods (§2), maybe a 4th (counter read). Call it 20–40 lines of new glue total. Genuinely low-risk.
- **The rest of the size gap — ~543 (region 3) + 129 (region 4) + 135 (region 5d) ≈ 807 lines** of x86-only inline logic has **no corresponding shared shape to re-front against today.** Unifying it requires first doing to x86 what was already done to aarch64 in an earlier phase (extracting the block-cache/translate/JIT-publish/chain engine into `carrick-dsr-x86`) — unscoped for Task 2, large, and itself high-risk (it's the campaign's own documented 61%-of-runtime hot path).
- **Fault lowering and xstate are ruled 100% lane-only** in §3 — roughly 300–450 more lines on each side that will never become shared code, by explicit, evidenced design, not by omission.
- **Sensitive dispatch (5a) and fork/exec continuation (7) are DIVERGED** — callable-out at best, not shared bodies.
- **The one genuine convergence point is region 5e** (syscall-arm outer wrapper): x86 already reduces to a small `Step`-shaped enum after calling out; aarch64 could be reshaped to match with modest, non-speculative rework (not new capability — moving already-written match arms into a helper).

Adding it up: a **realistically mergeable shared skeleton** — loop-top scaffolding, a
generic exit-class match whose arms are ALL opaque lane callbacks, and the
trap-limit/outcome bookkeeping at the tail — is on the order of **100–180 lines**, roughly
**10% of the combined 2,635 lines**, and every one of those lines would be wrapping a call
whose *body* remains 100% lane-authored. The other ~90% is either (a) already shared with
zero campaign work, (b) ruled lane-only by real architectural divergence (xstate, exclusive
monitor, process-topology-dependent fault handling), or (c) blocked on an unscoped
prerequisite (x86's missing translator extraction).

**Recommendation: SKIP the cross-ISA generic loop merge as Task 2 is currently scoped.**

A THIN-SKELETON merge is technically possible, but its shared skeleton would be so thin
(~10%, mostly boilerplate around opaque per-lane callbacks) that the indirection cost — a
new generic module, a grown trait, both call sites now routed through const-generic/
associated-type ceremony — is not clearly repaid. Critically, Task 2's own stated method
("thin re-front over existing functions, not new impl") **does not hold** for the single
region that accounts for most of the apparent size difference (region 3): the aarch64 side
of that region already exists as a re-frontable function; the x86 side does not exist as a
function at all.

**What I'd redirect Task 2's effort to instead:** extract `native_freebsd.rs`'s inline
cache/translate/chain/xstate-policy machinery into `carrick-dsr-x86`, mirroring the
already-proven-safe aarch64 extraction that produced `carrick-dsr-aarch64::translator`.
This is lower-risk (a pure move-across-a-crate-boundary, the exact pattern Phase 1/2
already validated once), delivers the campaign's own stated goal directly
(`native_freebsd.rs`'s 16.6K line count actually shrinks — a real structural win
independent of any cross-ISA unification), and is the genuine prerequisite that would let
a *future* cross-ISA loop merge be a true thin re-front instead of new implementation. Only
after that lands should the controller re-scout whether a generic loop is worth it — at
that point region 3's disposition might legitimately flip from LANE-ONLY to SHARED-shape.

**If the controller wants something out of Task 2 regardless:** the only safe, sized,
genuinely-thin pieces are (a) the 3-method context-accessor trio in §2, and (b) reshaping
aarch64's inline `DispatchOutcome` match into an x86-`Step`-shaped return (region 5e) —
both are pure readability/uniformity wins, neither touches fault lowering or xstate,
neither requires new capability.

**Unaffected by this verdict:** Tasks 3 (exec-capsule + prepared_image adoption on FreeBSD)
and 4 (cross-process futex host seam) do not depend on the loop merge and can proceed
independently on the plan's existing schedule.
