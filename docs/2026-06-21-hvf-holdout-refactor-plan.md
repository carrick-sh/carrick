# HVF factoring-holdout refactor — execution plan

Roadmap for the deferred P1 durability seams from
[`2026-06-20-structural-leverage-audit.md`](2026-06-20-structural-leverage-audit.md)
(§6 "Deferred"). These fold the macOS/HVF backend onto the shared abstractions
the x86 lane already uses, so the aarch64/host work is single-sourced and a new
VMM/arch/host is cheap. The HVF rig now makes them runtime-verifiable.

Priorities, in order: **(1) correctness, (2) robustness, (3) durability,
(4) leverage.** Risk is acceptable if the result maps to these — but correctness
leads, so each fold's claimed gaps are verified against the code (and a
reproducer where one exists) BEFORE behavior changes.

## How this plan was built (and its trust level)

A 5-agent mapping workflow produced per-seam specs + a dependency-ordered plan.
The agents are **reliable on the big picture** (which seams, the shared
abstractions, the dependency order) but **UNRELIABLE on specifics** — verifying
against the code already falsified several spec claims (below). Treat each spec's
bug claims and exact type signatures as hypotheses to confirm, not gospel. This
mirrors the maskfork lesson: a plausible diagnosis is the easiest place to be
wrong.

## Execution order (dependency-ordered, correctness-first)

`F8 → F4 → F5 → F7 → F3`. Hard constraint: **F3 (fold HVF onto the one shared
`run_threaded_loop`) is LAST** because it consumes the seams F4/F5/F8 introduce.
F7 (aarch64 engine) is orthogonal to the signal/fork/futex stack and is slotted
before F3 so the trap shell is centralized when F3 wires it in.

## Per-fold specs, with code-verified corrections

### F8 — fork coordinator → `PumpForkCoordinator<P: HostSignalPump>` — **DONE (rig-verified)**
- **Landed:** `carrick_hal::pump_fork_coord` — the platform-neutral
  `PumpForkCoordinator<P>` state machine + `HostSignalPump` trait. Kick+futex
  backends → `PumpForkCoordinator<SelfPipePump<G>>` (`GenericForkCoordinator<G>` is
  that alias); HVF → `PumpForkCoordinator<KqueuePump>`. The state machine
  reproduces BOTH backends exactly (CORRECTION 4's policy divergence is handled by
  `installed_independent_of_stop` (always-on vs lazy) + `reinit_child(had)`
  (coordinator- vs runtime-owned self-pipe reinit) + no-op `ensure_handler` for
  HVF's signal-less kick).
- **Verified:** coordinator unit tests (lazy + always-on, HVF 3/3); fork/clone
  probe spine on the rig (clonebasic/clone3args/forkshared/forksigwalk/
  forksleepfork/forkcow/forkaltstack/forkfpregs/forkhighva/maskfork/killgroup);
  fork-storm + nested-fork demos (no lost-wake); KVM/bhyve cross-compile; clippy.
- **Robustness follow-up (clearly scoped):** HVF's `block/restore_signals_for_fork`
  are still no-op (= pre-fold behavior). The real fix = `pthread_sigmask` HVF's
  routed-handler signal set across the fork window (CORRECTION 2). Self-contained
  now that the seam exists.
- *(historical design notes below)*
- **Was:** generic `GenericForkCoordinator<G>` (`carrick-hal/src/fork_coord.rs:80`,
  cfg linux/freebsd/netbsd, process-global self-pipe pump) vs HVF `ForkCoordinator`
  (`carrick-vmm-hvf/src/fork_coord.rs:59`, instance `Mutex<Option<SignalPump>>`,
  kqueue pump).
- **CORRECTION 1 (design):** the spec's `HostSignalPump` with only `block/restore`
  is INCOMPLETE. The two pumps also differ in **start/stop/reinit and ownership**
  (process-global free fns vs instance `Mutex<Option<SignalPump>>`). The trait
  must abstract the FULL lifecycle: `start`, `stop_for_fork`, `reinit_after_fork`,
  `block_signals_for_fork`, `restore_signals_after_fork`, `ensure_handler_installed`.
  The pump impl owns its state (HVF's `Mutex<Option<SignalPump>>` lives in the
  HVF pump impl; the self-pipe pump is the process-global one).
- **CORRECTION 2 (correctness):** the spec says HVF's `KqueuePump` block/restore
  are **no-ops** — WRONG. HVF's host-signal handlers DO poke a self-pipe
  (`carrick-vmm-hvf/src/host_signal.rs:13`), so during the fork window a handler
  can write to a stale/half-reinit'd pipe. HVF genuinely needs real block/restore
  (= `pthread_sigmask` of HVF's pump signal set), which is NEW HVF code, not a
  no-op. This is the actual robustness fix. It must compose with the existing
  `block_hvf_private_thread_signals` (host_signal.rs:167) — verify no double-block.
- **CORRECTION 3 (framing):** the spec's "active bug" (CPython
  `test_parent_process` timeout) was ALREADY fixed in the maskfork era (commit
  12f5f65, `SignalPump::stop` lost-wake). So F8 is **robustness + durability +
  leverage**, NOT a reproducible-bug fix. The race window it closes is real but
  not currently observable, so verify by "no regression on fork probes" + the
  state-machine unit test, not a red→green repro.
- **CORRECTION 4 (the BIG one — pump-LIFECYCLE policy diverges, not just the wake
  primitive):** the two coordinators' restart paths are genuinely different, so a
  single state machine CHANGES one backend's behavior:
  - The generic's `restart_after_child_fork` calls `reinit_after_fork::<G>`
    **UNCONDITIONALLY** (signal_pump.rs:361 — it tears down the stale self-pipe
    AND respawns the pump every time): the generic pump is **always-on**.
  - HVF's child path respawns **only `if had_signal_pump`** (fork_coord.rs:98),
    and the HVF pump is **lazy** — `start_signal_pump` is gated on tty/interactive
    (runtime.rs:1547-1549), so a non-interactive guest never has a pump.
  - HVF's self-pipe reinit is owned by the **runtime** (quiesce.rs:508,
    `host_signal::reinit_after_fork`), run BEFORE the coordinator's restart
    (quiesce.rs:531) — whereas the generic coordinator owns its own self-pipe
    rebuild inside `reinit_after_fork::<G>`.
  So `PumpForkCoordinator<P>` must parameterize the **pump policy** (always-on vs
  lazy) and the **self-pipe-reinit ownership** (pump-owned vs runtime-owned), not
  just the wake primitive + block/restore. This is a careful design pass — fold
  HVF onto the GENERIC (more-robust) policy only if the rig confirms HVF's lazy
  pump can become always-on without regressing the non-interactive/tty paths
  (pty/job-control probes), OR keep the policy as a trait knob. Do NOT blind-copy.
- **Verify:** `cargo test --lib` (the coordinator state-machine tests, lifted to
  the generic `PumpForkCoordinator`), `just conformance-probes` (fork*/clone*/
  kill*/maskfork/ppollunblock), nested-fork shell stress under `-t`.

### F4 — HVF signal disposition → `carrick-signal-core` host_glue — **DONE (rig-verified)**
- **Landed:** additive `HostSignalGlue` methods (`skip_install_routing` /
  `skip_ignore_mirror` / `skip_execve_reset`, defaults = the prior
  `!is_routable`/`is_claimed` so KVM/bhyve/NVMM are byte-unchanged) +
  `is_synchronous_self_fault` wired into `shared_routed_handler`; a ~30-line
  `HvfGlue` overriding them. HVF's four disposition fns + `handle_routed` collapse
  to one-line delegations; coherent because HVF already writes carrick-signal-core's
  `proc_pending` (`HvfGlue::poke = notify_pending`).
- **Verified:** every disposition probe identical pre/post (execvereset reset,
  killfault si_code guard `ignored=6/6 correct=1`, killgroup\*, faultaddr, execsig,
  forksigwalk); 29/29 unit tests; clippy clean. The 2 pre-existing unrelated
  failures (execvereset altstack, cloneexitsig chld) reproduce on the pre-F4 binary.
- **Note for F8:** F4 STUBBED HvfGlue's `kick_signal`/`install_kick_handler` (HVF
  kicks via `hv_vcpus_exit`); the disposition path never consults them. F8 must
  give those real meaning OR keep the trait relaxed — the coupling below stands.
- *(historical)* **Was:** HVF re-implemented the disposition control flow
  (`host_signal.rs:945-1083`) vs shared `host_glue.rs:30-148`.
- **CORRECTION (verify before fixing):** the spec's two claimed bugs are
  **muddled** — (a) the SIGINT skip-set claim cites `matches!(9|13|17|19)` which
  does NOT contain SIGINT(2); (b) the `reset_routed_handlers_after_execve`
  off-by-one spec contradicts itself on which side (`<< signum` vs
  `<< signum-1`) is correct. Before touching either, confirm the actual
  dispatcher `ignored_mask` ABI (is it indexed by `signum` or `signum-1`?) and
  the real per-backend skip sets. Do NOT "fix" an off-by-one without proving the
  ABI direction with a probe.
- **CORRECTION (both bug-claims FALSIFIED by code):** (a) no SIGINT drift —
  `ensure_host_handler` line 946 skips only `{9,13,17,19}`, so HVF DOES route
  SIGINT; (b) no off-by-one — both HVF (host_signal.rs:1070) and the shared
  (host_glue.rs:141) use `1u64 << linux_signum` for `ignored_mask` (correct per
  the dispatcher ABI, documented at host_signal.rs:1067-1069) and `<< (signum-1)`
  for the install mask. **F4 is pure dedup, no correctness bug.**
- **REAL intricacy (why it's not a clean fold):** HVF has THREE different
  per-function skip-sets — install `{9,13,17,19}`, ignore/default
  `{2,4,5,6,7,8,9,11,13,17,19}`, reset `{2,9,13,17,19}` — because HVF ROUTES the
  fault set (a sibling `kill -SEGV` must reach the guest) with the synchronous
  si_code guard, but must NOT host-`SIG_IGN` a fault (it would re-execute
  forever). The shared `host_glue` has ONE `is_routable` gate, which can't express
  this. The fold needs additive `HostSignalGlue` methods — `skip_install`,
  `skip_ignore`, `skip_execve_reset` (defaults = the current `!is_routable` /
  `is_claimed`, so KVM/bhyve/NVMM are byte-unchanged) + `is_synchronous_self_fault`
  wired into `shared_routed_handler` — then a full `HvfGlue` overriding them.
- **THE COUPLING (F4 ⇄ F8 ⇄ F3):** a `HostSignalGlue` impl requires
  `kick_signal()` + `install_kick_handler()`, but **HVF has no signal-based kick**
  — it kicks vCPUs via `hv_vcpus_exit` (a direct syscall) and pokes its pump via a
  self-pipe, not an RT-signal. So `HvfGlue` can't be created without ALSO
  reconciling HVF's signal-less kick + kqueue pump with the shared trait surface
  (F8's territory). **This structural mismatch — HVF's signal-less kick + kqueue
  pump vs the shared signal-based model — is the deep reason HVF is "the factoring
  holdout," and why F4/F8/F3 are one coupled refactor, not three independent
  folds.** Either relax the trait (kick becomes an associated mechanism, not
  necessarily a signal) or give HVF a no-op kick-signal shim; decide that FIRST.
- **Verify:** kill02 / sigaction02 / job-control LTP + the kill*/sig* probe spine
  on the HVF rig (only HVF exercises the routed-fault + si_code-guard path).

### F5 — `HvfFutex` → `FutexTableFutex<HvfShared>` — **DONE (commit after d8791cc8)**
- **Done out of plan-order** (it's behaviour-preserving + independent of F4/F8, so
  the "after F4" sequencing wasn't load-bearing for it). `HvfFutex` was already a
  forwarding shim; its private path + `shared_wait_sliced` loop + wake were
  byte-identical to `FutexTableFutex<S>`. The only thing keeping it separate was
  the carrick-trace probes: a default-no-op `SharedFutexSyscall::pre_wait` hook
  (once-before-wait peek) + moving the per-slice probe into `wait_one_slice` let
  it fold to `FutexTableFutex<HvfShared>` (~100 LOC → a ~25-line `HvfShared`).
- **Verified on the rig:** futexshare/requeue/deadline/pilock/extra/wakecount all
  pass; 17/17 carrick-thread futex unit tests; the `pre_wait` default keeps
  KVM/bhyve/NVMM unchanged (cross-compile clean).

### F7 — `Aarch64EngineCore<V: Aarch64Vmm>` (engine symmetric to carrick_x86)
- **DONE (slice):** `guest_cpu::timed_run` hoist — the 3 run-loop CPU-timing
  copies are single-sourced (verified).
- **Remaining slices:** a shared `TrapError::el0_fault` constructor (LOW value —
  the two sites read different register types: HVF applevisor `Reg`/`SysReg` vs
  KVM `carrick_hal::Reg`, so a clean shared constructor is awkward; reconsider as
  part of the full engine extraction, not standalone).
- **Capstone:** `Aarch64EngineCore<V>` + `Aarch64Exit` so the HVF and KVM-aarch64
  trap shells share one engine (like carrick_x86). Large.
- **Verify:** the full probe gate (the engine drives all syscall dispatch).

### F3 — fold `run_threaded_hvf_loop` onto the shared `run_threaded_loop` — **DONE (rig-verified)**
- **Landed:** extracted `HostBackend` + `run_threaded_loop` into the new neutral
  `crate::threaded_loop` module; HVF's loop is a thin wrapper over
  `run_threaded_loop(trap, dispatcher, HvfHostBackend, max_traps)`. The 5
  divergences became 4 `HostBackend` methods with macOS-safe defaults
  (`make_signal_arrival`, `pre_loop_setup`, `start_pump_eagerly`,
  `register_process_timer_kicker` — cfg'd) + the PID-ns fallback inlined (guarded
  by `requested()`). All four backends now drive ONE loop.
- **Verified:** build signed clean; carrick-runtime (macOS) compiles; HVF rig
  smoke + maskfork/killgroup/forksleepfork/itimer/itimerprofidle/posixtimers; full
  gate. *Linux/freebsd/netbsd inline-runtime compile relies on CI* — `ring`'s C
  build script blocks the carrick-runtime cross-compile from macOS (the change
  there is a single `use` + the moved trait; the new methods are defaults, so the
  existing KVM/bhyve/NVMM `HostBackend` impls are untouched).
- *(historical scope notes below)*
The KVM/bhyve/NVMM loops are already thin wrappers — e.g. `run_threaded_kvm_loop`
is just `run_threaded_loop(engine, dispatcher, KvmHostBackend, max_traps)`
(lib.rs:761). F3 makes HVF the same. With F4/F5/F8 done, the seams it consumes
(HvfGlue, hvf_futex, the fork coordinator) all exist.

**STRUCTURAL PREREQUISITE (discovered 2026-06-21 — the real work):** the shared
`run_threaded_loop` + `HostBackend` live INSIDE `#[cfg(not macos)] pub mod runtime
{ … }` (an INLINE module in lib.rs, the Linux/KVM path), while
`run_threaded_hvf_loop` is the SEPARATE `#[cfg(macos)] runtime.rs` file — two
mutually-exclusive same-named `crate::runtime` modules. So "un-gate for macOS" is
really: **extract `run_threaded_loop` + `HostBackend` (+ the `*HostBackend` impls'
shared scaffold) into a NEW platform-neutral module** (e.g. `threaded_loop.rs`,
no cfg) that BOTH the Linux inline module and `runtime.rs` call. Only then can HVF
fold. This is a real run-loop module restructure, highest-stakes (the loop drives
the ENTIRE runtime), so verify on the FULL gate + interactive `-t` + a container.

**The 5 per-backend differences (each → a `HostBackend` method, defaults preserve
KVM/bhyve/NVMM byte-for-byte):**
1. `signal_arrival` (lib.rs:574 hardcodes `GenericSignalArrival`) → `fn
   make_signal_arrival(&self, kicker, futex) -> Arc<dyn SignalArrival>`; default
   `GenericSignalArrival{kicker,futex}`, HVF `HvfSignalArrival`.
2. Pre-loop setup (runtime.rs:1460-1461 `install_default_handlers` +
   `TermiosRestoreGuard`) → `fn pre_loop_setup(&self) -> Box<dyn Any>`; default
   `Box::new(())`, HVF installs handlers + returns the termios guard (held for the
   loop).
3. Pump-start policy (shared loop line 591 starts UNCONDITIONALLY; HVF gates on
   `host_isatty` runtime.rs:1547) → `fn start_pump_eagerly(&self) -> bool`;
   default `true`, HVF `isatty(0)||isatty(1)`.
4. Timer wiring: shared calls `timer_delivery::register(kicker,main_tid)` +
   `register_delivery(make_timer_delivery())`; HVF skips the first. HVF can GAIN
   it (harmless — only registers the kicker for the fallback thread, spawned only
   in a pump-less context); `make_timer_delivery` → `HvfTimerDelivery`.
5. PID-namespace fallback (runtime.rs:1481-1483) → add to the shared loop guarded
   by `namespace::pid::requested()` (no-op when not requested → KVM/bhyve/NVMM
   unchanged).
**Then:** `HvfHostBackend` (make_futex=`hvf_futex`, make_fork_coordinator=
`ForkCoordinator`, make_kicker=`VcpuKicker`, the 5 above); repoint runtime.rs:745
to `run_threaded_loop(trap, dispatcher, HvfHostBackend, max_traps)`; delete
`run_threaded_hvf_loop`. `HvfTrapEngine: ThreadedEngine` already (trap.rs:5676).

## Load-bearing splits to PRESERVE (audit §3 — do NOT fold)
- Wake primitive: HVF kqueue/`EVFILT_USER` + self-pipe vs generic self-pipe +
  `pthread_kill` kick. Isolated by the pump trait / `make_signal_arrival`.
- Kick mechanism: HVF `hv_vcpus_exit` (no signal) vs KVM/bhyve/NVMM RT-signal +
  `EINTR`. Already isolated by `HostSignalGlue::install_kick_handler`.
- Futex wake: HVF `__ulock` vs Linux futex syscall vs BSD `_umtx_op`.
- COW fork RAM: Mach VM COW / OS COW / bhyve freeze+rebuild — behind
  `ForkRamStrategy`, orthogonal to the pump coordinator.

## Standing verification spine (re-run after EACH fold, on the HVF rig)
1. `cargo test --workspace --lib` (coordinator / fork_quiesce / signal_pump /
   futex unit tests). NOTE the known flake
   `carrick-vmm-hvf io_wait::unbounded_poll_wait_retries_after_backstop_slice`
   (timing-sensitive; passes in isolation — retry, don't treat as a regression).
2. `just conformance-probes` — the fork/signal/futex/trap probe gate vs Docker.
3. Targeted runtime demos for the fold's subsystem (nested-fork shell under `-t`;
   apt fork-storm; the futex/signal LTP suites).
4. `carrick-lldb` event-ring post-mortem if any nested-fork/futex test wedges
   (tracing perturbs these Heisenbugs).
