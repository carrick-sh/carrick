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

### F8 — fork coordinator → `PumpForkCoordinator<P: HostSignalPump>`
- **Current:** generic `GenericForkCoordinator<G>` (`carrick-hal/src/fork_coord.rs:80`,
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
- **Verify:** `cargo test --lib` (the coordinator state-machine tests, lifted to
  the generic `PumpForkCoordinator`), `just conformance-probes` (fork*/clone*/
  kill*/maskfork/ppollunblock), nested-fork shell stress under `-t`.

### F4 — HVF signal disposition → `carrick-signal-core` host_glue
- **Current:** HVF re-implements the disposition control flow
  (`carrick-vmm-hvf/src/host_signal.rs:945-1083`) vs shared
  `carrick-signal-core/src/host_glue.rs:30-148`.
- **CORRECTION (verify before fixing):** the spec's two claimed bugs are
  **muddled** — (a) the SIGINT skip-set claim cites `matches!(9|13|17|19)` which
  does NOT contain SIGINT(2); (b) the `reset_routed_handlers_after_execve`
  off-by-one spec contradicts itself on which side (`<< signum` vs
  `<< signum-1`) is correct. Before touching either, confirm the actual
  dispatcher `ignored_mask` ABI (is it indexed by `signum` or `signum-1`?) and
  the real per-backend skip sets. Do NOT "fix" an off-by-one without proving the
  ABI direction with a probe.
- **Genuine leverage:** the synchronous-fault `si_code` guard (host_signal.rs
  ~899-918) is HVF-only; making it a `HostSignalGlue::is_synchronous_self_fault`
  trait method puts it where any backend can opt in (audit §2.1 F4).
- **Verify:** kill02 / sigaction02 / job-control LTP, a new `sigint_routable`
  probe run on HVF + KVM to prove skip-set symmetry.

### F5 — `HvfFutex` → `FutexTableFutex<HvfSharedFutex>`
- **Current:** HVF hand-rolls the deadline/slice/interrupt loop
  (`carrick-vmm-hvf/src/threaded_impl.rs`) vs the shared `shared_wait_sliced`.
- **Care:** this is the exact site lost-wake bugs hide; sequence AFTER F4 so the
  signal/EINTR-interruptibility fixes are banked first (futex wait and signal
  interruptibility interact). Preserve the carrick-trace probes the module
  deliberately keeps (move them into `HvfSharedFutex::wait_one_slice`).
- **Verify:** futex*/perf_futex_pingpong probes, LTP futex suite.

### F7 — `Aarch64EngineCore<V: Aarch64Vmm>` (engine symmetric to carrick_x86)
- **DONE (slice):** `guest_cpu::timed_run` hoist — the 3 run-loop CPU-timing
  copies are single-sourced (commit d8791cc8, verified).
- **Remaining slices:** a shared `TrapError::el0_fault` constructor (LOW value —
  the two sites read different register types: HVF applevisor `Reg`/`SysReg` vs
  KVM `carrick_hal::Reg`, so a clean shared constructor is awkward; reconsider as
  part of the full engine extraction, not standalone).
- **Capstone:** `Aarch64EngineCore<V>` + `Aarch64Exit` so the HVF and KVM-aarch64
  trap shells share one engine (like carrick_x86). Large.
- **Verify:** the full probe gate (the engine drives all syscall dispatch).

### F3 — `make_signal_arrival` on `HostBackend` + delete `run_threaded_hvf_loop`
- **Current:** generic shared loop (`carrick-runtime/src/lib.rs:507-632`) vs the
  HVF clone (`carrick-runtime/src/runtime.rs:1455-1584`); the ONE load-bearing
  difference is the `SignalArrival` type (generic kick+futex vs HVF kqueue pump).
- **ADDED SCOPE the spec understates:** `HostBackend`/`run_threaded_loop` are
  `#[cfg(any(platform-linux,freebsd,netbsd))]` (lib.rs:463-467, 502-506) — NOT
  compiled on macOS. F3 must un-gate them for platform-macos, add an
  `HvfHostBackend`, and relocate the HVF-exclusive pre-loop setup
  (`install_default_handlers` runtime.rs:1460, `TermiosRestoreGuard` 1461,
  conditional pump-start 1547-1549). LAST, after F4/F5/F8 land + rig-verify.

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
