# NetBSD run-path sharing scout — is `native_freebsd.rs` host-glue or FreeBSD-welded?

**Date:** 2026-07-25
**Task:** Scout resolving the scope of NetBSD Tasks 3-5 (the "host-glue not
monolith" thesis's real test). Re-shapes
`docs/superpowers/plans/2026-07-24-netbsd-native-lane.md` Tasks 3-5.
**Subject file:** `crates/carrick-runtime/src/native_freebsd.rs` (15,784 lines) —
the x86 native RUN LOOP (`run_x86_thread`, syscall dispatch, signal delivery,
fork/vfork/exec, the 4 SharedFutex call sites). Hard-gated
`#![cfg(all(target_os = "freebsd", target_arch = "x86_64"))]` (line 26).
**Grounding:** `docs/superpowers/specs/2026-07-25-netbsd-primitives-grounding.md`
(Task 0 — all primitives GO). **Branch:** `feat/netbsd-native-lane` @ `e34ea71f`.
**Method:** full read of the run loop + both host crates
(`carrick-native-freebsd`, `carrick-native-netbsd`) + the seam traits
(`carrick-dsr::lane`, `carrick-dsr::host`) + `native/mod.rs` + `carrick-portable`;
on-box build/test probe on VM 201 (NetBSD 10.1 amd64).

---

## Bottom line

**The thesis HOLDS.** `native_freebsd.rs` is cleanly re-gateable to
`any(target_os = "freebsd", target_os = "netbsd") + x86_64` (rename →
`native_x86.rs`) behind a **bounded** set of dispatch points. Most of them are
**already trait seams** that the file happens to name through the concrete
`FreebsdHost`/`FreebsdHostJit` types instead of the lane's `Host` associated
type — a mechanical reference-swap, not a logic rewrite. There is exactly **one**
genuine FreeBSD-welded *capability* (the `procctl` subreaper), and it degrades to
a documented no-op red-list item, not an implementation blocker. **The
thread-spawn "gap" the scout was sent to find does not exist**: the run loop
spawns guest threads with `std::thread::Builder` (line 7855), which is
pthread-backed on NetBSD — no `_lwp_create` is required (the grounding doc's
`_lwp_create`/`_lwp_kill` notes describe a *lower-level alternative*, not a
necessity; the portable `std::thread` + `pthread_kill` path already in the loop
works verbatim on NetBSD).

---

## Inventory

Classification key: **SHARED-ALREADY** (POSIX, verbatim on both BSDs) ·
**LANE-DISPATCHABLE** (host-specific, behind a clean/small seam) ·
**FREEBSD-WELDED** (a real capability divergence — the thesis-testing spots).

| # | Dependency | Lines | Class | Seam / how NetBSD plugs in |
|---|---|---|---|---|
| 1 | **Guest-thread spawn** `std::thread::Builder::new().name().spawn(body)` (`spawn_native_clone_host_thread`) | 7845-7856 | **SHARED-ALREADY** | `std::thread` → pthread on NetBSD. **No `_lwp_create` needed.** This is the scout's headline finding — the loop never touches raw `clone`/`pthread_create`/`_lwp_create`. |
| 2 | **Kick send** `libc::pthread_kill(pthread, SIG)` + `pthread_self()` capture | 7634, 7696, 7731, 11982 | **SHARED-ALREADY** | POSIX; NetBSD libpthread has both. Only the signal *number* differs (item 8). The `_lwp_kill` in the NetBSD `fault.rs` doc is aspirational; `pthread_kill` is the portable path in use. |
| 3 | **Signal delivery / masking** `run_pending_signals`, `sigaction`, `sigprocmask`, `sigaltstack`, SIGCHLD handler | 6021, 6171-6225, 9805 | **SHARED-ALREADY** | Pure POSIX signal machinery. |
| 4 | **Child reaping** `waitpid`/`wait4`/`waitid`, `kill_and_reap_native_fork_child` | 462, 11546, 11691, 12475… | **SHARED-ALREADY** | POSIX. (The *subreaper acquire* that feeds it is item 12.) |
| 5 | **4× SharedFutex call sites + init** `carrick_native_freebsd::futex::{shared_wait ×2, shared_wake, shared_requeue, init_shared_waiter_table}` | 8379, 10797, 10838, 10873, 10903 | **LANE-DISPATCHABLE** | All args are shared types (`location.wait_addr().raw()`, `location.waiter_key()`, value/count/timeout, closures). NetBSD needs `carrick_native_netbsd::futex` with the **same 4-fn free-function API** — *thinner* (grounding §3: `SYS___futex`=166 is Linux-shaped → no waiter-count table, no logical-requeue). Seam = one cfg-selected `use … as futex` module alias at the file top. |
| 6 | **`FreebsdHost::exclusive_fixed_map_flag()`** (returns `MAP_EXCL`) | 166, 1252, 6562, 6574, 6687, 6696, 6720, 6728, 14485, 14530, 14606, 14631, 14899, 14926, 15004, 15028 (16 sites) | **LANE-DISPATCHABLE** | **Already a `NativeHost` trait method.** `NetbsdHost` inherits the default `0` (no `MAP_EXCL`; overlap caught by `NativeMappingTransaction`). Route the 16 sites through `<HostNativeLane>::Host::…`. Zero new surface. |
| 7 | **`FreebsdHost::shared_futex_waiter_key`** | 1251 | **LANE-DISPATCHABLE** | **Already a `NativeHost` trait method.** `NetbsdHost` inherits default `None` (kernel keys shared futexes by backing object). Route through `Host::`. |
| 8 | **Kick signal const** `FREEBSD_NATIVE_EXIT_KICK_SIGNAL = 65` | 7496, used 6156-6157, 7696, 7731, 8310, 11982, 15703-15704 | **LANE-DISPATCHABLE** | NetBSD crate already exports `NATIVE_EXIT_KICK_SIGNAL = 33` (SIGRTMIN). Reference the crate const per-lane; move the FreeBSD `65` into `carrick-native-freebsd` to mirror. |
| 9 | **JIT authority** concrete `FreebsdHostJit` field/value + `active_host_jit()` | 58, 7509, 8175, 8275, 8966, 8995, 9781 | **LANE-DISPATCHABLE** | Already behind the `NativeHostJit` trait via `active_host_jit()`. NetBSD's `active_host_jit()` exists (Task 1). Swap the concrete `jit: FreebsdHostJit` field/`let jit = FreebsdHostJit` for `<Host>::active_jit()` (`&'static dyn NativeHostJit`) or a per-lane type alias. |
| 10 | **Fault-shim module** `carrick_native_freebsd::fault::{register_code_region, unregister_code_region, install_fault_redirect, install_kick_redirect, KickRcxRecovery}` | 58, 7234, 7243, 7262, 7298, 8153, 8300, 8309, 8500 | **LANE-DISPATCHABLE** | NetBSD's `carrick_native_netbsd::fault` (Task 2) exposes the **byte-identical API** (verified: same 5 symbols). Seam = one cfg-selected `use … as fault` module alias. |
| 11 | **vfork `minherit`** `native_minherit` → `carrick_portable::freebsd_minherit` + `FREEBSD_INHERIT_SHARE/COPY` | 3283, 11734-11741, 11842, 11856 | **LANE-DISPATCHABLE** | NetBSD **has `minherit(2)`** with the same `MAP_INHERIT_SHARE/COPY` values (0/1), different syscall #. `carrick-portable` currently gates these `#[cfg(freebsd)]` only → add a NetBSD arm (~15 LoC in the portable layer, not the lane). |
| 12 | **Subreaper acquire** `procctl(P_PID, 0, PROC_REAP_ACQUIRE, NULL)` | 8388-8394 | **FREEBSD-WELDED** | **NetBSD has no `procctl`/`PROC_REAP_ACQUIRE` and no subreaper equivalent.** Effect = "orphaned guest grandchildren reparent here so guest `wait4(-1)` reaps them." Mechanism is LANE-DISPATCHABLE (new `NativeHost::become_guest_reaper()`; NetBSD = no-op) but the **capability is lost** on NetBSD → orphans reparent to host init, guest can't reap them. A **red-list item** (like the plan's kqueue/lwp worklist), not a blocker for a static ELF. |
| 13 | **vDSO TSC calibration** `freebsd_sysctl_i32` + `freebsd_tsc_vdso_is_safe` + `freebsd_tsc_frequency` (`kern.timecounter.invariant_tsc`, `.smp_tsc`, TSC freq) | 6378-6462 | **FREEBSD-WELDED (soft)** | `libc::sysctlbyname` exists on NetBSD; the sysctl **names** are FreeBSD-specific. On `None` the guest falls back to syscall clocks (line 6457 already returns `None` when unsafe). NetBSD arm = either NetBSD sysctl names or a plain `None` (correct, slower). **Graceful degradation**, not a hard weld. |
| 14 | **errno poke** `*libc::__error() = libc::EIO` (fault-injection helper) | 11661-11662 | **LANE-DISPATCHABLE** | Route through `carrick_portable::set_errno(EIO)` (already exists; the same fix landed for `identity_memory` in `b82681da`). Trivial. |
| 15 | **`#![cfg]` gate** | 26 | **LANE-DISPATCHABLE** | `all(freebsd, x86_64)` → `all(any(freebsd, netbsd), x86_64)`. |

**Tally:** SHARED-ALREADY = **4 categories** (items 1-4) · LANE-DISPATCHABLE =
**9** (items 5-11, 14, 15) · FREEBSD-WELDED = **2** (items 12, 13), of which only
item 12 is a true capability gap and item 13 is graceful-degradation.

---

## Verdict — thesis HOLDS (bounded host-glue)

Re-gating `native_freebsd.rs` to `any(freebsd, netbsd)` is a **bounded** change:

- **Nothing in the run loop's logic is FreeBSD-welded.** The syscall dispatch,
  signal delivery, fork/vfork/exec orchestration, thread lifecycle, JIT admission
  epoch, and the futex *call shape* are all lane-agnostic. What's FreeBSD-specific
  is a thin rind of **host primitive selection** (which futex/fault module, which
  kick signal, which errno accessor) plus **two host services** (the subreaper,
  the TSC clock source).
- **~16 of the dispatch points are already `NativeHost` trait seams** the file
  merely names through the concrete `FreebsdHost`/`FreebsdHostJit` type. Routing
  them through `<HostNativeLane>::Host` is mechanical and adds **zero** new
  surface — the seams (`active_jit`, `shared_futex_waiter_key`,
  `exclusive_fixed_map_flag`) were designed for exactly this.
- **The two identical-API host modules** (`futex`, `fault`) already exist on both
  crates with matching signatures (Tasks 1/2 verified on-box), so the futex +
  fault seam is a **single cfg-selected module alias**, not per-site cfg scatter.
- **The one hard weld** (item 12, `procctl` subreaper) has no NetBSD analog, but
  its *mechanism* trivially becomes a no-op `NativeHost` method and its *capability
  loss* (orphan reaping) is a known-gap red-list entry — squarely inside the
  plan's "the red list IS the NetBSD worklist" framing. It does **not** stop a
  static ELF from running.

**New code is small; the file edits are reference-swaps.** Genuinely new NetBSD
code beyond Tasks 0-2 (already landed): `carrick_native_netbsd::futex` (~120-160
LoC — grounding §3 makes it a thin `SYS___futex` wrapper, less than a third of
FreeBSD's 568-line waiter-table `futex.rs`) + a trivial `waiter_key` (returns
`None`), a `carrick-portable` NetBSD `minherit` arm (~15 LoC), a `become_guest_reaper`
seam (~5 LoC FreeBSD impl + ~2 LoC NetBSD no-op), and a TSC-calibration arm
(~10 LoC or `None`). The `native_freebsd.rs → native_x86.rs` edits themselves are
mechanical: change the `#![cfg]`, swap the ~30 concrete `FreebsdHost*`/
`carrick_native_freebsd::` references to lane-selected ones, and add the two
module-alias `use` lines. No control-flow rewrite.

**Hard spots to flag (thesis-strain, all bounded):** (1) the `procctl` subreaper
capability gap; (2) the TSC vDSO sysctl-name gap (soft). Neither strains the
thesis into "more than host-glue" — both are single host *services* with a clean
no-op/None fallback, exactly the shape a lane seam absorbs.

---

## Recommended dispatch mechanism — **hybrid (c), weighted to reuse the existing trait**

Not a new god-trait (over-abstracts 4 identical free functions), not per-site cfg
scatter (violates the plan's "no scattered `#[cfg(target_os)]` in shared code").
Sized-to-consumption:

1. **Reuse the existing `NativeHost` trait** for the seams already there. Add a
   file-top alias `type LaneHost = <HostNativeLane as carrick_dsr::lane::NativeLane>::Host;`
   and route the 16 `FreebsdHost::exclusive_fixed_map_flag()` sites, the
   `shared_futex_waiter_key` site, and the JIT authority through `LaneHost::` /
   `LaneHost::active_jit()`. (Extends the *existing* seam; no new surface.)
2. **One cfg-selected module-alias seam** at the file top for the two
   symmetric-API host modules and the kick const:
   ```rust
   #[cfg(target_os = "freebsd")] use carrick_native_freebsd::{futex, fault};
   #[cfg(target_os = "netbsd")]  use carrick_native_netbsd::{futex, fault};
   ```
   plus `use …::NATIVE_EXIT_KICK_SIGNAL`. This is option (b) applied *once* (a
   single module boundary), not per-call — the 4 futex sites + 8 fault sites then
   read `futex::…` / `fault::…` unchanged. Preferable to a trait because the APIs
   are already free-function-identical across both crates.
3. **Add exactly two small `NativeHost` methods** for the genuine host-service
   divergences (option a, sized to consumption):
   `fn become_guest_reaper()` (FreeBSD = `procctl` PROC_REAP_ACQUIRE; NetBSD =
   no-op with a doc-comment red-list pointer) and, if not folded into a `None`
   fallback, `fn vdso_tsc_calibration() -> Option<TscCalibration>`.
4. **`minherit` stays in `carrick-portable`** (the existing portable home) with a
   NetBSD arm — it is a libc-ABI shim, not a lane concern.

This keeps the run loop lane-agnostic, adds ≤2 trait methods + 1 module-alias
block + 1 `Host` alias, and touches `carrick-portable` for one libc shim.

---

## Re-shaped Tasks 3-5

The original plan's Task 3 ("Futex + lane dispatch") is only *part* of the work —
the re-gate of the whole run loop is the bulk, and it is a no-behavior-change
refactor that must be regression-checked on the FreeBSD box. Split Task 3:

- **Task 3a — the seam + FreeBSD-behind-it (no behavior change; FreeBSD-box
  regression GATES merge, not authoring).** Rename `native_freebsd.rs` →
  `native_x86.rs` (keep `#![cfg(freebsd, x86_64)]` for now). Introduce: the
  `LaneHost` alias routing the 16+2 trait-seam sites (item 6/7/9); the single
  cfg module-alias `use` block (FreeBSD arm only) for `futex`/`fault`/kick-const
  (items 5/8/10); the new `NativeHost::become_guest_reaper()` with the FreeBSD
  `procctl` impl (item 12); the TSC seam/`None` (item 13); `set_errno` (item 14);
  and the `carrick-portable` NetBSD `minherit` arm (item 11, dormant). Pure
  refactor — FreeBSD behavior identical; the existing FreeBSD futex tests + the
  12/12 cross-fork test must still pass on the fbsd box (deferred to box
  availability — peer-contended; gates merge).

- **Task 3b — re-gate + NetBSD impl.** Flip `#![cfg]` to
  `all(any(freebsd, netbsd), x86_64)`. Add the NetBSD arms: the module-alias
  `use carrick_native_netbsd::{futex, fault}` + kick const; `NetbsdHost::become_guest_reaper()`
  no-op + TSC `None`. Build `carrick_native_netbsd::futex` (thin `SYS___futex`
  wrapper, no waiter table — grounding §3) + trivial `waiter_key`. Box: the whole
  `native_x86.rs` run loop compiles on NetBSD. (This is the original Task 3 futex
  work, now smaller, plus the re-gate.)

- **Task 4 — wiring** (unchanged from plan). `NetbsdX8664Lane` + third
  `HostNativeLane` cfg arm in `native/mod.rs`; `page_profile` `(NetBsd, Amd64)`
  entry; `carrick-runtime` `Cargo.toml` `#[cfg(target_os = "netbsd")]`
  `carrick-native-netbsd` dep (mirror the existing freebsd arm, line 133-134);
  extend the `native/mod.rs` drift-guard to NetBSD.

- **Task 5 — acceptance ELF + gate ladder** (unchanged). Static x86_64 hello ELF
  runs under `run_elf_native_dispatch` on NetBSD (RED→GREEN on the box — the
  campaign's acceptance moment). Adapt `scripts/native-x86-ltp-gate.py` to VM 201.
  **Red-list seeded by this scout:** orphan-reap (item 12), vDSO-TSC-off (item 13),
  plus the plan's kqueue EVFILT / lwp edges / futex-correctness follow-ons.

---

## NetBSD-box probe results (VM 201, NetBSD 10.1 amd64)

Synced current `feat/netbsd-native-lane` @ `e34ea71f` (`git archive HEAD`), built
with `LIBCLANG_PATH=/usr/pkg/lib`.

- **Shared crates build clean together — YES.**
  `cargo build -p carrick-native-netbsd -p carrick-dsr-x86 -p carrick-dsr -p carrick-mem`
  → `Finished dev in 22.38s`, **zero errors/warnings**. Confirms: `carrick-dsr-x86`
  (translate engine) + `carrick-dsr` (`identity_memory`, with the `b82681da`
  errno-seam fix) + `carrick-mem` + `carrick-native-netbsd` (Tasks 1/2 JIT+fault)
  all co-compile on NetBSD/amd64. The Task-0 verbatim-reuse thesis stands with the
  errno gap already closed in the shared layer.
- **NetBSD host crate tests — 11/11 PASS.** `cargo test -p carrick-native-netbsd`
  → `11 passed; 0 failed` incl. `jit::dual_map_aliases_one_object`,
  `jit::fork_child_fresh_region_does_not_corrupt_parent_exec`,
  `jit::written_code_executes_through_the_exec_view`,
  `fault::raised_sigsegv_in_registered_region_routes_not_fatal`,
  `fault::kick_repairs_an_active_emitter_rcx_spill`. The host pieces the re-gated
  run loop consumes (W^X JIT with `Fresh` fork-repair; fault redirect + RCX-recovery
  kick) are proven on-box.
- **Thread-spawn gap — NONE.** The run loop uses `std::thread::Builder`
  (`spawn_native_clone_host_thread`, native_freebsd.rs:7855), pthread-backed on
  NetBSD, and kicks via `pthread_kill` (POSIX). `_lwp_create`/`_lwp_kill` are a
  lower-level *alternative* the grounding doc characterized, **not a requirement**;
  the re-gated loop needs nothing new from the NetBSD side for threading. The only
  thread-adjacent lane item is the kick *signal number* (33 vs 65), already a
  crate const.

**VM 201 state:** left running (`qm start 201` issued at scout start; box was
already up). The `/root/carrick` snapshot is a disposable `git archive` tree (no
`.git`), left in place per the Task-0 convention. No persistent box mutation; no
config changed. **Snapshot state: running, disposable snapshot at `e34ea71f`,
safe to `qm stop 201` when the fleet needs the slot.**

## Review corrections (2026-07-24, adversarial source-verify pass)

An adversarial review verified the scout's load-bearing claims against native_freebsd.rs
and CONFIRMED the core thesis (bounded host-glue; no run-loop LOGIC welded; thread-spawn
gap does not exist) but corrected three over-optimistic framings:

- **F1 (highest):** the inline TEST surface was omitted from the inventory. `mod
  identity_raw_range_tests` (native_freebsd.rs:218, gated only `#[cfg(test)]`) is welded to
  FreeBSD futex internals (`SYS_UMTX_OP`/`UMTX_OP_WAKE`/`waiter_parked_count`, 225-227/517)
  and `libc::__error()` (11662) — no NetBSD analog. The `#![cfg]` flip breaks `cargo test`
  on NetBSD. Fix: gate the FreeBSD-welded test surface `#[cfg(all(test, target_os="freebsd"))]`;
  NetBSD unit-test coverage of the run loop is a red-list follow-on.
- **F2:** the verdict line "futex + fault modules already exist on both crates" was false —
  `carrick-native-netbsd` has fault/jit/lib but NO futex.rs; NetBSD futex is net-new
  (~120-160 LoC via SYS___futex, 4-fn symmetric API, `init_shared_waiter_table` a no-op).
- **F3:** the `procctl` "no-op" is behavioral, not free — guest double-forked orphans
  reparent to host init (not guest-init), so guest `wait4` returns ECHILD and the run loop's
  own subreaper bookkeeping (12093-12103) goes stale; red-list precisely. Kick is a signal
  PAIR (65/+1); NetBSD needs 33 AND 34 reserved.

Re-shaped tasks (3a seam+test-gate / 3b re-gate+NetBSD-futex / 4 wire / 5 acceptance) live in
`docs/superpowers/plans/2026-07-24-netbsd-native-lane.md`.
