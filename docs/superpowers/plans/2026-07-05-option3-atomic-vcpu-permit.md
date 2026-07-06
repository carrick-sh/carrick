# Option 3 — Crash-safe atomic vCPU admission permit (design spike) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.
> **REQUIRED READING:** `docs/superpowers/plans/2026-07-05-option3-atomic-vcpu-permit-companion-review.md` — the adversarial companion review whose design this plan now implements. Read it before Task 1; it has the full rationale and the exact `trap.rs` line anchors.

**Goal:** Replace carrick's cross-process HVF vCPU-admission `flock` permit with a fork-shared, **generation-stamped slot table** whose acquire is a cheap userspace CAS (vs `open`+`flock`+backoff) while **recreating flock's kernel-backed death-reclaim** — because a shared count that can exist without a reclaimable owner is exactly what timed out the node suites in the 3b attempt (`cur=4 budget=4 live_len=0`, node ~447×, flock matched in ~7-8 s).

**Architecture (amended per the companion review):** Ownership is the source of truth, not a bolt-on. Every admitted count IS a generation-stamped slot (`state | owner_pid | generation` in one packed `AtomicU64`), reclaimable idempotently by (a) a token-guarded local release on `vcpu_destroyed`, (b) a cooperative `process_exit_cleanup` release before a fork-child `_exit` skips Rust drops, and (c) a **mandatory** root `EVFILT_PROC/NOTE_EXIT` supervisor for hard death (SIGKILL/segfault/missed cleanup), with the generation guard defeating PID reuse. Flag-gated behind `CARRICK_HVF_ATOMIC_PERMIT=1`; `flock` stays the default and fallback. The cap math is untouched, and the cap-raise experiment is a SEPARATE follow-up (never committed with the atomic permit).

**Tech Stack:** Rust 2024; macOS+aarch64 HVF (`crates/carrick-vmm-hvf`); `mmap(MAP_ANON|MAP_SHARED)`, packed `AtomicU64` slots; `crate::darwin_kqueue` (`Kevent::proc_exit` = one-shot `EVFILT_PROC|NOTE_EXIT|NOTE_EXITSTATUS`, kqueue.rs:195-214); `waitid(WNOWAIT|WNOHANG)` non-consuming readiness (pattern at `host_signal.rs:197-205`/`io_wait.rs:659-667`); `HvfHostBackend::pre_loop_setup` (`runtime.rs:1610-1613`); `engine.process_exit_cleanup` (`hvf_aarch64_engine.rs:295`, currently no-op; called `vcpu_loop/mod.rs:1469/1500/1884`).

## Global Constraints
- **KEEP the cap math** unchanged: `budget_from_limits = min(hvf_cap, physical_cores)` (`trap.rs:1034`) and the per-class budgets `global_permit_budget_from_mn` (`trap.rs:726`). This spike changes the MECHANISM only.
- **The cap-raise is OUT of this plan.** It is a separate follow-up; do NOT commit any `CONSERVATIVE_GLOBAL_VM_CAP` change with the atomic permit (a failed fork-storm gate must be unambiguously the permit, not the cap or their interaction).
- **Gated + fallback:** all new behavior behind `CARRICK_HVF_ATOMIC_PERMIT=1`; unset → the current `flock` path, byte-for-byte.
- **Preserve the three flock invariants (companion review §"Current invariants"):** (1) only budgeted admission classes acquire — `ExecveRebuild`/vfork ungated; (2) a permit releases only if the destroyed `vcpu_id` HELD one (not every `vcpu_destroyed`); (3) fork-child clears inherited LOCAL tracking without releasing the parent's shared slots.
- **No ownerless count. Ever.** The slot (with owner + generation) must be published before/atomically-with the count it represents; the reaper reclaims by owner record, never by a bare counter.
- **Generation guard** on every reclaim so a late event for a dead owner cannot free a new slot held by a reused PID.
- The region is `MAP_ANON|MAP_SHARED`, created **before any guest fork** (in the initial admission path / HVF engine init — NOT lazily on first acquire; a child's first acquire would map a private region). It survives fork (inherited) but the carrick host process must not `execve` (it doesn't — guest exec is emulated via `ExecveRebuild`, no host exec).
- macOS+aarch64 only. Never run carrick+docker concurrently. Never `git commit --no-verify`. Typed domain values at boundaries.

## File Structure
- Modify `crates/carrick-vmm-hvf/src/trap.rs` — the permit subsystem: the packed-slot `PermitRegion`, `acquire`/`register`/token-guarded `release`, `reset_*_after_fork_child`, `create_vm_with_admission`, `create_vcpu_with_permit`, `vcpu_destroyed`, and the `atomic_permit_enabled()` dispatch (flock vs atomic).
- Create `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs` — the root supervisor: the `EVFILT_PROC` watcher + periodic backstop + `start_vcpu_permit_reaper()`.
- Modify `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:295` — the `process_exit_cleanup` override (atomic-only cooperative release).
- Modify `crates/carrick-vmm-hvf/src/runtime.rs` (`HvfHostBackend::pre_loop_setup` ~:1610) — start the reaper in the root when atomic permits are enabled.
- Reference (do not change the cap math): `host_facts.rs` (`physical_cpu_count`), `darwin_kqueue.rs` (`Kevent::proc_exit`), `host_signal.rs`/`io_wait.rs` (the `waitid(WNOWAIT)` pattern).

---

## Task 1 — Tokenized generation-stamped slot table (source of truth)

**Files:** Modify `crates/carrick-vmm-hvf/src/trap.rs`. Test: `vm_create_admission_tests` (~:4522).

**Interfaces (Produces):** `struct PermitRegion` over a fork-shared mmap: `magic/version` header, `next_generation: AtomicU32`, `slots: [AtomicU64; MAX_SLOTS]` each packed `state(free|acquiring|registered) | owner_pid:u32 | generation`. `fn atomic_permit_enabled() -> bool`. `fn acquire(budget, pid) -> Option<PermitToken>` (CAS a free slot → `acquiring(pid, gen)`; count occupied (`acquiring|registered`) slots; if > budget, CAS that exact `(slot,gen)` back to free + return None to trigger backoff; else return the token). `struct PermitToken { slot: u16, generation: u32, owner_pid: u32 }`. `fn register(vcpu_id, token)` (CAS slot `acquiring→registered` for the same `(pid,gen)`; insert `vcpu_id→token` into a process-local `HashMap`). `fn release_token(vcpu_id)` (remove local map entry; if present CAS that exact `(slot,gen)`→free; else no-op on the shared table). `fn reclaim_owner(pid, generation?) -> usize` (used by Tasks 2/3: CAS matching `(pid[,gen])` registered/acquiring slots → free). `fn occupied() -> usize` (derived count = non-free slots; there is no separate `live` counter). MAX_SLOTS = HVF vcpu ceiling (~64).

- [ ] **Step 1: Port only the useful parts of the 3b patch** (`.superpowers/sdd/task-3b-mech-atomic.patch`): the `MAP_ANON|MAP_SHARED` region setup, the injectable-for-test constructor, and the cap-math preservation. **Do NOT apply it mechanically** — it uses a bare `AtomicUsize` count (the leak). Build the packed-slot `PermitRegion` instead.
- [ ] **Step 2: RED — the state-machine unit tests** (in `vm_create_admission_tests`, over a private test region):
```rust
#[test] fn acquire_cannot_leave_an_unowned_count() {
    let r = PermitRegion::new_anon_for_test();
    let t = r.acquire(4, std::process::id()).unwrap();   // slot published owned BEFORE any count-only state
    assert_eq!(r.occupied(), 1);
    assert_eq!(r.slot_state(t.slot), SlotState::Acquiring); // owner+gen visible even pre-register
    // a crash here is reclaimable: reap by owner finds the acquiring slot
    r.force_owner_for_test(t.slot, 999_999_999, t.generation);
    assert_eq!(r.reclaim_owner(999_999_999, None), 1);
    assert_eq!(r.occupied(), 0);
}
#[test] fn vcpu_destroyed_of_unregistered_vcpu_does_not_release_a_permit() {
    let r = PermitRegion::new_anon_for_test();
    let t = r.acquire(4, std::process::id()).unwrap();
    r.register(100, t);                        // vcpu 100 holds the permit
    r.release_token(999);                      // an UNPERMITTED sibling vcpu teardown
    assert_eq!(r.occupied(), 1);               // must NOT free vcpu 100's permit
    r.release_token(100);
    assert_eq!(r.occupied(), 0);
}
#[test] fn release_is_generation_checked() {
    let r = PermitRegion::new_anon_for_test();
    let t = r.acquire(4, std::process::id()).unwrap();
    r.register(1, t);
    let stale = PermitToken { generation: t.generation.wrapping_sub(1), ..t };
    assert!(!r.try_free_exact_for_test(stale)); // a stale token/event cannot free a newer owner
    assert_eq!(r.occupied(), 1);
}
#[test] fn fork_child_reset_clears_local_only() {
    let r = PermitRegion::new_anon_for_test();
    let t = r.acquire(4, std::process::id()).unwrap(); r.register(1, t);
    r.reset_local_after_fork_child();          // child clears local map
    assert!(r.local_token(1).is_none());
    assert_eq!(r.occupied(), 1);               // parent's shared slot untouched
}
```
Run `cargo test -p carrick-vmm-hvf vm_create_admission_tests --lib` → fails (types/fns don't exist).
- [ ] **Step 3: Implement** the packed-slot region + acquire/register/release_token/reclaim_owner/reset per the Interfaces and the companion review §"Recommended replacement design". Use one packed `AtomicU64` per slot (avoids torn multi-field state). `next_generation.fetch_add(1)` per acquire. Wire `create_vm_with_admission`/`create_vcpu_with_permit`/`vcpu_destroyed`/`reset_*_after_fork_child` to the atomic path when `atomic_permit_enabled()`, keeping the flock path intact for the default.
- [ ] **Step 4: GREEN + offline gates** (all tests; `cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings`; `just fmt-check`; `just build`). Verify with a `libc::fork()` test that the region address is inherited across fork.
- [ ] **Step 5: Commit** — `feat(hvf): tokenized generation-stamped atomic vcpu permit slots (flag-gated)`.

---

## Task 2 — Mandatory EVFILT_PROC supervisor + periodic backstop

**Files:** Create `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs`. Modify `crates/carrick-vmm-hvf/src/runtime.rs` (`pre_loop_setup` ~:1610). Test: unit test in the new file + a proc-event integration check.

**Interfaces (Consumes Task 1):** `PermitRegion::reclaim_owner(pid, gen)`, the slot table's owner set. **Produces:** `fn start_vcpu_permit_reaper()` (idempotent; spawns the root supervisor thread) + a `crate::trap::start_vcpu_permit_reaper` re-export.

The root process (`host_proc::set_root_guest_pid`) is the supervisor. `EVFILT_PROC` is MANDATORY (not conditional) — `kill(pid,0)` is not a crash-reclaim equivalent (zombies + PID reuse).

- [ ] **Step 1: RED** — a supervisor unit test: register a `Kevent::proc_exit` on a short-lived child that `_exit`s; assert the reaper reclaims that `(pid,gen)`'s slots on the delivered `NOTE_EXIT`; AND a register-after-exit test: a child that exits BEFORE registration is still reclaimed via the post-register `waitid(WNOWAIT|WNOHANG)` / `ESRCH` path. Run `cargo test -p carrick-vmm-hvf permit_reaper` → fails.
- [ ] **Step 2: Implement the supervisor** in `vcpu_permit_reaper.rs`: own one `Kqueue`; poll the slot table for new `(owner_pid, generation)`; register `Kevent::proc_exit(pid)` (kqueue.rs:195-214, already one-shot `EVFILT_PROC|NOTE_EXIT|NOTE_EXITSTATUS`); **immediately after a successful register, do a non-consuming `waitid(WNOWAIT|WNOHANG)`** (host_signal.rs pattern) so an exit-before-register is not stranded; on `EV_ERROR`/`ESRCH` reclaim that generation-stamped slot at once; on `NOTE_EXIT` reclaim slots matching the watched `(pid,generation)`. Keep a **periodic backstop scan** (a low-frequency sweep, e.g. every 250 ms) ONLY for missed registrations / kqueue setup failure — the primary detector is the proc event, NOT `kill(pid,0)`.
- [ ] **Step 3: Start it in the root** at `HvfHostBackend::pre_loop_setup` (runtime.rs:~1610): `if crate::trap::atomic_permit_enabled() { crate::trap::start_vcpu_permit_reaper(); }`. (Do NOT edit the generic loop body / `threaded_loop.rs` — the generic loop must not grow HVF knowledge. Region init stays in the admission path per Task 1, since the initial VM is created before the loop.)
- [ ] **Step 4: GREEN + offline gates.**
- [ ] **Step 5: Commit** — `feat(hvf): EVFILT_PROC death-reclaim supervisor for atomic permits`.

---

## Task 3 — Cooperative release before fork-child `_exit`

**Files:** Modify `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:295` (the `process_exit_cleanup` no-op override).

The runtime already calls `engine.process_exit_cleanup()` on normal fork-child exit and signal death (`vcpu_loop/mod.rs:1469/1500/1884`), before `_exit` skips Rust drops. HVF overrides it as a no-op because the flock path was fd-lifetime-bound. For the atomic path this is the fast path that shrinks the churn window (leaving the supervisor for HARD death only).

- [ ] **Step 1: RED** — the exec/fork churn probe `conformance-probes/src/bin/execpermitchurn.rs`: fork N children that each `_exit` immediately; parent reaps; loop. With `CARRICK_HVF_ATOMIC_PERMIT=1`, assert the region's `occupied()` returns to baseline after each round (expose via a debug hook or `carrick trace` of the slot table). Pre-fix (no cooperative release, reaper-only) the count sits high between reaps.
- [ ] **Step 2: Implement** an atomic-only `process_exit_cleanup` that releases all slots owned by the current PID (or at least this engine's registered token), **idempotent** with `vcpu_destroyed` and the supervisor via the generation check. It must NOT run on the parent after a fork reset.
- [ ] **Step 3: GREEN** — the churn probe's `occupied()` returns to baseline promptly (not dependent on the backstop interval); offline gates.
- [ ] **Step 4: Commit** — `feat(hvf): cooperative atomic-permit release on fork-child exit`.

---

## Task 4 — Exec: PROVE no leak / no double-release (proof task, code only if it fails)

**Files:** Modify `crates/carrick-vmm-hvf/src/trap.rs` ONLY if the proof fails.

The exec-leak premise in the prior draft was stale: the current code destroys the inherited vCPU and calls `vcpu_destroyed` BEFORE the ungated `ExecveRebuild` (trap.rs:3544-3556), and `ExecveRebuild` has no budget so it acquires nothing. So after Task 1's tokenization, exec should already release correctly via `vcpu_destroyed(vcpu_id)`.

- [ ] **Step 1: PROVE it** — with `CARRICK_HVF_ATOMIC_PERMIT=1`, run the churn probe in `execve` mode (children `execve(/bin/true)` instead of `_exit`) and assert `occupied()` returns to baseline. Read the exec teardown path (trap.rs:3544-3556) and confirm the destroyed pre-exec `vcpu_id` is in the local token map so `release_token` runs.
- [ ] **Step 2:** If the proof passes, add ONLY a regression test asserting exec does not leak. **Do NOT add an explicit `release_token`/`release_atomic` on the exec path** unless the proof shows the tokenized path bypasses `vcpu_destroyed` — an extra release would double-free.
- [ ] **Step 3: Commit** — `test(hvf): prove execve rebuild releases atomic permit via vcpu_destroyed` (or, only if a real bypass was found, `fix(hvf): release atomic permit on execve rebuild`).

---

## Task 5 — Integration validation (phases separate; NO cap change here)

**Files:** Modify `scripts/conformance/vcpu-admission-gate.sh` (env passthrough for `CARRICK_HVF_ATOMIC_PERMIT`).

- [ ] **Step 1: Atomic gate** — `CARRICK_HVF_ATOMIC_PERMIT=1 bash scripts/conformance/vcpu-admission-gate.sh`: cpython-queue/node-v8-smoke/node-app-smoke/go-os_exec all MATCH, none TIMEOUT (the exact gate that caught 3b). Watch for host-UI instability.
- [ ] **Step 2: Fork-storm** — `CARRICK_HVF_ATOMIC_PERMIT=1 cargo run -q -p carrick-conformance -- --tier full --workers 8 --flake-retries 0 --suite ltp-msgstress01 --suite ltp-futex_cmp_requeue01 --jsonl /tmp/opt3-storm.jsonl` × 3: zero CRASH/TIMEOUT/HV_NO_RESOURCES/HV_BUSY.
- [ ] **Step 3: Commit** — `test(hvf): validate atomic vcpu permit under gate + fork-storm`.
- **Decision gate:** if Steps 1-2 pass across 3 runs, the atomic permit is a viable default (a follow-up flips the flag). If any step regresses, the flag stays off and flock ships — **the spike still delivered the measurement.** Do NOT touch `CONSERVATIVE_GLOBAL_VM_CAP` in this plan.

---

## Follow-ups (separate plans, gated on this spike)
- **Cap-raise experiment** (the "more concurrent processes" payoff): with the atomic permit proven, a SEPARATE temporary/env-gated patch raises `CONSERVATIVE_GLOBAL_VM_CAP` 4→physical cores and re-checks `ltp-waitpid13` + the fork-storm gate. Never committed together with the atomic permit (ambiguity).
- **Option 4** (cap-free, reclaim-only): only after this spike + prompt reclaim, gate `create_vm_with_admission` behind `CARRICK_HVF_NO_XPROC_PERMIT=1` and stress the fork-storm pre-block window. Firecracker runs cap-free but never faces that window, so this measurement — not precedent — clears Option 4.

## Self-Review
- **Companion-review coverage:** ownerless-count leak → Task 1 slot-is-source-of-truth ✓; token-guarded release → Task 1 `release_token` by vcpu_id + the unregistered-doesn't-release test ✓; `kill(pid,0)` weak → Task 2 mandatory `EVFILT_PROC` + `waitid(WNOWAIT)` + generation guard ✓; cooperative `_exit` → Task 3 ✓; wrong integration point → Task 2 uses `pre_loop_setup`, not `threaded_loop`/`crate::hvf` ✓; stale exec premise → Task 4 downgraded to proof ✓; cap-raise conflation → moved to Follow-ups, Global Constraint forbids committing it here ✓.
- **Placeholders:** the genuine unknowns (backstop interval; whether cooperative-exit alone suffices vs relies on the supervisor) are measured in Task 3/5, not hand-waved. Task 4 is explicitly proof-first.
- **Type consistency:** `PermitRegion`, `PermitToken{slot,generation,owner_pid}`, `acquire`, `register`, `release_token`, `reclaim_owner`, `occupied`, `atomic_permit_enabled`, `start_vcpu_permit_reaper` used consistently across tasks.
