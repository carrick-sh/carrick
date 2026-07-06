# Option 3 — Crash-safe atomic vCPU admission permit (design spike) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace carrick's cross-process HVF vCPU-admission file-lock permit with a fork-shared shared-memory atomic counter that has **cheaper acquire** (a userspace CAS vs `open`+`flock`+backoff) while preserving the file-lock's load-bearing **crash/death-reclaim**, via a supervisor that reclaims leaked slots on process death (periodic PID-liveness reaper, then optionally prompt `EVFILT_PROC/NOTE_EXIT`) plus an explicit exec-path release.

**Architecture:** This is a **design SPIKE gated behind `CARRICK_HVF_ATOMIC_PERMIT=1`** — the `flock` permit stays the default and the fallback until the atomic path proves it survives the fork-storm/many-thread gate. It builds directly on the already-written atomic-counter patch (`.superpowers/sdd/task-3b-mech-atomic.patch`), which failed *only* because it lost death-reclaim (fork-child exit/exec teardown skipped the decrement → orphaned counts pinned the pool → node worker_threads 447× timeout). The fix is a race-proof reaper in the root process (`host_proc::set_root_guest_pid` marks it) that scans the shared region's slot→owner-PID table and reclaims any dead owner (`kill(pid,0)==ESRCH`), backing the whole thing on the same `min(hvf_cap, physical_cores)` cap math (unchanged, per the maintainer's kept physical-core cap).

**Tech Stack:** Rust 2024; macOS+aarch64 HVF backend (`crates/carrick-vmm-hvf`); `mmap(MAP_ANON|MAP_SHARED)`, `AtomicU64`/`AtomicUsize`, `libc::kill(pid,0)` liveness, `crate::darwin_kqueue::Kqueue` (`EVFILT_PROC`/`NOTE_EXIT`); `crate::host_proc` (root pid / guest-pid tracking); the Phase-3a gate `scripts/conformance/vcpu-admission-gate.sh`.

**Research basis:** `docs/2026-07-05-admission-reclaim-research.md` (macOS has no robust futex/mutex/OFD lock; `EVFILT_PROC/NOTE_EXIT` is the native death-watch; leases/reapers are the race-proof backstop; Firecracker runs cap-free but never faces our fork-storm pre-block window — hence Option 4 stays gated).

## Global Constraints
- **KEEP the cap math** unchanged: `vcpu_gate::budget_from_limits = min(hvf_cap, physical_cores)` (`trap.rs:1034`) and `global_permit_budget_from_mn` per-class budgets (`trap.rs:726`; Initial/SharedWaitResume=`min(mn,4)`, ForkRebuild{vfork:false}=`mn`, vfork/execve=`None`). This task changes the *mechanism*, not the budget.
- **Gated + fallback:** all new behavior behind `CARRICK_HVF_ATOMIC_PERMIT=1`; unset → the current `flock` permit, byte-for-byte. The atomic path must never become the default in this plan.
- **The atomic region must be created before any fork** (so children inherit it via `MAP_SHARED`) and keyed per-run by `CARRICK_RUN_ID` if `shm_open` is used (prefer anon+MAP_SHARED — inherited across fork, no name/cleanup).
- **Crash-safety is the acceptance bar:** a permit holder that dies by exit/SIGKILL/SEGFAULT **or** replaces its image via `execve` must not permanently consume a slot.
- macOS+aarch64 only (`#[cfg(all(target_os = "macos", target_arch = "aarch64"))]`), matching the existing permit code.
- Never run carrick and the Docker oracle concurrently. Never `git commit --no-verify`. Typed domain values at boundaries.
- **Validation is mandatory and specific:** every phase that changes admission re-runs `scripts/conformance/vcpu-admission-gate.sh` (4 fragile workloads must stay MATCH) AND the fork-storm suites (`ltp-msgstress01`, `ltp-futex_cmp_requeue01` at `--workers 8`) with `CARRICK_HVF_ATOMIC_PERMIT=1`, watching for HV_NO_RESOURCES/HV_BUSY/timeout AND host-UI (WindowServer/Finder) instability. If the atomic path regresses the gate, STOP — flock is the shipped fallback.

---

## File Structure
- Modify `crates/carrick-vmm-hvf/src/trap.rs` — the whole permit subsystem (`GlobalVcpuPermit*`, `acquire/register/release_*`, `reset_*_after_fork_child`, `create_vm_with_admission`, `create_vcpu_with_permit`). Add the atomic region + slot→owner-PID table + the `CARRICK_HVF_ATOMIC_PERMIT` dispatch that chooses flock vs atomic.
- Create `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs` — the supervisor: the periodic PID-liveness reaper and (Phase D) the `EVFILT_PROC` prompt-reclaim, plus its start/stop lifecycle. One file, one responsibility (death-reclaim of the shared permit region).
- Modify `crates/carrick-runtime/src/threaded_loop.rs` (~:142, where `host_proc::set_root_guest_pid` runs) — start the reaper in the root process when the atomic path is enabled.
- Reference only (read, don't change the cap math): `crates/carrick-host/src/host_facts.rs` (`physical_cpu_count`), `crates/carrick-vmm-hvf/src/darwin_kqueue.rs` (`Kqueue`), `crates/carrick-runtime/src/host_proc.rs` (root pid / `is_guest_process` / `pid_info`).

---

## Task 1 — Shared-memory atomic permit region + owner-PID table (behind the flag)

**Files:** Modify `crates/carrick-vmm-hvf/src/trap.rs` (`GlobalVcpuPermit*` region ~:735-897, `create_vm_with_admission` ~:939, `create_vcpu_with_permit` ~:900, `vcpu_destroyed` ~:1070). Test: `trap.rs` `vm_create_admission_tests` (~:4522).

**Interfaces:**
- Produces: `fn atomic_permit_enabled() -> bool` (reads `CARRICK_HVF_ATOMIC_PERMIT`); a `PermitRegion` mapped once pre-fork holding `live: AtomicUsize` + a fixed-size `slots: [AtomicU32; MAX_SLOTS]` table of owner PIDs (0 = free); `fn try_acquire_atomic(budget) -> bool` (CAS-increment `live` while `< budget`, then claim a free slot with the caller's `getpid()`); `fn release_atomic(pid)` (clear one slot owned by `pid`, `fetch_sub(1)`); `fn reclaim_dead_slots() -> usize` (used by Task 2). MAX_SLOTS = the HVF cap ceiling (~64).

**Start from the existing patch:** `.superpowers/sdd/task-3b-mech-atomic.patch` already converts `GlobalVcpuPermit` to a zero-sized marker + a fork-shared count with `try_acquire`/`release`/`release_unregistered` + a `HashSet<u64>` of live vcpu-ids and unit tests (7/7 passed). Apply it as the base, THEN extend it with the **slot→owner-PID table** (the patch had only a bare count — the reaper needs per-PID ownership to know how much to reclaim).

- [ ] **Step 1: Apply the base atomic patch** and confirm its unit tests compile: `git apply .superpowers/sdd/task-3b-mech-atomic.patch` then `cargo test -p carrick-vmm-hvf vm_create_admission_tests --lib`. If it no longer applies cleanly (trap.rs shifted since it was saved), port the change by hand — the shape is: `GlobalVcpuPermit` → unit struct; a `fn global_vcpu_count() -> &'static AtomicUsize` backed by `mmap(MAP_ANON|MAP_SHARED)` created in a `OnceLock` before any guest fork; `try_acquire` CAS-increments while `< budget`; `release`/`release_unregistered` `fetch_sub`.
- [ ] **Step 2: RED — write the owner-table test** in `vm_create_admission_tests`:
```rust
#[test]
fn atomic_permit_records_and_reclaims_owner_pids() {
    let region = PermitRegion::new_anon_for_test(); // test ctor over a private mmap
    let me = std::process::id();
    assert!(region.try_acquire(4, me));            // slot claimed for `me`
    assert_eq!(region.live(), 1);
    assert_eq!(region.owner_slot_count(me), 1);
    // a slot owned by a definitely-dead pid must be reclaimable:
    region.force_claim_for_test(999_999_999, /*count*/ 2); // simulate leaked slots
    assert_eq!(region.live(), 3);
    let reclaimed = region.reclaim_dead_slots();    // 999999999 is not alive
    assert_eq!(reclaimed, 2);
    assert_eq!(region.live(), 1);                   // only `me`'s slot remains
}
```
Run `cargo test -p carrick-vmm-hvf atomic_permit_records_and_reclaims_owner_pids --lib` → fails (no owner table / `reclaim_dead_slots` yet).
- [ ] **Step 3: Implement the owner table.** Add `slots: [AtomicU32; MAX_SLOTS]` to the mmap'd `PermitRegion` (owner PID per slot, 0 = free). `try_acquire(budget, pid)`: CAS-increment `live` while `< budget`; on success, CAS-claim the first `slots[i]==0` to `pid` (if none free — shouldn't happen since `live<=budget<=MAX_SLOTS` — undo the increment and return false). `release(pid)`: find one `slots[i]==pid`, CAS it to 0, `live.fetch_sub(1)`. `reclaim_dead_slots()`: for each `slots[i]==pid` where `pid!=0 && libc::kill(pid as i32, 0) < 0 && errno==ESRCH`, CAS it to 0 and `live.fetch_sub(1)`; return the count. Use `Ordering::AcqRel` for the CAS, `Acquire`/`Release` for loads/stores. Route acquire/register/release through `atomic_permit_enabled()`: true → the atomic path; false → the existing flock path (keep it intact).
- [ ] **Step 4: GREEN** — the new test passes; `cargo test -p carrick-vmm-hvf vm_create_admission_tests --lib` (all, incl. the ported patch tests) green; `cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings`; `just fmt-check`; `just build`.
- [ ] **Step 5: Commit** — `feat(hvf): fork-shared atomic vcpu permit with owner-pid table (flag-gated)`. (Trailers per Global Constraints.)

**Gotcha:** the region MUST be created before the first guest fork. Put the `OnceLock` init at engine/VM bring-up (before `run_oci` forks a guest), not lazily on first acquire (a fork child's first acquire would map a *private* region). Verify by asserting the same region address is inherited across a `libc::fork()` in a test.

---

## Task 2 — The race-proof reaper (the death-reclaim that fixes the 3b leak)

**Files:** Create `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs`. Modify `crates/carrick-runtime/src/threaded_loop.rs` (~:142) to start it in the root. Test: unit test in the new file.

**Interfaces:**
- Consumes: `PermitRegion::reclaim_dead_slots()` (Task 1).
- Produces: `fn start_reaper()` (spawns a daemon thread that, every `REAP_INTERVAL_MS`, calls `reclaim_dead_slots()`; idempotent via a `OnceLock`/`AtomicBool`), `const REAP_INTERVAL_MS: u64`.

The root process (`host_proc::set_root_guest_pid(std::process::id())`, threaded_loop.rs:142) is the natural supervisor — it outlives the fork tree and can see all guest PIDs. Fork children do NOT start a reaper (only the root does); the shared region + `kill(pid,0)` liveness make the root's single reaper authoritative for the whole tree.

- [ ] **Step 1: RED — reaper reclaims a dead owner within one interval.** Test: build a private `PermitRegion`, `force_claim_for_test(dead_pid, 1)`, spawn the reaper loop against it, sleep `2*REAP_INTERVAL_MS`, assert `live()==0`. Run `cargo test -p carrick-vmm-hvf reaper_reclaims_dead_owner` → fails (no reaper).
- [ ] **Step 2: Implement `start_reaper`** — a named daemon `std::thread` that loops `{ region.reclaim_dead_slots(); sleep(REAP_INTERVAL_MS) }`, guarded by an `AtomicBool` so it starts once. Start it only when `atomic_permit_enabled()`. `REAP_INTERVAL_MS`: start at **20** (a value the fork-storm gate will tune — see the spike note).
- [ ] **Step 3: Wire it into the root** at threaded_loop.rs:~142, right after `set_root_guest_pid`, `if crate::hvf::atomic_permit_enabled() { crate::hvf::start_vcpu_permit_reaper(); }` (expose a thin re-export from carrick-vmm-hvf). Only the root reaches this path.
- [ ] **Step 4: GREEN + offline gates** (test passes; clippy/fmt/build).
- [ ] **Step 5: Commit** — `feat(hvf): periodic reaper reclaims dead-owner vcpu permits`.

**SPIKE — this is the load-bearing uncertainty (measure, don't guess):** the reaper interval trades reclaim latency against scan cost. Too slow and a rapid death-churn workload (node worker_threads) pins the pool between reaps → the exact 447× timeout the flock version avoided (flock reclaims *instantly* on close). **After Step 4, run the fork-storm validation** (`CARRICK_HVF_ATOMIC_PERMIT=1 scripts/conformance/vcpu-admission-gate.sh` + `--workers 8` msgstress01/futex_cmp_requeue01). If node still times out at 20ms, that is the signal that a periodic reaper alone is insufficient and Task 4 (prompt `EVFILT_PROC` reclaim) is REQUIRED, not optional. Record the measured churn-vs-interval result in the report.

---

## Task 3 — Explicit permit release on execve (the exec-teardown leak)

**Files:** Modify `crates/carrick-vmm-hvf/src/trap.rs` — the `ExecveRebuild` path (`create_vm_with_admission(..., VmCreateAdmission::ExecveRebuild)` ~:3555) and where the old VM is torn down before it.

`NOTE_EXIT` does not fire on `execve` (the PID survives — Linux reclaims via `mm_release→exit_robust_list`, macOS has no equivalent). So the exec rebuild MUST release the old VM's permit explicitly. This is the second half of the 3b leak ("fork-child exit/**exec** teardown never ran the destructor").

- [ ] **Step 1: RED — an exec across a held permit must not leak.** A hostless-ish test is hard here; instead use the fork-storm-adjacent differential: with `CARRICK_HVF_ATOMIC_PERMIT=1`, run a guest that repeatedly `fork()`+`execve()`s in a tight loop (a small conformance probe `conformance-probes/src/bin/execpermitchurn.rs`: fork N children that each immediately `execve(/bin/true)`; parent reaps; repeat) and assert the shared `live` count returns to baseline after each round (expose it via a debug probe or `carrick trace` of `VCPU_LIVE`). Pre-fix (exec release missing) the count climbs and admission eventually stalls.
- [ ] **Step 2: Read the exec rebuild** (trap.rs ~:3540-3560) — find where the old VM/vCPU is destroyed on exec. Confirm whether `vcpu_destroyed` (→ `release`) runs on that path for the atomic case; the 3b finding says it does NOT. Add an explicit `release_atomic(getpid())` (or route the old-VM teardown through `vcpu_destroyed`) BEFORE the `ExecveRebuild` acquire, so the exec releases exactly the permit it held.
- [ ] **Step 3: GREEN** — the churn probe's `live` returns to baseline; offline gates.
- [ ] **Step 4: Commit** — `fix(hvf): release atomic vcpu permit on execve rebuild`.

**Gotcha:** `ExecveRebuild`'s own budget is `None` (ungated) — so exec re-acquires nothing; it only needs to RELEASE the pre-exec permit. Don't double-release (guard: release only if the pre-exec VM actually held a permit under the atomic path).

---

## Task 4 — (Conditional) Prompt EVFILT_PROC/NOTE_EXIT reclaim

**Do this ONLY if Task 2's spike showed the periodic reaper's latency causes a gate regression.** If the 20ms reaper passes the fork-storm gate, SKIP this task and record that the reaper alone suffices.

**Files:** Modify `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs`. Reference `crates/carrick-vmm-hvf/src/darwin_kqueue.rs` (`Kqueue`).

- [ ] **Step 1:** In the root reaper, own a `Kqueue`. When a new owner PID appears in the region (the reaper notices a slot it hasn't watched), register `EV_ADD|EVFILT_PROC` with `fflags=NOTE_EXIT` for that PID. On `kevent` delivery of `NOTE_EXIT`, immediately `reclaim` that PID's slots (prompt, ~0 latency).
- [ ] **Step 2: Handle the register-after-dead race** (finding 5's acknowledged Firecracker race): `kevent(EV_ADD, EVFILT_PROC)` on an already-exited PID returns `ESRCH` — on `ESRCH`, reclaim that PID's slots immediately. The periodic `reclaim_dead_slots()` from Task 2 stays as the belt-and-suspenders backstop for any PID that died in the registration gap.
- [ ] **Step 3:** Re-run the fork-storm gate with prompt reclaim; confirm the churn timeout is gone. Offline gates.
- [ ] **Step 4: Commit** — `feat(hvf): prompt EVFILT_PROC death-reclaim for atomic vcpu permits`.

**Gotcha:** kqueue registration is not free at fork-storm scale (one `EV_ADD` per new owner PID). Reuse the existing `darwin_kqueue::Kqueue` abstraction and a single kq in the root; do NOT create a kq per PID. The reaper already knows the owner set from the region table, so it registers incrementally.

---

## Task 5 — End-to-end validation + the raise-the-cap experiment

**Files:** Modify `scripts/conformance/vcpu-admission-gate.sh` (accept an env passthrough so it can run with `CARRICK_HVF_ATOMIC_PERMIT=1`). Reference the fork-storm suites.

- [ ] **Step 1: Full gate under the atomic path** — `CARRICK_HVF_ATOMIC_PERMIT=1 bash scripts/conformance/vcpu-admission-gate.sh`: all 4 fragile workloads (cpython-queue, node-v8-smoke, node-app-smoke, go-os_exec) MATCH, none TIMEOUT (this is the exact gate that caught the 3b leak). Watch for host-UI instability.
- [ ] **Step 2: Fork-storm stress** — `CARRICK_HVF_ATOMIC_PERMIT=1 cargo run -q -p carrick-conformance -- --tier full --workers 8 --flake-retries 0 --suite ltp-msgstress01 --suite ltp-futex_cmp_requeue01 --jsonl /tmp/opt3-storm.jsonl` × 3 runs: zero CRASH/TIMEOUT/HV_NO_RESOURCES/HV_BUSY.
- [ ] **Step 3: The payoff experiment (why we did this)** — with the cheaper atomic acquire proven safe, raise `CONSERVATIVE_GLOBAL_VM_CAP` from 4 toward physical cores (10) AND re-check `ltp-waitpid13` (the suite that needs ~11 concurrent processes and timed out under the cold-start cap of 4): `CARRICK_HVF_ATOMIC_PERMIT=1 cargo run ... --suite ltp-waitpid13`. Record whether the higher cap closes it AND the fork-storm gate still passes (the two must both hold). This is the concrete win that motivated Option 3.
- [ ] **Step 4: Commit** — `test(hvf): validate atomic vcpu permit under fork-storm + raised cap`.

**Decision gate:** if Steps 1-2 pass, the atomic permit is a viable default and the maintainer can flip `CARRICK_HVF_ATOMIC_PERMIT` on (a follow-up). If Step 3 shows the raised cap safely closes waitpid13-class workloads without HV/host instability, that answers the "more concurrent processes" question. If any step regresses, the flag stays off and flock ships — **the spike still delivered the measurement.**

---

## Notes toward Option 4 (out of scope here, recorded for the follow-up)
Option 4 (drop the cap entirely, reclaim-only) is unlocked ONLY after this spike, and needs its own measurement: with the atomic path + prompt reclaim, gate `create_vm_with_admission` behind `CARRICK_HVF_NO_XPROC_PERMIT=1` (budget → `None` for all classes) and stress the fork-storm pre-block window (`--workers 8` msgstress01/futex fanout × 3). PASS = zero HV_NO_RESOURCES across the burst where every child is runnable before any blocks. Firecracker runs cap-free but never faces this window (its VMs are externally orchestrated), so this measurement — not precedent — is what clears Option 4.

---

## Self-Review
- **Spec coverage:** cheaper acquire (Task 1 atomic CAS) ✓; preserve death-reclaim (Task 2 reaper + Task 4 prompt EVFILT_PROC) ✓; exec-teardown leak (Task 3) ✓; keep cap math (Global Constraints + Task 5 raises only the *conservative* cap, deliberately) ✓; gated+fallback (flag throughout) ✓; validation on the exact gate that caught 3b (Task 5) ✓; Option-4 path recorded ✓.
- **Placeholder scan:** the two genuine unknowns (reaper interval; whether prompt reclaim is needed) are marked as SPIKE/measure steps with concrete pass criteria, not hand-waves — appropriate for a spike. Task 4 is explicitly conditional on Task 2's measurement.
- **Type consistency:** `PermitRegion`, `try_acquire(budget,pid)`, `release(pid)`, `reclaim_dead_slots()`, `atomic_permit_enabled()`, `start_reaper()` are used consistently across tasks.
