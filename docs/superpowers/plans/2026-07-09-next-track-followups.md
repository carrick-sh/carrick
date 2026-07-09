# Next Track Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the five Next Track items from `docs/2026-07-09-mt-residency-lease-evidence.md`: (1) resident-VM accounting so the fork admission gate sees hard-slot residency, (2) the cluster-B root-cause reproducer (epoll/AF_UNIX manager shape), (3) skip-resume-on-idle-TimedOut (zero-churn idle endpoint), (4) an xsig-ring `target_tid` for cross-process thread-directed sends, (5) the epoll-ET p50 pre-existing-debt bisect.

**Architecture:** The resident-VM tracker is a second generation-stamped atomic slot table (reusing `PermitRegion` over a new `KernelArena` section) — occupancy stays derived from slots, death-reclaimed by the existing reaper; no free-running counter to drift. The fork gate probes that table with a 10 s bound (symmetric with the post-fork `HV_NO_RESOURCES` backpressure). The idle endpoint is an inner re-wait loop in the two slicing wait arms that re-arms the wait without the resume/re-park round trip. The xsig slot grows a `target_ns_tid` field (same-binary fork-shared ring — layout change is compat-safe). Cluster B gets a test-only veto-bypass knob plus a manager-shaped probe. The bisect is a `git bisect run` predicate over `perf_epoll_pipe_loop`.

**Tech Stack:** Rust workspace (`carrick-vmm-hvf`, `carrick-kernel`, `carrick-runtime`, `carrick-thread`, `carrick-signal-core`, `conformance-probes`), HVF/macOS arm64, dtrace, `scripts/run-probe.sh` conformance harness, `scripts/build-signed.sh`.

## Global Constraints

- NEVER `git commit --no-verify`; run `cargo fmt` before every commit (formatting is enforced by hooks).
- Never run a carrick guest and the Docker oracle concurrently (`scripts/run-probe.sh` sequences its phases itself; verification runs use it or run phases strictly one at a time).
- Verification runs are ONE-SHOT and `CARRICK_RUN_ID`-scoped; no retry-until-green. If a run diverges from the expectation, record the divergence as an inline `> **AMENDMENT**` in this plan and stop for review — do not re-roll.
- Probes print deterministic booleans via `report!` only — never counts, times, or pids.
- The resident-VM table must have NO free-running counter: occupancy is derived from generation-stamped slots and reclaimed by the death reaper (the drift-free invariant documented at `crates/carrick-vmm-hvf/src/trap.rs:1186`).
- New env knobs: `CARRICK_MT_VM_LEASE_FDBACKED` is test-only and default-OFF. No default behavior change ships without its battery.
- Regression floors that must hold at every task boundary: `procladder_mt` @160 lease-ON GREEN; `procladder`, `procladder_mt`, `procladder_mixed` MATCH via `scripts/run-probe.sh`; `perf_fork` p50 ≤ 2.5 ms; `perf_wait_pipe_pingpong` p50 ≤ 50 µs; `perf_futex_pingpong` in the 31–34 µs band.
- Perf and bisect runs need a quiet host (no concurrent lanes, no Docker). Classify any load-coupled observation per the three buckets in the evidence doc (real race / time assumption / measurement contamination) — never dismiss as flake.
- Do not loop mass `carrick run` HVF storms unthrottled (WindowServer/Finder crash risk); the verification commands below are single bounded runs.
- Build the runnable binary with `scripts/build-signed.sh` (a bare `cargo build --release` strips the hypervisor entitlement).

## Background for the implementer (read once)

- Evidence doc: `docs/2026-07-09-mt-residency-lease-evidence.md` (§Next Track is the spec for this plan). Prior campaign plan: `docs/superpowers/plans/2026-07-08-mt-residency-lease-and-pump-stop.md`.
- Permit machinery: `crates/carrick-vmm-hvf/src/trap.rs` — `SharedPermitTable` (trap.rs:1104), `PermitRegion` (trap.rs:1122), slot bit-layout `atomic_permit_slot` (trap.rs:1023), acquire (trap.rs:1221), `register` (trap.rs:1265), `release_token` (trap.rs:1288), `reclaim_owner` (trap.rs:1336), `reset_local_after_fork_child` (trap.rs:1373), `cooperative_release_local` (trap.rs:1394), `new_shared_global` (trap.rs:1171), `permit_region()` (trap.rs:1491), reaper bridge (trap.rs:1454), `start_vcpu_permit_reaper` (trap.rs:1482), `acquire_atomic_vcpu_permit` (trap.rs:1537), `probe_fork_vm_admission` (trap.rs:1823, with the KNOWN BLIND SPOT doc), `create_vm_with_admission` (trap.rs:1767), backpressure PARK 25 ms / MAX_WAIT 10 s (trap.rs:1668), `ADMISSION_PERMIT_MAX_WAIT` 60 s (trap.rs:879), `GLOBAL_VCPU_CEILING` 120 (trap.rs:782).
- VM residency transitions: create funnel = `create_vm_with_admission` Ok arm (trap.rs:1790). The four `hv_vm_destroy()` sites: `shared_wait_park` (trap.rs:3853), `release_vm_after_reclaim_park` (trap.rs:3880), `fork_prepare_and_teardown` (trap.rs:4237), execve rebuild (trap.rs:4686). vCPU-only park path that frees a permit but keeps the VM: `reclaim_park` → `vcpu_destroyed` (trap.rs:1960).
- Arena: `crates/carrick-kernel/src/arena.rs` — `ArenaLayout { header, permits, processes }` (arena.rs:44), `ARENA_VERSION = 2` (arena.rs:15), `publish_fresh_header` (arena.rs:275). Attach fails closed on version mismatch (arena.rs:164).
- Reaper: `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs` — `trait PermitReclaimSource` (reaper:51), `spawn_reaper(&'static dyn PermitReclaimSource)` (idempotent, single static STARTED).
- MT lease slicing arms: `crates/carrick-runtime/src/vcpu_loop/mod.rs` — `WaitOnSignals` arm (mod.rs:1293-1425), `WaitOnSleep` arm (mod.rs:1426-1531), `try_upgrade_vm_release_on_slice_tick` (mod.rs:734), `try_release_vm_mt` (mod.rs:772), `resume_vcpu_after_blocking_wait` (mod.rs:823), `mt_vm_lease_enabled` (mod.rs:85), `parked_slice_stretch`/`parked_full_slices` locals (mod.rs:985-995). The skip-resume follow-up is named in the doc comments at mod.rs:714-718 and mod.rs:986-991.
- Park registry: `crates/carrick-thread/src/thread.rs` — `VcpuParkClass` (thread.rs:112), `park_vcpu_classified` (thread.rs:440), `all_other_parked_release_safe` (thread.rs:494), test-only `all_other_vcpus_parked` (thread.rs:479), tests at thread.rs:1088-1220.
- xsig ring: `crates/carrick-signal-core/src/xsig.rs` — `XSigSlot` (xsig.rs:27, `#[repr(C)]`, `used` state machine 0/1/2/3), `xsig_enqueue` (xsig.rs:97), `xsig_drain_for_self` (xsig.rs:173), ring tests xsig.rs:216-431. Consumer: `crates/carrick-runtime/src/dispatch/signal.rs` — `drain_xsignals_process_directed` (signal.rs:833), `mark_process_signal_pending` (signal.rs:1136), send paths `bootstrap_signal_send_as` xsig branch (signal.rs:2396-2410), `sigqueueinfo_common` (signal.rs:2038, enqueue at 2112-2122), `route_thread_signal` (signal.rs:1970 — the in-process thread-directed delivery to mirror), pinning tests (signal.rs:2608, 2663). `pidfd_send_signal` enqueue: `crates/carrick-runtime/src/dispatch/proc.rs:2915-2924`. Runtime wrapper: `crates/carrick-runtime/src/lib.rs:1687`.
- Probes: `conformance-probes/src/bin/` (autobins; drop a file = registered). Build: `scripts/build-probes.sh`. Iterate: `scripts/run-probe.sh <name>` (MATCH = stdout equality vs Docker, sequenced phases). Templates: `procladder_mixed.rs` (attempt-vs-veto shape), `spliceunixpoll.rs` (AF_UNIX listener + epoll), `epollforkeventfd.rs` (cross-fork epoll wake).
- Cluster-B wedge shape (from `.superpowers/sdd/task-6-regression-attribution.md`): pid 38232 — orphaned (ppid=1) forkserver-descended MT python, AF_UNIX BIND+LISTEN+ACCEPTs in its event ring, 2 guest threads BOTH blocked in `ThreadWaiter::wait_kqueue` (WaitOnFds), held dups keeping the forkserver alive-pipe open; stopped progressing under the (refuted) eager whole-VM release. Cores retained: `cr-attr-fs.38232.core`.
- Kill-switch fatal shape (from `.superpowers/sdd/task-6-debug-report.md`): lease OFF @160 → permits free but ~127-VM ceiling pinned → pre-fork gate passes trivially → child post-fork `hv_vm_create` fatals after 10 s backpressure, 18–20× `trap engine failed`, rc=125.

---

### Task 1: Resident-VM slot table (arena section + region + recording + reclaim)

**Files:**
- Modify: `crates/carrick-kernel/src/arena.rs` (layout + header publish + test)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (region accessor, record/release helpers, wiring at the 1 create + 4 destroy sites, fork-child reset, cooperative release, dual reaper source, tests)

**Interfaces:**
- Consumes: existing `PermitRegion` (acquire/register/release_token/release_unregistered/reclaim_owner/reset_local_after_fork_child/cooperative_release_local), `KernelArena::global()`, `spawn_reaper(&'static dyn PermitReclaimSource)`.
- Produces (Task 2 depends on these exact names):
  - `fn vm_residency_region() -> &'static PermitRegion` (trap.rs, cfg macos/aarch64)
  - `const VM_RESIDENCY_LOCAL_KEY: u64 = u64::MAX;`
  - `fn record_vm_resident()` / `fn record_vm_released()` (trap.rs, private)
  - arena field `ArenaLayout::vm_slots: PermitSection`

- [ ] **Step 1: Write the failing arena test**

In `crates/carrick-kernel/src/arena.rs` tests module, add:

```rust
#[test]
fn vm_slots_section_is_published_and_independent() {
    let arena = KernelArena::create().unwrap();
    let l = arena.layout();
    assert_eq!(
        l.vm_slots.magic.load(std::sync::atomic::Ordering::Acquire),
        PERMIT_MAGIC
    );
    assert_eq!(
        l.vm_slots
            .next_generation
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    // Claiming in vm_slots must not consume permit slots (independent tables).
    let claimed = l
        .vm_slots
        .try_claim_slot(crate::domains::HostPid::new(42), arena.allocate_generation());
    assert!(claimed.is_ok());
    assert_eq!(
        l.permits.slots[claimed.unwrap()].load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p carrick-kernel --lib vm_slots_section_is_published_and_independent`
Expected: FAIL to compile — `no field vm_slots on ArenaLayout`.

- [ ] **Step 3: Add the arena section**

In `crates/carrick-kernel/src/arena.rs`:
- Bump `pub const ARENA_VERSION: u32 = 2;` → `3` (attach fails closed on mismatch, so a stale `CARRICK_KERNEL_ARENA` file from an old layout can never be attached).
- Append to `ArenaLayout` (append-only, keeping prior field offsets):

```rust
#[repr(C)]
pub struct ArenaLayout {
    pub header: ArenaHeader,
    pub permits: PermitSection,
    pub processes: ProcessSection,
    /// Resident-VM slot table: one generation-stamped slot per LIVE HVF VM
    /// (claimed on `hv_vm_create`, freed on `hv_vm_destroy`, death-reclaimed
    /// by the vcpu-permit reaper). Same byte layout and slot protocol as
    /// `permits`; consumed by `carrick-vmm-hvf/src/trap.rs::vm_residency_region`.
    /// Exists because vCPU-admission permits UNDER-REPORT residency: a
    /// vCPU-only park frees its permit while keeping its VM
    /// (docs/2026-07-09-mt-residency-lease-evidence.md, Next Track 1).
    pub vm_slots: PermitSection,
}
```

- In `publish_fresh_header` (arena.rs:275), before the header-magic store, add:

```rust
        layout.vm_slots.next_generation.store(1, Ordering::Relaxed);
        layout
            .vm_slots
            .version
            .store(PERMIT_VERSION, Ordering::Relaxed);
        layout.vm_slots.magic.store(PERMIT_MAGIC, Ordering::Release);
```

- [ ] **Step 4: Run the arena tests**

Run: `cargo test -p carrick-kernel --lib`
Expected: all pass, including the new test.

- [ ] **Step 5: Write the failing trap.rs region/record tests**

In `crates/carrick-vmm-hvf/src/trap.rs` tests module (near `permit_table_is_the_arena_permit_section`, ~trap.rs:5871), add:

```rust
#[test]
fn vm_residency_region_is_the_arena_vm_slots_section() {
    let arena = carrick_kernel::arena::KernelArena::global();
    assert_eq!(
        vm_residency_region().table_addr_for_test(),
        &arena.layout().vm_slots as *const _ as usize,
    );
    // Independent of the permit table.
    assert_ne!(
        vm_residency_region().table_addr_for_test(),
        permit_region().table_addr_for_test(),
    );
}

#[test]
fn vm_residency_record_release_roundtrip_on_test_region() {
    let region = PermitRegion::new_anon_for_test();
    let pid = std::process::id();
    let token = region
        .acquire(atomic_permit_slot::MAX_SLOTS, pid)
        .expect("record acquires unconditionally under MAX_SLOTS");
    region.register(VM_RESIDENCY_LOCAL_KEY, token);
    assert_eq!(region.occupied(), 1);
    region.release_token(VM_RESIDENCY_LOCAL_KEY);
    assert_eq!(region.occupied(), 0);
    // Idempotent: a second release is a no-op.
    region.release_token(VM_RESIDENCY_LOCAL_KEY);
    assert_eq!(region.occupied(), 0);
}

#[test]
fn dual_reclaim_source_merges_and_reclaims_both_tables() {
    use crate::vcpu_permit_reaper::PermitReclaimSource;
    let a = Box::leak(Box::new(PermitRegion::new_anon_for_test()));
    let b = Box::leak(Box::new(PermitRegion::new_anon_for_test()));
    let (slot_a, gen_a) = a.force_owner_for_test(4242);
    let (slot_b, gen_b) = b.force_owner_for_test(4242);
    let dual = DualReclaimSource(a, b);
    let owners = dual.owner_slots();
    assert!(owners.contains(&(4242, gen_a)));
    assert!(owners.contains(&(4242, gen_b)));
    assert_eq!(dual.reclaim(4242, gen_a) + dual.reclaim(4242, gen_b), 2);
    let _ = (slot_a, slot_b);
}
```

(If `force_owner_for_test` returns a different shape, adapt the destructuring to its actual signature — it exists in this tests module already; do not invent a new helper.)

- [ ] **Step 6: Run to verify compile failures**

Run: `cargo test -p carrick-vmm-hvf --lib vm_residency 2>&1 | head -30`
Expected: FAIL to compile — `vm_residency_region`, `VM_RESIDENCY_LOCAL_KEY`, `DualReclaimSource` not found.

- [ ] **Step 7: Implement the region, recording helpers, and dual reaper source**

In `crates/carrick-vmm-hvf/src/trap.rs` (all `#[cfg(all(target_os = "macos", target_arch = "aarch64"))]`):

Next to `PermitRegion::new_shared_global` (trap.rs:1171):

```rust
    /// Same as [`Self::new_shared_global`] but over the arena's resident-VM
    /// slot section. One slot per live HVF VM, claimed/freed at the actual
    /// `hv_vm_create`/`hv_vm_destroy` transitions; occupancy is DERIVED from
    /// the slots (no separate counter to drift), and the death reaper
    /// reclaims a dead owner's slot exactly like a permit slot.
    fn new_shared_global_vm() -> PermitRegion {
        let arena = carrick_kernel::arena::KernelArena::global();
        PermitRegion {
            table: &arena.layout().vm_slots as *const _ as usize,
            local: std::sync::Mutex::new(HashMap::new()),
        }
    }
```

Next to `permit_region()` (trap.rs:1491):

```rust
/// The process-global resident-VM region. Same fork-inheritance property as
/// `permit_region`: first touched during initial-VM creation, before any
/// guest fork.
fn vm_residency_region() -> &'static PermitRegion {
    static REGION: std::sync::OnceLock<PermitRegion> = std::sync::OnceLock::new();
    REGION.get_or_init(PermitRegion::new_shared_global_vm)
}

/// The process-local registration key for THE resident VM (one VM per
/// process). `u64::MAX` cannot collide with an HVF vcpu_id in the shared
/// local map.
const VM_RESIDENCY_LOCAL_KEY: u64 = u64::MAX;

/// Record "this process now holds a live HVF VM". Called from the single
/// create funnel (`create_vm_with_admission` Ok arm). Recording is
/// UNCONDITIONAL (budget = MAX_SLOTS): the VM already exists; the budget is
/// enforced only by the fork-admission PROBE. A full table (impossible in
/// practice: 128 slots > the ~127-VM hard ceiling) logs and under-counts by
/// one rather than failing the create.
fn record_vm_resident() {
    if !atomic_permit_enabled() {
        return; // flock fallback: no residency table; the gate skips the VM probe too
    }
    let region = vm_residency_region();
    // A stale prior registration (should not happen: one VM per process,
    // destroy paths release first) would leak a slot until death-reclaim;
    // release defensively so the table can never double-count one process.
    region.release_token(VM_RESIDENCY_LOCAL_KEY);
    match region.acquire(atomic_permit_slot::MAX_SLOTS, std::process::id()) {
        Some(token) => region.register(VM_RESIDENCY_LOCAL_KEY, token),
        None => tracing::warn!(
            "resident-VM table full; VM unrecorded (fork gate will under-count by one)"
        ),
    }
}

/// Record "this process's HVF VM is gone". Called after each SUCCESSFUL
/// `hv_vm_destroy`. Idempotent (token-guarded).
fn record_vm_released() {
    if !atomic_permit_enabled() {
        return;
    }
    vm_residency_region().release_token(VM_RESIDENCY_LOCAL_KEY);
}
```

Replace `start_vcpu_permit_reaper` (trap.rs:1482) with a dual source (the reaper watches both tables; reclaim after a CONFIRMED death frees any of that pid's slots in either table, so cross-table generation collisions are harmless):

```rust
/// Both slot tables feed ONE reaper: pid death must reclaim the dead owner's
/// vCPU-permit slots AND its resident-VM slot.
struct DualReclaimSource(&'static PermitRegion, &'static PermitRegion);

impl crate::vcpu_permit_reaper::PermitReclaimSource for DualReclaimSource {
    fn owner_slots(&self) -> Vec<(u32, u32)> {
        let mut owners = self.0.owner_slots();
        owners.extend(self.1.owner_slots());
        owners
    }
    fn reclaim(&self, pid: u32, generation: u32) -> usize {
        self.0.reclaim(pid, generation) + self.1.reclaim(pid, generation)
    }
}

pub fn start_vcpu_permit_reaper() {
    static DUAL: std::sync::OnceLock<DualReclaimSource> = std::sync::OnceLock::new();
    crate::vcpu_permit_reaper::spawn_reaper(
        DUAL.get_or_init(|| DualReclaimSource(permit_region(), vm_residency_region())),
    );
}
```

Wire the transitions:
- `create_vm_with_admission` Ok arm (trap.rs:1790): `Ok(vm) => { record_vm_resident(); Ok((vm, permit)) }`.
- `shared_wait_park` (after the `vm_rc != 0` check, trap.rs:3858): add `record_vm_released();` before `Ok(())`.
- `release_vm_after_reclaim_park` (after the `vm_rc != 0` check, trap.rs:3885): add `record_vm_released();` before `Ok(())`.
- `fork_prepare_and_teardown` (trap.rs:4237): after the `hv_vm_destroy()`, add `if vm_destroy_rc == 0 { record_vm_released(); }`.
- Execve rebuild (trap.rs:4686): change `let _ = unsafe { applevisor_sys::hv_vm_destroy() };` to capture the rc and call `record_vm_released()` when rc == 0.
- `reset_admission_permits_after_fork_child` (trap.rs:1607): in the atomic branch, also `vm_residency_region().reset_local_after_fork_child();` (the child must NOT be able to release the parent's slot through the inherited local map; the child's own `create_vm_with_admission` records a fresh child-pid slot).
- `cooperative_release_atomic_permit` (trap.rs:1623): also free the residency slot — `permit_region().cooperative_release_local() + vm_residency_region().cooperative_release_local()`.

- [ ] **Step 8: Run the trap tests**

Run: `cargo test -p carrick-vmm-hvf --lib`
Expected: PASS, including the three new tests and all pre-existing permit tests (`fork_child_reset_clears_local_only`, `cooperative_release_*`, `region_address_is_inherited_across_fork`, `concurrent_acquire_never_over_admits_past_budget`).

- [ ] **Step 9: Full-workspace sanity + commit**

```bash
cargo fmt
cargo test -p carrick-kernel -p carrick-vmm-hvf --lib
cargo clippy -p carrick-kernel -p carrick-vmm-hvf --all-targets 2>&1 | grep -c warning  # expect no NEW warnings
git add crates/carrick-kernel/src/arena.rs crates/carrick-vmm-hvf/src/trap.rs
git commit -m "feat(hvf): resident-VM slot table in the kernel arena, reaper-reclaimed"
```

---

### Task 2: Fork admission sees resident VMs

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (`probe_fork_vm_admission` + a bounded VM-slot probe + constants + doc updates + tests)
- Test: e2e recorded runs (procladder family) — see steps

**Interfaces:**
- Consumes: Task 1's `vm_residency_region()`, `record_vm_resident/record_vm_released`, `GlobalVcpuPermitBackoff`, `permit_exhausted`, `trace_permit_park`.
- Produces: `const GLOBAL_VM_CEILING: usize = 120;` (on `VmCreateAdmission`), `fn probe_vm_slot_budget(region: &PermitRegion, budget: usize, max_wait: std::time::Duration) -> Result<(), TrapError>`.

- [ ] **Step 1: Write the failing unit test**

In the trap.rs tests module:

```rust
#[test]
fn fork_vm_probe_bounds_out_when_residency_is_pinned_and_admits_after_release() {
    let region = PermitRegion::new_anon_for_test();
    let budget = 4;
    let mut tokens = Vec::new();
    for i in 0..budget {
        let t = region.acquire(budget, 1000 + i as u32).expect("under budget");
        region.register(i as u64, t);
    }
    // Pinned at budget: the probe must bound out quickly (test-scale wait).
    let err = probe_vm_slot_budget(&region, budget, std::time::Duration::from_millis(50));
    assert!(matches!(err, Err(TrapError::HostResourceExhausted { .. })));
    // One release frees a hard slot: the probe admits again.
    region.release_token(0);
    assert!(probe_vm_slot_budget(&region, budget, std::time::Duration::from_millis(50)).is_ok());
    drop(tokens);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p carrick-vmm-hvf --lib fork_vm_probe_bounds_out`
Expected: FAIL to compile — `probe_vm_slot_budget` not found.

- [ ] **Step 3: Implement the bounded VM-slot probe and wire the gate**

In trap.rs, next to `probe_fork_vm_admission` (trap.rs:1823):

```rust
/// Fork-gate bound for the resident-VM probe. Deliberately the SAME 10 s as
/// the post-fork `hv_vm_create` HV_NO_RESOURCES backpressure MAX_WAIT: the
/// pre-fork gate never waits longer than the post-fork path it replaces, so
/// a pinned fleet (lease off, or fd-veto-retained VMs) degrades to guest
/// EAGAIN in ~10 s instead of a rc=125 trap fatal. Lease-driven releases
/// land at the 2–8 s slice ticks, well inside the bound.
const FORK_VM_PROBE_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Bounded acquire-and-release of ONE slot in `region`: proves a hard slot
/// exists for the fork child's `hv_vm_create` under `budget`.
fn probe_vm_slot_budget(
    region: &PermitRegion,
    budget: usize,
    max_wait: std::time::Duration,
) -> Result<(), TrapError> {
    let pid = std::process::id();
    let mut backoff = GlobalVcpuPermitBackoff::default();
    let start = std::time::Instant::now();
    let mut parks: u32 = 0;
    loop {
        if let Some(token) = region.acquire(budget, pid) {
            region.release_unregistered(token);
            return Ok(());
        }
        if start.elapsed() >= max_wait {
            return Err(permit_exhausted(
                "resident-vm slot",
                budget,
                parks,
                start.elapsed(),
            ));
        }
        parks += 1;
        trace_permit_park("resident-vm slot", budget, parks, start.elapsed());
        std::thread::sleep(backoff.next_delay());
    }
}
```

On `VmCreateAdmission` (next to `GLOBAL_VCPU_CEILING`, trap.rs:782):

```rust
    /// Resident-VM budget for the fork gate: same soft margin under the
    /// measured ~126-concurrent-VM HVF ceiling as the vCPU-permit budget.
    const GLOBAL_VM_CEILING: usize = 120;
```

Extend `probe_fork_vm_admission` (and REWRITE its `KNOWN BLIND SPOT` doc paragraph to state the blind spot is closed by the resident-VM probe, citing this plan):

```rust
pub fn probe_fork_vm_admission() -> Result<(), TrapError> {
    let Some(budget) = (VmCreateAdmission::ForkRebuild { vfork: false }).global_permit_budget()
    else {
        return Ok(());
    };
    let permit = acquire_admission_permit(budget)?;
    release_unregistered_admission_permit(permit);
    // Resident-VM budget: permits alone UNDER-REPORT residency (a vCPU-only
    // park frees its permit while keeping its VM — the lease-off @160 fatal
    // and the fd-veto capacity cost, evidence doc Next Track 1). Probe the
    // hard-slot table too. Flock fallback has no residency table; it keeps
    // the historical permit-only gate.
    if atomic_permit_enabled() {
        probe_vm_slot_budget(
            vm_residency_region(),
            VmCreateAdmission::GLOBAL_VM_CEILING,
            FORK_VM_PROBE_MAX_WAIT,
        )?;
    }
    Ok(())
}
```

- [ ] **Step 4: Run unit tests**

Run: `cargo test -p carrick-vmm-hvf --lib`
Expected: PASS (new test + all existing).

- [ ] **Step 5: Build signed + regression gates (must stay green)**

```bash
scripts/build-signed.sh
scripts/run-probe.sh procladder
scripts/run-probe.sh procladder_mt
scripts/run-probe.sh procladder_mixed
```
Expected: MATCH ×3.

Then the @160 lease-ON gate (one-shot):

```bash
RUN_ID=cr-t2-$$; base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/procladder_mt | \
  CARRICK_RUN_ID=$RUN_ID timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p'
```
Expected: `ladder_forked_all=true ladder_children_ok=true`, rc=0, wall < 60 s. Lease releases free VM slots at the 2–8 s ticks, so the storm is admitted; if this EAGAIN-degrades instead, STOP — the budget/wait needs review, record an AMENDMENT.

- [ ] **Step 6: RECORDED e2e — the two fatal shapes must now degrade to EAGAIN**

(a) Kill-switch shape (was: rc=125 trap-fatal storm):

```bash
RUN_ID=cr-t2ks-$$; base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/procladder_mt | \
  CARRICK_MT_VM_LEASE=0 CARRICK_RUN_ID=$RUN_ID timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p' 2>&1 | tail -20
```
Expected: NO `trap engine failed` lines; the first over-ceiling fork EAGAINs after ~10 s, the probe's fork loop breaks, output is `ladder_forked_all=false` with `ladder_children_ok=true` for the admitted subset, rc=0. Record the exact output in the task report.

(b) Veto capacity shape (was: ~10.5 s HV_NO_RESOURCES fatals, report lost):

```bash
RUN_ID=cr-t2mx-$$; base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/procladder_mixed | \
  CARRICK_RUN_ID=$RUN_ID timeout 300 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p' 2>&1 | tail -20
```
Expected: NO `trap engine failed` lines; `ladder_forked_all=false ladder_children_ok=true`, rc=0. Record.

- [ ] **Step 7: Perf floor + commit**

```bash
# perf_fork must stay ≤2.5ms (the gate adds one atomic scan per fork — µs):
RUN_ID=cr-t2pf-$$; base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | \
  CARRICK_RUN_ID=$RUN_ID timeout 120 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'
cargo fmt
git add crates/carrick-vmm-hvf/src/trap.rs
git commit -m "feat(hvf): fork admission probes the resident-VM budget, closing the permit blind spot"
```

---

### Task 3: xsig ring `target_tid` for cross-process thread-directed sends

**Files:**
- Modify: `crates/carrick-signal-core/src/xsig.rs` (slot field, enqueue/drain signature, ring tests)
- Modify: `crates/carrick-runtime/src/lib.rs:1687` (wrapper), `crates/carrick-runtime/src/dispatch/signal.rs` (send sites + drain routing + pinning tests), `crates/carrick-runtime/src/dispatch/proc.rs:2915` (pidfd send site)

**Interfaces:**
- Consumes: existing ring protocol (`used` 0/1/2/3 state machine), `route_thread_signal` (signal.rs:1970 — mirror its publish half: per-tid mark + siginfo store + waiter kick), `take_pending_in_from` provenance pair.
- Produces: `xsig_enqueue(target_host_pid: i32, signum: i32, code: i32, sender_ns_pid: i32, sender_uid: u32, value: i64, target_ns_tid: i32) -> bool` (0 = process-directed); `xsig_drain_for_self()` items grow a trailing `target_ns_tid: i32`.

- [ ] **Step 1: Write the failing ring test**

In `crates/carrick-signal-core/src/xsig.rs` tests:

```rust
#[test]
fn enqueue_carries_target_tid_through_drain() {
    // (follow the existing tests' init/reset pattern in this module)
    assert!(xsig_enqueue(std::process::id() as i32, 10, 0, 7, 1000, 0, 4321));
    let drained = xsig_drain_for_self();
    assert_eq!(drained.len(), 1);
    let (_sig, _code, _ns, _uid, _val, target_ns_tid) = drained[0];
    assert_eq!(target_ns_tid, 4321);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p carrick-signal-core --lib enqueue_carries_target_tid`
Expected: FAIL to compile (arity mismatch).

- [ ] **Step 3: Implement the ring change**

In `XSigSlot` (xsig.rs:27), after `target_host_pid`:

```rust
    /// Guest ns tid of a THREAD-DIRECTED cross-process send (tkill/tgkill/
    /// rt_tgsigqueueinfo); 0 = process-directed (kill/rt_sigqueueinfo/pidfd).
    /// Same-binary fork-shared ring: layout changes are compat-safe.
    target_ns_tid: AtomicI32,
```

Extend `xsig_enqueue` with the trailing `target_ns_tid: i32` parameter; store it with the other `Relaxed` payload stores in the claim phase (before the `used.store(2, Release)` publish). Extend `xsig_drain_for_self` to load and return it as the trailing tuple element. Free path (`used.store(0, Release)`) unchanged. Update every existing xsig.rs test call site with a trailing `0`.

- [ ] **Step 4: Run ring tests**

Run: `cargo test -p carrick-signal-core --lib`
Expected: PASS, including `concurrent_drain_delivers_each_entry_exactly_once` and `ring_full_rejects_257th_enqueue`.

- [ ] **Step 5: Write the failing dispatcher pinning tests**

In `crates/carrick-runtime/src/dispatch/signal.rs` tests, modeled exactly on `ring_drain_publishes_process_directed_signal_visible_to_non_drainer` (signal.rs:2608 — reuse its dispatcher/tid/mask setup verbatim):

```rust
#[test]
fn ring_drain_routes_thread_directed_to_target_tid_only() {
    // setup as in ring_drain_publishes_process_directed_signal_visible_to_non_drainer:
    // dispatcher, main + sibling synthetic tids, both blocking SIGUSR1, xsig_init.
    // Enqueue THREAD-DIRECTED at main's guest tid:
    //   xsig_enqueue(getpid, SIGUSR1, LINUX_SI_TKILL, 4242, 1000, 0, <main guest tid>)
    // Drain (sibling wins the race): dispatcher.drain_xsignals_process_directed()
    // Assert:
    //   - NOT pinned to the drainer: take_pending_siginfo(sibling, usr1).is_none()
    //   - NOT process-directed: take_process_pending_siginfo(usr1).is_none()
    //   - visible to main PER-THREAD: take_pending_in_from(main, set) == Some((usr1, true))
    //     and take_pending_siginfo(main, usr1) carries sender ns-pid 4242 with
    //     si_code SI_TKILL
    //   - exactly-once: second take is None
}

#[test]
fn ring_drain_target_tid_zero_stays_process_directed() {
    // Same setup; enqueue with target_ns_tid = 0; assert the EXISTING
    // process-directed contract (from_thread == false via the shared set),
    // i.e. the same assertions as
    // ring_drain_publishes_process_directed_signal_visible_to_non_drainer.
}

#[test]
fn ring_drain_discards_thread_directed_for_exited_tid() {
    // Enqueue with a target_ns_tid matching NO registered thread; drain;
    // assert nothing lands anywhere: per-thread takes None for all tids,
    // take_process_pending_siginfo None (Linux discards thread-directed
    // pending at thread exit).
}
```

Write these as REAL tests (full bodies following the 2608 test's concrete setup), not comments.

- [ ] **Step 6: Run to verify they fail**

Run: `cargo test -p carrick-runtime --lib ring_drain_routes_thread_directed 2>&1 | tail -5`
Expected: FAIL (compile: enqueue arity; then behavior: signal lands process-directed).

- [ ] **Step 7: Implement drain routing + send sites**

In `drain_xsignals_process_directed` (signal.rs:833): destructure the new tuple element. When `target_ns_tid != 0`, resolve the local `ThreadId` the way `route_thread_signal` (signal.rs:1970) resolves its target (same registry lookup); if found, publish PER-THREAD — the per-`(tid, signum)` `pending_siginfos` entry (clear-first for non-RT, push_back), the per-thread pending mark, and the same waiter kick `route_thread_signal` issues — and if not found, `continue` (discard; comment the Linux discard-at-thread-exit semantics). `target_ns_tid == 0` keeps the existing process-directed publication verbatim.

Send sites (all gain the trailing arg):
- `bootstrap_signal_send_as` xsig branch (signal.rs:2396-2410): derive `target_ns_tid` from the `SignalTarget` it received — the `GuestTid(t)` variant passes `t` raw, every other variant passes 0. (Routing still addresses the ring by host pid, so cross-process thread-directed delivery works where it worked before — tid == pid main threads — but now lands thread-directed in the target. Note this limitation in the comment.)
- `sigqueueinfo_common` (signal.rs:2112-2122): pass the target tid for the `rt_tgsigqueueinfo` flavor, 0 for `rt_sigqueueinfo`.
- `pidfd_send_signal` (proc.rs:2915-2924): pass 0.
- Runtime wrapper `xsig_enqueue` (lib.rs:1687): extend passthrough.

- [ ] **Step 8: Run the dispatcher tests + full battery**

```bash
cargo test -p carrick-runtime -p carrick-signal-core --lib
```
Expected: PASS — the 3 new pinning tests, plus the two existing stranding-fix tests (`ring_drain_publishes_process_directed_signal_visible_to_non_drainer`, `per_tid_delivery_does_not_steal_process_directed_payload`) UNCHANGED and green.

- [ ] **Step 9: e2e signal probes + commit**

```bash
scripts/build-signed.sh
for p in killrt killtarget killgroup killchld forksigwalk procladder_mt; do scripts/run-probe.sh "$p" || echo "DIFF: $p"; done
cargo fmt
git add crates/carrick-signal-core/src/xsig.rs crates/carrick-runtime/src
git commit -m "feat(xsig): ring slots carry target_tid; cross-process tkill/tgkill land thread-directed"
```
Expected: MATCH ×6. (Probe names: verify each exists under `conformance-probes/src/bin/` first; substitute the actual kill-family probe names if these differ, from `ls conformance-probes/src/bin | grep kill`.)

---

### Task 4: skip-resume-on-idle-TimedOut (zero-churn idle endpoint)

**Files:**
- Create: `conformance-probes/src/bin/mtidlesleep.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs` (`WaitOnSignals` arm 1293-1425, `WaitOnSleep` arm 1426-1531, doc comments at 714-718 / 986-991)

**Interfaces:**
- Consumes: `try_upgrade_vm_release_on_slice_tick`, `resume_vcpu_after_blocking_wait`, `signal_wait_slice/remaining/expired`, `parked_slice_stretch`/`parked_full_slices`.
- Produces: no new API — the arms gain an inner re-wait loop; behavior contract: an idle parked `TimedOut` tick re-arms the wait WITHOUT the resume/re-park round trip.

- [ ] **Step 1: Write the churn-measurement probe (the red witness)**

Create `conformance-probes/src/bin/mtidlesleep.rs`:

```rust
//! Idle-churn witness for the MT VM lease: a TWO-threaded process where BOTH
//! threads sit in one long `nanosleep` (the WaitOnSleep slicing arm, both
//! RELEASE-SAFE). Under the slice-tick lease WITHOUT skip-resume, the parked
//! process resumes + re-parks its vCPU on every stretched tick (2s→4s→8s ≈
//! 4-6 rebuilds in 20 s). WITH skip-resume, an idle TimedOut tick re-arms the
//! wait with the vCPU still parked: expect ≤2 hv_vm_create for the whole run
//! (initial boot + the final-wake rebuild). Measured externally via dtrace on
//! hv_vm_create — the probe itself reports only a deterministic boolean.

use conformance_probes::report;

fn main() {
    let t = std::thread::spawn(|| unsafe {
        let ts = libc::timespec { tv_sec: 20, tv_nsec: 0 };
        libc::nanosleep(&ts, std::ptr::null_mut());
    });
    unsafe {
        let ts = libc::timespec { tv_sec: 20, tv_nsec: 0 };
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
    let joined = t.join().is_ok();
    report!(slept_both = joined);
}
```

- [ ] **Step 2: Record the RED (pre-fix churn)**

```bash
scripts/build-probes.sh   # or build just this probe per the script's usage
scripts/build-signed.sh
sudo -n /usr/sbin/dtrace -q -n 'pid$target:Hypervisor:hv_vm_create:entry { @creates = count(); }' \
  -c "target/release/carrick run-elf --raw --fs memory conformance-probes/target/aarch64-unknown-linux-musl/release/mtidlesleep"
```
(If `run-elf --fs memory` cannot run this probe, use the threaded `run … --raw --fs host` base64 form from Task 2 Step 5 with dtrace `-p` on the carrick pid instead; what matters is one bounded run with a create count.)
Expected RED: `@creates` ≥ 4 (initial + per-tick rebuilds at the 2 s→4 s→8 s cadence, ×2 threads' arms). Record the exact count — this is the before number.

- [ ] **Step 3: Restructure the `WaitOnSignals` arm**

In `crates/carrick-runtime/src/vcpu_loop/mod.rs`, replace the section of the `WaitOnSignals` arm from the `let slice = match (reclaim.is_some(), guest_remaining) {` recompute (mod.rs:1342) through the `match wait_result {` dispatch, with an inner re-wait loop. The complete new shape (preserving every existing comment that still applies):

```rust
                    // Inner re-wait loop: an idle parked TimedOut tick re-arms
                    // the wait WITHOUT the resume/re-park round trip (the
                    // "skip-resume-on-idle-TimedOut" endpoint named by the
                    // 2026-07-09 evidence doc). Every tick still: re-checks
                    // the finite guest deadline, advances the full-slice
                    // count, and may attempt the deferred whole-VM upgrade.
                    // Any non-TimedOut result (or a deadline expiry, or a
                    // non-parked wait) breaks out to the single resume below.
                    let wait_result = loop {
                        let guest_remaining =
                            signal_wait_remaining(signal_wait_deadline, timeout);
                        let slice_eff = match (reclaim.is_some(), guest_remaining) {
                            (true, None) => slice.max(parked_slice_stretch),
                            (true, Some(remaining)) if remaining > Duration::from_secs(1) => {
                                slice.max(parked_slice_stretch).min(remaining)
                            }
                            _ => slice,
                        };
                        let was_parked_full_slice =
                            reclaim.is_some() && slice_eff >= Duration::from_secs(1);
                        // Deferred MT whole-VM upgrade: only from the SECOND
                        // parked full slice on, and only when the CURRENT
                        // tick is itself a full ≥1 s slice (unchanged rule).
                        let released = was_parked_full_slice
                            && parked_full_slices >= 1
                            && self.try_upgrade_vm_release_on_slice_tick(engine);
                        let result = self.waiter.wait(&[], Some(slice_eff), block_mask);
                        if let Some(outcome) = self.exec_replaced_thread_exit() {
                            return Ok(outcome);
                        }
                        match result {
                            crate::io_wait::WaitResult::TimedOut => {
                                if was_parked_full_slice {
                                    parked_full_slices = parked_full_slices.saturating_add(1);
                                    if released {
                                        // Post-release progression: 2s→4s→8s.
                                        parked_slice_stretch = (parked_slice_stretch * 2)
                                            .clamp(Duration::from_secs(2), Duration::from_secs(8));
                                    }
                                }
                                if signal_wait_expired(signal_wait_deadline) {
                                    break result; // finite deadline: resume, then EAGAIN below
                                }
                                if reclaim.is_none() {
                                    break result; // vCPU live (short-wait class): keep the old re-dispatch cadence
                                }
                                // Idle parked tick: skip the resume/re-park
                                // round trip entirely and re-arm the wait.
                                continue;
                            }
                            other => break other,
                        }
                    };
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
```

The trailing `match wait_result { … }` arms stay byte-identical to today's (`Ready`/`TimedOut`/`Interrupted`/`Errno`), except the `TimedOut` arm loses its now-inner-loop bookkeeping and becomes:

```rust
                        crate::io_wait::WaitResult::TimedOut => {
                            if signal_wait_expired(signal_wait_deadline) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EAGAIN,
                                });
                            }
                            continue;
                        }
```

Also update the two "deliberately NOT attempted" doc comments (mod.rs:714-718 and mod.rs:986-991) to state the skip is now implemented, and delete the stale pre-wait upgrade/stretch code this loop replaces (the old lines 1342-1384 region).

- [ ] **Step 4: Restructure the `WaitOnSleep` arm the same way**

Replace from the `let remaining_until_deadline = deadline - now;` recompute (mod.rs:1465) through the `match wait_result {` dispatch:

```rust
                    let wait_result = loop {
                        let now = Instant::now();
                        if now >= deadline {
                            break crate::io_wait::WaitResult::TimedOut;
                        }
                        let remaining_until_deadline = deadline - now;
                        let wait_for = if reclaim.is_some()
                            && remaining_until_deadline > Duration::from_secs(1)
                        {
                            remaining_until_deadline.min(parked_slice_stretch)
                        } else {
                            remaining_until_deadline.min(Duration::from_millis(50))
                        };
                        let was_parked_full_slice =
                            reclaim.is_some() && wait_for >= Duration::from_secs(1);
                        let released = was_parked_full_slice
                            && parked_full_slices >= 1
                            && self.try_upgrade_vm_release_on_slice_tick(engine);
                        let result = self.waiter.wait_with_dispatch_pending(
                            &[],
                            Some(wait_for),
                            carrick_abi::SigBlockMask::NONE,
                            sleep_interrupt_pending,
                        );
                        if let Some(outcome) = self.exec_replaced_thread_exit() {
                            return Ok(outcome);
                        }
                        match result {
                            crate::io_wait::WaitResult::TimedOut => {
                                if was_parked_full_slice {
                                    parked_full_slices = parked_full_slices.saturating_add(1);
                                    if released {
                                        parked_slice_stretch = (parked_slice_stretch * 2)
                                            .clamp(Duration::from_secs(2), Duration::from_secs(8));
                                    }
                                }
                                if Instant::now() >= deadline {
                                    break result;
                                }
                                if reclaim.is_none() {
                                    break result;
                                }
                                continue;
                            }
                            other => break other,
                        }
                    };
                    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
                    match wait_result {
```

Trailing match arms unchanged except `TimedOut` reduces to the deadline check + `break Ok(DispatchOutcome::Returned { value: 0 })` / `continue`.

KNOWN RISK to verify, not assume: between skipped ticks the syscall is NOT re-dispatched, so anything only a re-dispatch serviced must arrive via the waiter kick (`Ready`/`Interrupted`) or via `sleep_interrupt_pending` (polled inside `wait_with_dispatch_pending`). The step-6 battery (kill-family probes + LTP six-pack + forkserver) is the guard; if any goes red, STOP and record.

- [ ] **Step 5: Compile + unit tests**

```bash
cargo fmt && cargo test -p carrick-runtime --lib
```
Expected: PASS (including `timed_wait_reclaim_*` at mod.rs:2410/2420).

- [ ] **Step 6: GREEN churn measurement + full battery**

```bash
scripts/build-signed.sh
# Same dtrace command as Step 2:
sudo -n /usr/sbin/dtrace -q -n 'pid$target:Hypervisor:hv_vm_create:entry { @creates = count(); }' \
  -c "target/release/carrick run-elf --raw --fs memory conformance-probes/target/aarch64-unknown-linux-musl/release/mtidlesleep"
```
Expected GREEN: `@creates` ≤ 3 and strictly less than the Step-2 red count. Record both numbers.

Battery (one-shot each):

```bash
scripts/run-probe.sh procladder && scripts/run-probe.sh procladder_mt && scripts/run-probe.sh procladder_mixed
# @160 lease-ON gate (same command as Task 2 Step 5): expect GREEN
# kill family (same list as Task 3 Step 9): expect MATCH
target/release/carrick-conformance --workers 1 --no-image-refresh \
  --suite ltp-clone08 --suite ltp-kill10 --suite ltp-ptrace06 \
  --suite ltp-waitpid06 --suite ltp-waitpid08 --suite ltp-waitpid10
# CPython forkserver (the lease's designated witness) per the evidence doc's command
# perf floors: perf_fork ≤2.5ms, perf_wait_pipe_pingpong ≤50µs, perf_futex_pingpong 31-34µs
```
Expected: all MATCH/GREEN/SUCCESS and floors hold.

- [ ] **Step 7: Commit**

```bash
cargo fmt
git add crates/carrick-runtime/src/vcpu_loop/mod.rs conformance-probes/src/bin/mtidlesleep.rs
git commit -m "perf(lease): skip the resume/re-park round trip on idle TimedOut ticks"
```

---

### Task 5: Cluster-B reproducer (epoll/AF_UNIX manager) + root cause

**Files:**
- Modify: `crates/carrick-thread/src/thread.rs` (promote `all_other_vcpus_parked` to `pub fn all_other_parked`), `crates/carrick-runtime/src/vcpu_loop/mod.rs` (test-only knob in `try_release_vm_mt`)
- Create: `conformance-probes/src/bin/procladder_epollmgr.rs`
- Create (investigation output): `.superpowers/sdd/cluster-b-rootcause.md`

**Interfaces:**
- Consumes: `VcpuParkClass`, `try_release_vm_mt` re-check (mod.rs:783), `mt_vm_lease_enabled` env pattern (mod.rs:85).
- Produces: env knob `CARRICK_MT_VM_LEASE_FDBACKED` (default OFF; treats FdBacked parks as release-safe in the re-check — the reproducible form of the b01e18e2 veto-neutering mutation); `pub fn all_other_parked(&self, tid: ThreadId) -> bool` on the registry.

- [ ] **Step 1: Knob + registry method, TDD**

Failing test in `crates/carrick-thread/src/thread.rs` (model on `fd_backed_park_vetoes_release_safe_recheck`, thread.rs:1153):

```rust
#[test]
fn all_other_parked_ignores_park_class() {
    // three threads; park one FdBacked + one ReleaseSafe;
    // all_other_parked(third) == true while all_other_parked_release_safe(third) == false
}
```
(Write the full body following the 1153 test's setup.) Run → FAIL (method missing) → promote the `#[cfg(test)] all_other_vcpus_parked` (thread.rs:479) to `pub fn all_other_parked` (keep a thin test alias if other tests name the old symbol) → PASS.

In `try_release_vm_mt` (mod.rs:783), replace the re-check call:

```rust
        let release_safe = if mt_vm_lease_fdbacked_release_enabled() {
            // TEST-ONLY (CARRICK_MT_VM_LEASE_FDBACKED=1): treat fd-backed
            // parks as release-safe — the reproducible form of the
            // procladder_mixed mutation check (b01e18e2). The veto stays the
            // shipping default until cluster B is root-caused (the recorded
            // reviewer condition).
            self.registry.all_other_parked(self.this_tid)
        } else {
            self.registry.all_other_parked_release_safe(self.this_tid)
        };
        if !release_safe {
```

with `mt_vm_lease_fdbacked_release_enabled()` a cached-env fn mirroring `mt_vm_lease_enabled` (mod.rs:85), default false, truthy only on `"1"`.

```bash
cargo fmt && cargo test -p carrick-thread -p carrick-runtime --lib
git add crates/carrick-thread/src/thread.rs crates/carrick-runtime/src/vcpu_loop/mod.rs
git commit -m "test(lease): CARRICK_MT_VM_LEASE_FDBACKED knob reproduces the veto-neutered release"
```

- [ ] **Step 2: Write the manager-shaped probe**

Create `conformance-probes/src/bin/procladder_epollmgr.rs` — the cluster-B shape from the 38232 cores: an MT child with TWO fd-backed epoll waiters (an AF_UNIX listener and a socketpair peer, mirroring "AF_UNIX BIND+LISTEN+ACCEPTs, 2 threads in wait_kqueue") plus a 3 s-nanosleep release-safe sibling to drive the slice-tick upgrade (same de-vacuousing rule as `procladder_mixed` — the module doc there explains why 3 s):

```rust
//! Cluster-B reproducer shape: N children, each THREE-threaded —
//!   * thread A: epoll_wait on an epfd holding an AF_UNIX SOCK_STREAM
//!     LISTENER (fd-backed park; the 38232 manager's accept loop),
//!   * main:     epoll_wait on an epfd holding a socketpair peer
//!     (fd-backed park; the manager's alive/command channel),
//!   * thread B: loop { nanosleep(3s) } (release-safe; drives the deferred
//!     whole-VM upgrade attempt — vacuous without it, see procladder_mixed).
//! Default (veto ON): the fd-backed parks veto the release; probe is a
//! mechanism gate and must stay GREEN. With CARRICK_MT_VM_LEASE_FDBACKED=1
//! the release actually happens under the two epoll waiters — the
//! wake-correctness question cluster B left open (a plain pipe read survived
//! release, b01e18e2; an epoll/AF_UNIX manager is the un-root-caused shape).
//! Parent waits 2.6 s (past the ~2 s first upgrade attempt), then connects to
//! each child's listener AND writes one byte to each socketpair — BOTH
//! fd-backed waiters must wake. A stranded waiter hangs the parent's
//! unbounded waitpid → harness-timeout red (same recorded property as
//! procladder_mixed).
//! Invariants: mgr_forked_all, mgr_children_ok. N default 4 (gate-safe);
//! PROC_LADDER_N overrides.
```

Full implementation requirements (pattern the code on `procladder_mixed.rs` for fork/report/SIGPIPE and on `spliceunixpoll.rs` for the AF_UNIX listener + `epoll_create1`/`epoll_ctl` calls):
- Pre-fork per child: `socketpair(AF_UNIX, SOCK_STREAM)`; parent keeps one end.
- Child: unlink+bind `/tmp/pl_mgr_<i>.sock`, `listen(8)`; thread A: own epfd + ADD listener EPOLLIN → `epoll_wait(-1)` → `accept` → `read` 1 byte → `write` 1 byte to an internal notify pipe → then `loop { pause(); }`; thread B: `loop { nanosleep(3s) }`; main: own epfd + ADD socketpair-end EPOLLIN + ADD notify-pipe read end EPOLLIN → loop `epoll_wait(-1)` until BOTH the socketpair byte and the notify byte have been read → `_exit(0)`.
- Parent: `nanosleep(2.6s)`; per child: `socket+connect` to the child's path, `write` 1 byte; `write` 1 byte to the socketpair end; then `waitpid` each child, count clean exits; `report!(mgr_forked_all = …, mgr_children_ok = …)`.

- [ ] **Step 3: Gate-shape verification (veto ON — must be green and MATCH)**

```bash
scripts/build-probes.sh && scripts/build-signed.sh
scripts/run-probe.sh procladder_epollmgr
```
Expected: MATCH (`mgr_forked_all=true mgr_children_ok=true` both sides). If carrick DIFFs here with the veto ON, that is a NEW bug — stop and report before proceeding.

- [ ] **Step 4: The experiment — veto neutered (one-shot, recorded)**

```bash
RUN_ID=cr-clb-$$; base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/procladder_epollmgr | \
  CARRICK_MT_VM_LEASE_FDBACKED=1 CARRICK_RUN_ID=$RUN_ID timeout 120 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p'; echo "rc=$?"
```
Two recorded outcomes:
- **RED (timeout/hang)** → the reproducer exists. Do NOT kill it blind: attach and take cores of the stuck child(ren) (`lldb -p <pid> -o 'process save-core cluster-b-<pid>.core' -o detach -o quit`), then root-cause with the carrick-lldb skill (event ring: was the kqueue kicked? did the waker claim? did `rebind_shared_wait_state_mt` run? what does the epoll wake registry hold?). Write `.superpowers/sdd/cluster-b-rootcause.md` with the mechanism.
- **GREEN** → escalate the shape ONE variable at a time, one run each, recording each: (i) EPOLLET on all registrations; (ii) orphan the children (double-fork; the 38232 manager was ppid=1); (iii) give each child an inherited dup of a parent pipe whose EOF the parent later needs (the forkserver alive-fd chain). If all three stay green, record the negative result honestly: the veto's justification narrows, but it is NOT lifted in this campaign — that decision needs the real forkserver core shape revisited.

- [ ] **Step 5: Commit probe + findings**

```bash
cargo fmt
git add conformance-probes/src/bin/procladder_epollmgr.rs .superpowers/sdd/cluster-b-rootcause.md
git commit -m "probe(conformance): procladder_epollmgr drives the release attempt under epoll/AF_UNIX fd-waiters"
```
(If Step 4 root-caused a fix-able wake gap: STOP here and get review — a wake-path fix is its own red-first task, not a drive-by.)

---

### Task 6: epoll-ET p50 pre-existing-debt bisect

**Files:**
- Create: `scripts/perf/bisect-epoll-p50.sh`
- Create (finding): append a section to `docs/2026-07-09-mt-residency-lease-evidence.md` or a note in `docs/perf-results/`

**Interfaces:**
- Consumes: `perf_epoll_pipe_loop` probe (prints `epoll_pipe_loop_p50_us=`), `scripts/build-signed.sh`, window `0572d32f..9baacd44` (good ≈ 33.2 µs, bad ≈ 50.9 µs).
- Produces: the culprit commit hash + a recorded fix/defer decision.

- [ ] **Step 1: Write the bisect predicate**

Create `scripts/perf/bisect-epoll-p50.sh` (chmod +x):

```bash
#!/bin/bash
# `git bisect run` predicate for the perf_epoll_pipe_loop p50 regression
# window 0572d32f..9baacd44 (good ≈33µs, bad ≈51µs; threshold 42µs on the
# median of 3 one-shot runs). Quiet host required; no concurrent lanes.
# EPOLL_PROBE must point at a probe binary built ONCE at HEAD (the guest
# binary is independent of the carrick commit under test).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
./scripts/build-signed.sh >/dev/null 2>&1 || exit 125   # unbuildable commit: skip
: "${EPOLL_PROBE:?set EPOLL_PROBE=/abs/path/to/perf_epoll_pipe_loop}"
runs=()
for i in 1 2 3; do
  p50=$(base64 -i "$EPOLL_PROBE" | CARRICK_RUN_ID="bisect-$$-$i" timeout 120 \
    target/release/carrick run ubuntu:24.04 --raw --fs host \
    /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' 2>/dev/null \
    | awk -F= '/^epoll_pipe_loop_p50_us=/{print $2}')
  [ -n "$p50" ] || exit 125                             # run failed here: skip
  runs+=("$p50")
done
median=$(printf '%s\n' "${runs[@]}" | sort -n | sed -n 2p)
echo "bisect $(git rev-parse --short HEAD): p50 median ${median}us" >&2
awk -v m="$median" 'BEGIN { exit (m < 42.0) ? 0 : 1 }'
```

- [ ] **Step 2: Sanity-check both endpoints before bisecting**

In a dedicated worktree (`git worktree add ../carrick-bisect 9baacd44`), with `EPOLL_PROBE` exported to the main tree's built probe:

```bash
cd ../carrick-bisect
EPOLL_PROBE=<abs path> ../carrick/scripts/perf/bisect-epoll-p50.sh; echo "9baacd44 -> $?"   # expect 1 (bad)
git checkout 0572d32f
EPOLL_PROBE=<abs path> ../carrick/scripts/perf/bisect-epoll-p50.sh; echo "0572d32f -> $?"   # expect 0 (good)
```
Expected: 1 then 0. If either endpoint misclassifies, STOP — the threshold or the window is wrong; record and re-derive before burning a bisect.

- [ ] **Step 3: Run the bisect (~7 steps × build+3 runs)**

```bash
git bisect start 9baacd44 0572d32f
EPOLL_PROBE=<abs path> git bisect run ../carrick/scripts/perf/bisect-epoll-p50.sh
git bisect log | tail -5
git bisect reset
```
Expected: a single culprit commit. Record its hash, subject, and the p50 medians at culprit and culprit~1.

- [ ] **Step 4: Record the decision + commit**

Append a `## epoll-ET p50 debt window: bisect result` section to the evidence doc (culprit, numbers, and the decision: fix only if the culprit is an obvious one-liner; otherwise file it as a named follow-up with the mechanism hypothesis). Remove the worktree.

```bash
cargo fmt   # no-op guard
git add scripts/perf/bisect-epoll-p50.sh docs/
git commit -m "perf(epoll): bisect the 33->51us epoll_pipe_loop p50 window to its culprit"
```

---

### Task 7: Final battery + evidence addendum

**Files:**
- Create: `docs/2026-07-10-next-track-evidence.md` (or the current date)

- [ ] **Step 1: Full test + gate battery (one-shot each, in this order, nothing concurrent)**

```bash
cargo test -p carrick-thread -p carrick-runtime -p carrick-vmm-hvf -p carrick-kernel -p carrick-signal-core --lib
just ci          # fmt + clippy + build + test, sequentially — CI masks nothing this way
scripts/run-probe.sh procladder && scripts/run-probe.sh procladder_mt && \
  scripts/run-probe.sh procladder_mixed && scripts/run-probe.sh procladder_epollmgr
# @160 lease-ON gate (Task 2 Step 5 command): GREEN
# Task 2 Step 6 (a)+(b) EAGAIN shapes: still no trap fatals
# LTP six-pack + go-os_exec (evidence doc's commands): 6/6 + 86/86 MATCH
# CPython forkserver: SUCCESS
# perf floors: perf_fork ≤2.5ms, perf_fork_exec recorded, perf_wait_pipe_pingpong ≤50µs,
#   perf_futex_pingpong 31-34µs, perf_epoll_pipe_loop p50 recorded (pre-existing ~51µs unless Task 6 fixed it)
```
Expected: everything green/MATCH; any divergence gets an AMENDMENT and stops the campaign for review.

- [ ] **Step 2: Write the evidence doc**

Follow the structure of `docs/2026-07-09-mt-residency-lease-evidence.md` (Host / Verdict / Changes / Measurements / Load Sensitivity / Verification Commands / Next Track): verbatim numbers only, refuted designs marked refuted, the Task 5 outcome (root cause or honest negative), the Task 6 culprit, and a new Next Track ledger (e.g. veto-lift decision, `target_tid` for non-main-thread cross-process routing, flock-path residency).

- [ ] **Step 3: Commit**

```bash
cargo fmt
git add docs/
git commit -m "docs(evidence): next-track campaign — resident-VM gate, skip-resume, xsig target_tid, cluster-B, epoll bisect"
```

## Explicitly out of scope

- Lifting the fd-backed veto default (`VcpuParkClass::FdBacked` still vetoes; gated on the cluster-B root cause per the recorded reviewer condition).
- Cross-process thread-directed routing to NON-main threads (the ring is addressed by host pid; `target_tid` fixes the delivery side only).
- Resident-VM accounting for the flock permit fallback path (`CARRICK_HVF_ATOMIC_PERMIT=0` keeps the historical permit-only gate).
- Fixing the Task 6 culprit unless it is an obvious one-liner.
- Any change to `GLOBAL_VCPU_CEILING`/admission budgets beyond adding the VM-slot probe.
