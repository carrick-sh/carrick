# Identity-Aware vCPU Lease Drain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace scalar vCPU lease counts with a unique identity-aware drain freeze that prevents sibling re-registration through fork and crash protected work.

**Architecture:** `GenericVcpuRegistry` owns one locked identity map, one optional unique freeze, and one-shot membership/thaw subscriptions. Process fork and crash capture acquire an RAII `VcpuLeaseDrainGuard`; production vCPU registration becomes a typed enrollment that preserves census-before-registry ordering and stores denied admission outside `HvpatchProductionPhase`. Diagnostic probes receive a waiting identity rather than a scalar lease count.

**Tech Stack:** Rust 2024, `Arc`/`Weak`, `Mutex`, atomics, USDT via `carrick-observability`, DTrace, Cargo/Just, Python source-contract tests.

**Spec:** `docs/superpowers/specs/2026-08-28-identity-aware-vcpu-lease-drain.md`

## Global Constraints

- Read `/Volumes/CaseSensitive/carrick/AGENTS.md` before editing; use `just test`, never a bare workspace `cargo test`.
- Use `RUSTC_WRAPPER=` for every Cargo/Just verification command.
- TDD is red-first: each behavior test must fail against the pre-change implementation before its production code lands.
- `VcpuLeaseDrainPoll::Complete` is diagnostic only; protected work requires `VcpuLeaseDrainEnrollment::Frozen(VcpuLeaseDrainGuard)`.
- A freeze is unique and non-refcounted. Any second enrollment, including the same owner, returns typed `Busy`.
- The registry lock atomically couples identity observation, freeze installation, registration admission, and subscription enrollment. Callbacks execute only after releasing that lock.
- Census participation remains before registry publication. A denied registration uses the ordinary suspension path to drop the just-entered census participation.
- Registration-wait state is a sidecar on `ProductionHvpatchLoopJob`; it must never replace or consume `HvpatchProductionPhase`.
- Fork/crash barriers are released before the drain guard is dropped. Crash retains the guard through `CrashQuorum`, every live `read_core_bytes`, and owned core-byte construction.
- Preserve `VcpuRegistry::any_other_in_guest` as page-table drain authority and `CrashQuorum` as register-inventory authority.
- Delete the infallible `VcpuRegistry::register` and scalar `VcpuRegistry::count`; no renamed or wrapped scalar substitute is allowed.
- Do not change or re-bless unrelated host-authority inventory drift. It is acceptable only when the checker reports `changed=[]`.
- Never run Carrick and Docker concurrently. No guest run is required before the final signed acceptance decision.
- Delegation: Codex owns Tasks 1, 3, 4, and 5 architecture and acceptance. Antigravity may implement the file-disjoint mechanical migrations in Task 2, the repetitive fork teardown rewrite within Task 4 after interfaces land, and Task 6. Codex reviews actual diffs, reruns gates, and sends findings back to the same conversation for at most three repair rounds.

## File Structure

- `crates/carrick-hal/src/threaded.rs`: public drain/registration enrollment types, opaque subscription/guard, shared registry state, atomic publication rules, core protocol tests.
- `crates/carrick-hal/src/lib.rs`: public re-exports for the new HAL types.
- `crates/carrick-hal/src/pump_fork_coord.rs`: inert trait implementation used by signal-pump tests.
- `crates/carrick-hal/src/timer_delivery.rs`: test-only direct registration migration.
- `crates/carrick-vmm-hvf/src/vcpu_kick.rs`: HVF registry test migration.
- `crates/carrick-vmm-kvm/src/kvm_kicker.rs`: KVM registry test migration.
- `crates/carrick-runtime/src/vcpu_loop/threads.rs`: sole production registration wrapper becomes typed enrollment.
- `crates/carrick-runtime/src/vcpu_loop/mod.rs`: registration-wait sidecar, production admission flow, crash drain helper/budget, crash guard lifetime, source-contract tests.
- `crates/carrick-runtime/src/threaded_loop.rs`: update the module authority map
  that names the old `register_vcpu` wrapper.
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`: fork drain enrollment, retry subscription, fork RAII teardown, diagnostic mapper, probe call, fork tests.
- `crates/carrick-runtime/src/kernel/guest_execution.rs`: correct transient-census authority documentation.
- `crates/carrick-runtime/src/lib.rs`: correct blocking-wait/fork drain authority documentation.
- `crates/carrick-thread/src/fork_quiesce.rs`: identity-aware hermetic stress fixture and comments.
- `crates/carrick-observability/src/probes.rs`: `pt-pause-begin` ABI argument rename and documentation.
- `scripts/dtrace/hvpatch-stop-the-world.d`: narrower peer-executor/no-sibling-lease metric.
- `scripts/dtrace/hvpatch-fork-wait-amplification.d`: ABI comment audit.
- `docs/identity-and-scope-domains.md`: partial implementation receipt.

---

### Task 1: Atomic HAL Lease Freeze Protocol

**Files:**
- Modify: `crates/carrick-hal/src/threaded.rs:186-470`
- Modify: `crates/carrick-hal/src/lib.rs:45-60`
- Modify: `crates/carrick-hal/src/pump_fork_coord.rs:74-105`
- Modify: `crates/carrick-hal/src/timer_delivery.rs:115-145`

**Interfaces:**
- Consumes: existing `ThreadId`, `InGuestFlag`, `VcpuKickDyn`, `VcpuRegistration`.
- Produces:
  - `pub enum VcpuLeaseDrainPoll { Complete, Waiting(ThreadId) }`
  - `pub struct VcpuLeaseChangeSubscription`
  - `pub struct VcpuLeaseDrainGuard`
  - `pub enum VcpuLeaseDrainEnrollment { Frozen(VcpuLeaseDrainGuard), Waiting { tid, subscription }, Busy { owner, subscription } }`
  - `pub enum VcpuRegistrationEnrollment { Registered, Waiting { owner, subscription } }`
  - `VcpuRegistry::{poll_lease_drain, subscribe_lease_drain, subscribe_register}`
  - temporary compatibility `register`/`count` methods retained only so later
    tasks compile independently; Task 6 deletes them after the last caller moves.

- [ ] **Step 1: Add red identity and freeze tests**

Add focused tests under `generic_registry_tests` before defining the new API:

```rust
#[test]
fn lease_drain_is_identity_aware_and_freezes_registration() {
    let registry = GenericVcpuRegistry::new();
    let owner = t(10);
    let sibling = t(20);
    let owner_flag = InGuestFlag::for_guest_thread();
    let sibling_flag = InGuestFlag::for_guest_thread();
    assert!(matches!(
        registry.subscribe_register(owner, noop(), &owner_flag, Arc::new(|| {})),
        VcpuRegistrationEnrollment::Registered
    ));
    assert_eq!(registry.poll_lease_drain(owner), VcpuLeaseDrainPoll::Complete);
    let guard = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
        VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
        _ => panic!("sole owner must freeze"),
    };
    assert!(matches!(
        registry.subscribe_register(sibling, noop(), &sibling_flag, Arc::new(|| {})),
        VcpuRegistrationEnrollment::Waiting { owner: waiting, .. } if waiting == owner
    ));
    assert_eq!(registry.poll_lease_drain(owner), VcpuLeaseDrainPoll::Complete);
    drop(guard);
    assert!(matches!(
        registry.subscribe_register(sibling, noop(), &sibling_flag, Arc::new(|| {})),
        VcpuRegistrationEnrollment::Registered
    ));
    assert_eq!(registry.poll_lease_drain(owner), VcpuLeaseDrainPoll::Waiting(sibling));
}
```

Add separate tests named:

```rust
lease_drain_absent_owner_still_waits_on_only_registration
lease_drain_returns_lowest_sibling_identity
lease_drain_same_owner_reentry_is_busy
lease_guard_drop_wakes_busy_drain_and_registration_waiters
lease_membership_mutation_wakes_waiter_after_removal
lease_registration_replacement_does_not_publish_membership_change
lease_subscription_drop_cancels_only_unclaimed_listener
```

In the guard-drop test, use two `Arc<AtomicUsize>` counters and assert both are
zero before `drop(guard)` and one after it. In the replacement test, enroll a
drain waiter with a sibling present, replace that sibling under the same
identity, and assert the callback remains zero.

- [ ] **Step 2: Run the tests to prove RED**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-hal generic_registry_tests::lease_ -- --nocapture
```

Expected: compilation fails because `subscribe_register`,
`subscribe_lease_drain`, and the enrollment types do not exist.

- [ ] **Step 3: Implement one Arc-owned registry state**

Replace the map-only field with an `Arc<Mutex<VcpuRegistryState>>`:

```rust
type VcpuLeaseChangeCallback = Arc<dyn Fn() + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VcpuLeaseListenerKind {
    Membership,
    Thaw,
}

struct VcpuLeaseListener {
    kind: VcpuLeaseListenerKind,
    callback: VcpuLeaseChangeCallback,
}

struct VcpuLeaseFreeze {
    owner: ThreadId,
    generation: u64,
}

struct VcpuRegistryState {
    vcpus: HashMap<ThreadId, VcpuRegistration>,
    freeze: Option<VcpuLeaseFreeze>,
    listeners: BTreeMap<u64, VcpuLeaseListener>,
    next_listener: u64,
    next_freeze_generation: u64,
}

impl Default for VcpuRegistryState {
    fn default() -> Self {
        Self {
            vcpus: HashMap::new(),
            freeze: None,
            listeners: BTreeMap::new(),
            next_listener: 1,
            next_freeze_generation: 1,
        }
    }
}

#[derive(Default)]
pub struct GenericVcpuRegistry {
    state: Arc<Mutex<VcpuRegistryState>>,
}
```

Implement checked, nonzero listener/freeze id allocation with
`checked_add(1).unwrap_or_else(|| std::process::abort())`. Recover poisoned
mutexes with `unwrap_or_else(|error| error.into_inner())`, matching current
behavior.

- [ ] **Step 4: Implement opaque subscription and unique guard Drop**

Use `Weak<Mutex<VcpuRegistryState>>` plus exact ids:

```rust
pub struct VcpuLeaseChangeSubscription {
    state: Weak<Mutex<VcpuRegistryState>>,
    listener_id: u64,
}

pub struct VcpuLeaseDrainGuard {
    state: Weak<Mutex<VcpuRegistryState>>,
    owner: ThreadId,
    generation: u64,
}
```

`VcpuLeaseChangeSubscription::drop` removes only its still-present exact
listener. `VcpuLeaseDrainGuard::drop` verifies `(owner, generation)`, clears the
freeze, takes every `Thaw` listener, unlocks, and invokes the callbacks. A
mismatched live freeze is a carrier invariant failure and calls
`std::process::abort()`; a dropped registry needs no action.

- [ ] **Step 5: Implement atomic poll, drain enrollment, and registration enrollment**

The trait methods must use these decisions while holding the same state lock:

```rust
fn lowest_sibling(state: &VcpuRegistryState, except: ThreadId) -> Option<ThreadId> {
    state.vcpus.keys().copied().filter(|tid| *tid != except).min()
}
```

`subscribe_lease_drain` checks `state.freeze` first and returns `Busy` for any
existing freeze, including the same owner. Otherwise it returns `Waiting` plus
a `Membership` listener when `lowest_sibling` exists, or installs one freeze
and returns `Frozen`.

`subscribe_register` returns `Waiting` plus a `Thaw` listener only when a
different owner holds the freeze. Otherwise it inserts/replaces the exact
registration. Only insertion of a previously absent key takes `Membership`
listeners. `unregister` takes `Membership` listeners only when removal returned
`Some`. Every callback batch runs after dropping the mutex guard.

- [ ] **Step 6: Migrate HAL-local users and retain explicit temporary shims**

Re-export all five new public types in `carrick-hal/src/lib.rs`. Make
`InertRegistry` a thin wrapper around one `GenericVcpuRegistry` and delegate
`register`, `unregister`, `poll_lease_drain`, `subscribe_lease_drain`, and
`subscribe_register` to that same inner authority. During the temporary
compatibility phase, `count` must also delegate to the same inner registry; it
must not retain the old hard-coded zero. Only kick behavior may remain inert
through noop handles. Update `timer_delivery.rs` to assert its test enrollment
is `Registered`.

Retain `VcpuRegistry::register` and `count` as clearly commented temporary
compatibility methods until Task 6. `GenericVcpuRegistry::register` delegates to
`subscribe_register(tid, handle, in_guest, Arc::new(|| {}))` and aborts if a freeze denies the
legacy caller; `count` remains a diagnostic map length. Do not mark either
`#[deprecated]`, because dependent crates build under `-D warnings`. No new
production decision may use them.

- [ ] **Step 7: Run focused HAL verification**

Run:

```bash
RUSTC_WRAPPER= cargo test -p carrick-hal generic_registry_tests -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-hal pump_fork_coord -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-hal timer_delivery -- --nocapture
RUSTC_WRAPPER= cargo check -p carrick-hal
```

Expected: all commands exit zero.

- [ ] **Step 8: Commit the HAL protocol**

```bash
git add crates/carrick-hal/src/threaded.rs crates/carrick-hal/src/lib.rs crates/carrick-hal/src/pump_fork_coord.rs crates/carrick-hal/src/timer_delivery.rs
git commit -m "feat(hal): add identity-aware vcpu lease freeze"
```

---

### Task 2: Mechanical Backend Registry Migration

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/vcpu_kick.rs:640-870`
- Modify: `crates/carrick-vmm-kvm/src/kvm_kicker.rs:110-230`

**Interfaces:**
- Consumes: Task 1 `VcpuRegistrationEnrollment`, `VcpuLeaseDrainPoll`, and
  `VcpuRegistry::subscribe_register`.
- Produces: backend tests with no direct `register` or scalar `count` use.

- [ ] **Step 1: Dispatch the file-disjoint migration to Antigravity**

Create an isolated branch/worktree from the exact Task 1 commit. The brief must
limit writes to the two backend files, require reading `AGENTS.md`, and require:

```text
Replace each test-only VcpuRegistry::register call with subscribe_register and
assert Registered. Replace count assertions with exact poll_lease_drain
assertions relative to a named synthetic observer. Do not recreate a scalar
count helper. Preserve all kick/in_guest assertions. Run:
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf vcpu_kick --lib
RUSTC_WRAPPER= cargo test -p carrick-vmm-kvm kvm_kicker --lib
Do not report tests_passing=true unless both exit zero.
```

- [ ] **Step 2: Verify the legacy backend shapes are present before migration**

Before integrating the worker commit, run on the Task 1 branch:

```bash
rg -n "\.register\(|\.count\(\)" crates/carrick-vmm-hvf/src/vcpu_kick.rs crates/carrick-vmm-kvm/src/kvm_kicker.rs
```

Expected: matches at the existing direct registration and scalar-count test
assertions. Save this output as the red mechanical receipt; the same command
must have no registry API matches after the migration.

- [ ] **Step 3: Review and integrate the worker diff**

Reject any helper returning `usize`, any `debug_registered_vcpus().len()`
decision, or any loss of existing kick/in-guest assertions. Send findings to
the same Antigravity conversation and require both focused commands again.
Fast-forward or cherry-pick only after the actual diff and both commands pass.

- [ ] **Step 4: Run backend verification locally**

```bash
RUSTC_WRAPPER= cargo test -p carrick-vmm-hvf vcpu_kick --lib
RUSTC_WRAPPER= cargo test -p carrick-vmm-kvm kvm_kicker --lib
RUSTC_WRAPPER= cargo check -p carrick-vmm-hvf -p carrick-vmm-kvm
```

Expected: all commands exit zero.

- [ ] **Step 5: Record the integrated commit**

If the worker commit was not already suitably scoped, commit the reviewed
integration:

```bash
git add crates/carrick-vmm-hvf/src/vcpu_kick.rs crates/carrick-vmm-kvm/src/kvm_kicker.rs
git commit -m "test(vmm): migrate vcpu registry identity assertions"
```

---

### Task 3: Production Registration Admission Sidecar

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/threads.rs:250-275`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:2953-2970, 5550-5580, 8070-8140, 10980-11220`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs:1-30`

**Interfaces:**
- Consumes: Task 1 `VcpuRegistrationEnrollment` and
  `VcpuLeaseChangeSubscription`.
- Produces:
  - `ThreadRuntimeState::subscribe_register_vcpu(engine, callback)`
  - `ProductionHvpatchLoopJob::registration_wait: Option<VcpuLeaseChangeSubscription>`
  - `enter_guest_executor_then_register`, the production-used ordering seam.

- [ ] **Step 1: Add red source-contract and interleaving tests**

Add tests in the existing `vcpu_loop/mod.rs` source-contract module:

```rust
#[test]
fn production_registration_keeps_census_before_registry_publication() {
    let source = include_str!("mod.rs");
    let poll = source.split("fn poll_with_engine(").nth(1).unwrap();
    assert!(
        poll.find("guest_executors").unwrap()
            < poll.find("subscribe_register_vcpu").unwrap()
    );
}

#[test]
fn registration_wait_is_sidecar_not_hvpatch_phase() {
    let source = include_str!("mod.rs");
    let job = source.split("struct ProductionHvpatchLoopJob").nth(1).unwrap();
    assert!(job.contains("registration_wait: Option<carrick_hal::VcpuLeaseChangeSubscription>"));
    let phases = source
        .split("enum HvpatchProductionPhase")
        .nth(1)
        .unwrap()
        .split("impl HvpatchProductionPhase")
        .next()
        .unwrap();
    assert!(!phases.contains("RegistrationWait"));
}
```

Add behavior tests that call the not-yet-existing production seam with a real
`GenericVcpuRegistry`, `GuestExecutorCensus`, and synthetic threads:

- `page_table_admission_census_precedes_denied_registry_publication` holds the
  first participation and its drain freeze, calls
  `enter_guest_executor_then_register` for a second thread, and asserts inside
  the registration closure that the census already has a peer before registry
  admission returns `Waiting`.
- `fork_owner_registration_ignores_raised_barrier_and_preserves_phase` raises a
  real `QuiesceBarrier`, retains an exact `RetryProcessFork` phase value, and
  calls the same seam for the freeze owner. It asserts `Registered`, unchanged
  phase, and a still-raised barrier.
- `registration_thaw_wakes_external_exec_control_quantum` constructs a denied
  registration while the phase is `RetryProcessFork { external_exec: Some(_),
  .. }`, drops the freeze, and proves the callback routes through
  `wake_control`, not guest-continuation `wake`.
- `registration_thaw_wakes_pending_control_quantum_before_phase_transition`
  keeps the phase `Resident`, publishes an external-exec scheduler control
  quantum, denies registration behind a freeze, and proves thaw calls
  `wake_control` while leaving the guest continuation untouched.

Add a source-contract test that bounds the `poll_with_engine` registration
block and proves it calls the helper without `is_quiescing`, `try_begin_fork`,
or assigning `self.phase`.

- [ ] **Step 2: Run the tests to prove RED**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime production_registration_keeps_census_before_registry_publication --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime registration_wait_is_sidecar_not_hvpatch_phase --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime page_table_admission_census_precedes_denied_registry_publication --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime fork_owner_registration_ignores_raised_barrier_and_preserves_phase --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime registration_thaw_wakes_external_exec_control_quantum --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime registration_thaw_wakes_pending_control_quantum_before_phase_transition --lib -- --nocapture
```

Expected: source assertions fail and behavior tests compile-fail because the
sidecar, wake-mode helper, and production admission seam do not exist.

- [ ] **Step 3: Convert the production registration wrapper**

Replace `register_vcpu` with:

```rust
pub(super) fn subscribe_register_vcpu(
    &self,
    engine: &E,
    callback: Arc<dyn Fn() + Send + Sync + 'static>,
) -> carrick_hal::VcpuRegistrationEnrollment {
    let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
    let enrollment = self.kicker.subscribe_register(
        self.this_tid,
        handle,
        &self.in_guest,
        callback,
    );
    if matches!(enrollment, carrick_hal::VcpuRegistrationEnrollment::Registered) {
        self.registry.record_thread_port(
            self.this_tid,
            crate::host_proc::current_thread_port(),
        );
    }
    enrollment
}
```

Add the production-used ordering seam now that its tests are recorded red:

```rust
fn enter_guest_executor_then_register<F>(
    census: &Arc<crate::kernel::GuestExecutorCensus>,
    thread: Option<crate::kernel::ThreadRef>,
    register: F,
) -> (
    crate::kernel::GuestExecutorParticipation,
    carrick_hal::VcpuRegistrationEnrollment,
)
where
    F: FnOnce() -> carrick_hal::VcpuRegistrationEnrollment,
{
    let participation = census.enter(thread);
    let enrollment = register();
    (participation, enrollment)
}
```

- [ ] **Step 4: Add and initialize the sidecar**

Add this field to `ProductionHvpatchLoopJob` and initialize it to `None` in
every constructor:

```rust
registration_wait: Option<carrick_hal::VcpuLeaseChangeSubscription>,
```

At the start of a fresh admitted poll, drop the prior claimed/unclaimed sidecar
before creating a new enrollment. Add a pure production-used wake-mode helper
that returns control mode when a non-consuming `control_quantum()` inspection
before enrollment reports a pending scheduler control quantum, or when the
phase is `RetryProcessFork { external_exec: Some(_), .. }`; it returns ordinary
mode only when neither condition holds. Build the callback from that captured
mode, the exact scheduler, and
`kernel_thread.key()`; it calls `scheduler.wake_control(thread_key)` in control
mode and `scheduler.wake(thread_key)` otherwise. The callback must not inspect a
later phase value after enrollment, and the pre-enrollment inspection must not
consume or finish the scheduler control quantum.

Keep both inputs portable: implement the `RetryProcessFork` pattern only inside
the existing macOS/AArch64 cfg, return ordinary mode for that phase dimension on
other targets, and calculate pending control with the same cfg split:

```rust
fn registration_wake_uses_control(
    phase: &HvpatchProductionPhase,
    pending_control_quantum: bool,
) -> bool {
    if pending_control_quantum {
        return true;
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        matches!(
            phase,
            HvpatchProductionPhase::RetryProcessFork {
                external_exec: Some(_),
                ..
            }
        )
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = phase;
        false
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
let pending_control_quantum = self.control_quantum()?.is_some();
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
let pending_control_quantum = false;
```

- [ ] **Step 5: Preserve census-before-registry order and suspend denied admission**

Use the production helper so census admission occurs before the closure can
publish registry membership:

```rust
let registration_wake_mode = registration_wake_uses_control(
    &self.phase,
    pending_control_quantum,
);
let (participation, enrollment) = enter_guest_executor_then_register(
    &self.kernel.guest_executors,
    self.state.kernel_thread.as_ref().map(Arc::clone),
    || self.state.subscribe_register_vcpu(engine, wake_registration),
);
self.state.guest_execution = Some(participation);
```

Then match the registry result:

```rust
match enrollment {
    carrick_hal::VcpuRegistrationEnrollment::Registered => {}
    carrick_hal::VcpuRegistrationEnrollment::Waiting { subscription, .. } => {
        self.registration_wait = Some(subscription);
        return Ok(self.suspend(
            HvpatchLoopSuspension::InitialAdmission,
            executor::ExecutorExit::Blocked(
                crate::kernel::objects::BlockedReason::HostWait,
            ),
        ));
    }
}
```

Do not add a barrier precheck. Do not change `self.phase`. The ordinary
`suspend` must unregister the absent key harmlessly and drop census/crash
participation through `leave_executor`.

- [ ] **Step 6: Make the red production admission tests green**

Use a real `GenericVcpuRegistry`, `GuestExecutorCensus`, and two synthetic
threads. Hold the first participation, acquire a drain freeze owned by the
first, then call the real `enter_guest_executor_then_register` seam for the
second. Inside its registration closure, assert `census.has_peer_executor()`
before attempting the denied registry publication. After it returns, assert:

```rust
assert!(census.has_peer_executor());
assert!(matches!(attempt, VcpuRegistrationEnrollment::Waiting { .. }));
assert_eq!(registry.poll_lease_drain(first), VcpuLeaseDrainPoll::Complete);
```

Drop the denied thread's participation and assert the census returns to one.
This pins the exact ordering that prevents a page-table editor from seeing a
false zero before publication.

Retain the exact-owner and external-exec control-quantum tests added in Step 1.
The owner test deliberately passes no barrier into the helper, proving the
production admission path cannot acquire a self-deadlocking barrier precheck.
The thaw test must demonstrate that dropping the freeze makes the denied job's
control quantum runnable without resuming its guest continuation.

- [ ] **Step 7: Run focused runtime verification**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime production_registration --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime registration_wait --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime page_table_admission_census_precedes_denied_registry_publication --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime fork_owner_registration_ignores_raised_barrier_and_preserves_phase --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime registration_thaw_wakes_external_exec_control_quantum --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime registration_thaw_wakes_pending_control_quantum_before_phase_transition --lib -- --nocapture
RUSTC_WRAPPER= cargo check -p carrick-runtime
```

Expected: all commands exit zero.

- [ ] **Step 8: Commit production admission**

```bash
git add crates/carrick-runtime/src/vcpu_loop/threads.rs crates/carrick-runtime/src/vcpu_loop/mod.rs crates/carrick-runtime/src/threaded_loop.rs
git commit -m "feat(runtime): freeze vcpu registration admission"
```

---

### Task 4: Process-Fork Drain Guard and RAII Teardown

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:300-1480`
- Modify: `crates/carrick-thread/src/fork_quiesce.rs:1120-1210`

**Interfaces:**
- Consumes: Task 1 `VcpuLeaseDrainEnrollment`, `VcpuLeaseDrainGuard`,
  `VcpuLeaseChangeSubscription`; Task 3 owner re-registration behavior.
- Produces:
  - `ProcessForkRetrySubscription::Lease`
  - unique guard retained across the full fork transaction
  - one RAII release authority enforcing `end_quiesce -> end_fork -> drop guard`.

- [ ] **Step 1: Add red production source-contract, release-order, and registry regression tests**

Add a source-contract test bounded to `prepare_in_process_fork` that requires
`subscribe_lease_drain` and `ProcessForkRetrySubscription::Lease`, and rejects
`kicker.count()`, `subscribe_quiesced_progress`, and
`ProcessForkRetrySubscription::Progress` inside that function. This is the
red-first proof of the production fork decision; it must fail before Step 3.

The exact-owner production admission test from Task 3 is the red-first proof
that a retry does not barrier-precheck or mutate the logical phase. Keep the
following registry-level tests as regression coverage for wake and freeze
semantics; they are not claimed as red after Task 1:

Add focused tests proving:

```rust
#[derive(Clone)]
struct NoopKick;

impl VcpuKickDyn for NoopKick {
    fn kick(&self) {}
}

fn noop_kick() -> Box<dyn VcpuKickDyn> {
    Box::new(NoopKick)
}

fn register_for_test(
    registry: &GenericVcpuRegistry,
    tid: ThreadId,
    flag: &InGuestFlag,
) {
    assert!(matches!(
        registry.subscribe_register(tid, noop_kick(), flag, Arc::new(|| {})),
        VcpuRegistrationEnrollment::Registered
    ));
}

#[test]
fn fork_lease_wait_wakes_on_terminal_unregister_without_barrier_progress() {
    let registry = GenericVcpuRegistry::new();
    let owner = ThreadId::synthetic_for_tests(10);
    let sibling = ThreadId::synthetic_for_tests(20);
    let owner_flag = InGuestFlag::for_guest_thread();
    let sibling_flag = InGuestFlag::for_guest_thread();
    register_for_test(&registry, owner, &owner_flag);
    register_for_test(&registry, sibling, &sibling_flag);
    let wakes = Arc::new(AtomicUsize::new(0));
    let wake = Arc::clone(&wakes);
    let enrollment = registry.subscribe_lease_drain(
        owner,
        Arc::new(move || { wake.fetch_add(1, Ordering::SeqCst); }),
    );
    assert!(matches!(enrollment, VcpuLeaseDrainEnrollment::Waiting { tid, .. } if tid == sibling));
    registry.unregister(sibling);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
}

#[test]
fn fork_owner_can_retry_while_its_barrier_remains_raised() {
    let registry = GenericVcpuRegistry::new();
    let barrier = QuiesceBarrier::new();
    let owner = ThreadId::synthetic_for_tests(10);
    let sibling = ThreadId::synthetic_for_tests(20);
    let owner_flag = InGuestFlag::for_guest_thread();
    let sibling_flag = InGuestFlag::for_guest_thread();
    register_for_test(&registry, owner, &owner_flag);
    register_for_test(&registry, sibling, &sibling_flag);
    barrier.set_quiescing();
    registry.unregister(owner);
    registry.unregister(sibling);
    assert!(barrier.is_quiescing());
    assert!(matches!(
        registry.subscribe_register(owner, noop_kick(), &owner_flag, Arc::new(|| {})),
        VcpuRegistrationEnrollment::Registered
    ));
    assert!(matches!(
        registry.subscribe_lease_drain(owner, Arc::new(|| {})),
        VcpuLeaseDrainEnrollment::Frozen(_)
    ));
    barrier.end_quiesce();
}

#[test]
fn fork_release_lowers_barriers_before_thaw_callback() {
    let registry = GenericVcpuRegistry::new();
    let barrier = Arc::new(QuiesceBarrier::new());
    let owner = ThreadId::synthetic_for_tests(10);
    let sibling = ThreadId::synthetic_for_tests(20);
    let owner_flag = InGuestFlag::for_guest_thread();
    register_for_test(&registry, owner, &owner_flag);
    assert!(barrier.try_begin_fork());
    barrier.set_quiescing();
    let guard = match registry.subscribe_lease_drain(owner, Arc::new(|| {})) {
        VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
        _ => panic!("owner must freeze"),
    };
    let saw_quiescing = Arc::new(AtomicBool::new(true));
    let observed = Arc::clone(&saw_quiescing);
    let sibling_flag = InGuestFlag::for_guest_thread();
    assert!(matches!(
        registry.subscribe_register(
            sibling,
            noop_kick(),
            &sibling_flag,
            Arc::new({
                let barrier = Arc::clone(&barrier);
                move || observed.store(barrier.is_quiescing(), Ordering::SeqCst)
            }),
        ),
        VcpuRegistrationEnrollment::Waiting { .. }
    ));
    let mut release = ProcessForkRelease::new(Arc::clone(&barrier), true, guard);
    release.release();
    assert!(!saw_quiescing.load(Ordering::SeqCst));
}
```

Extend the hermetic stress fixture to maintain an identity `BTreeSet<ThreadId>`
and an optional freeze owner instead of an `AtomicUsize` count.

- [ ] **Step 2: Run tests to prove RED**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork_uses_identity_lease_subscription --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime fork_release_lowers_barriers_before_thaw_callback --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-thread fork_quiesce_stress --lib -- --nocapture
```

Expected: the production source-contract assertion fails because fork still
uses progress/count, the release-order test compile-fails because
`ProcessForkRelease` does not exist, and the stress fixture still names a
scalar count. The two registry-level semantic tests may already pass and are
run later as regressions.

- [ ] **Step 3: Replace progress retry with registry subscription**

Add:

```rust
Lease {
    _subscription: carrick_hal::VcpuLeaseChangeSubscription,
},
```

Remove the fork drain's `subscribe_quiesced_progress` closure. Use an exact
scheduler wake callback in `subscribe_lease_drain`. `Waiting` kicks/wakes
siblings and returns `Retry` with `ProcessForkRetrySubscription::Lease`; `Busy`
returns the same retry without claiming a membership identity; `Frozen` stores
the guard in fork authority.

Migrate every direct `registry.register` use in this file's tests to
`subscribe_register` while preserving the same identity and kick handle.
This is required before Task 6 deletes the temporary compatibility method.

- [ ] **Step 4: Introduce one fork release authority**

Create an internal RAII value whose `Drop` is the only post-acquisition release
path:

```rust
struct ProcessForkRelease {
    barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
    quiesced: bool,
    drain: Option<carrick_hal::VcpuLeaseDrainGuard>,
    active: bool,
}

impl ProcessForkRelease {
    fn new(
        barrier: Arc<crate::fork_quiesce::QuiesceBarrier>,
        quiesced: bool,
        drain: carrick_hal::VcpuLeaseDrainGuard,
    ) -> Self {
        Self { barrier, quiesced, drain: Some(drain), active: true }
    }

    fn release(&mut self) {
        if !self.active { return; }
        if self.quiesced { self.barrier.end_quiesce(); }
        self.barrier.end_fork();
        drop(self.drain.take());
        self.active = false;
    }
}

impl Drop for ProcessForkRelease {
    fn drop(&mut self) { self.release(); }
}
```

`ProcessForkCoordinator::into_parts` returns this release authority alongside
the two admission permits. It must not set a state that drops the lease guard
before returning it.

- [ ] **Step 5: Delegate the repetitive fork exit-path rewrite to Antigravity**

After Steps 3-4 compile, commit the red tests, drain integration, and release
authority as a Codex-owned checkpoint:

```bash
git add crates/carrick-runtime/src/vcpu_loop/quiesce.rs crates/carrick-thread/src/fork_quiesce.rs
git commit -m "feat(runtime): acquire identity-aware fork drain"
git rev-parse HEAD
```

Create the worker's manual worktree from that exact checkpoint and verify its
HEAD matches before dispatch. This ensures the worker sees the new interfaces
and tests despite sharing `quiesce.rs`. Scope the worker only to
`vcpu_loop/quiesce.rs`. Require it to remove every manual
`process_barrier.end_quiesce/end_fork` after `into_parts`, retain
`ProcessForkRelease` through all fallible preparation/publication branches, and
call `release()` explicitly at the existing successful barrier-release point.
Require:

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib -- --nocapture
RUSTC_WRAPPER= cargo check -p carrick-runtime
```

Review every early return in the actual diff. Send back any path that drops the
guard before backend rollback, topology publication, child activation, or
barrier release.

- [ ] **Step 6: Prove no raw fork count/progress decision survives**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork_uses_identity_lease_subscription --lib -- --nocapture
rg -n "subscribe_quiesced_progress|ProcessForkRetrySubscription::Progress" crates/carrick-runtime/src/vcpu_loop/quiesce.rs
rg -n "kicker\.count" crates/carrick-runtime/src/vcpu_loop/quiesce.rs
```

Expected: the bounded production source contract passes; no progress retry
match remains. The final `rg` may show only the page-table diagnostic site that
Task 6 migrates; it must show no match within `prepare_in_process_fork`.

- [ ] **Step 7: Run fork verification**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime fork_lease --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime fork_owner_registration_ignores_raised_barrier_and_preserves_phase --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-thread fork_quiesce --lib -- --nocapture
RUSTC_WRAPPER= cargo check -p carrick-runtime
```

Expected: all commands exit zero.

- [ ] **Step 8: Commit the reviewed fork integration**

```bash
git add crates/carrick-runtime/src/vcpu_loop/quiesce.rs crates/carrick-thread/src/fork_quiesce.rs
git commit -m "feat(runtime): hold vcpu drain freeze across fork"
```

---

### Task 5: Crash Snapshot Drain Guard and Testable Budget

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:6780-7200`

**Interfaces:**
- Consumes: Task 1 drain enrollment/guard.
- Produces:
  - `CrashLeaseDrainBudget { timeout: Duration, poll_interval: Duration }`
  - `CrashLeaseDrainTimeout::{Waiting(ThreadId), Busy(ThreadId)}`
  - `fn acquire_crash_lease_drain<N>(registry: &dyn VcpuRegistry, owner: ThreadId, budget: CrashLeaseDrainBudget, nudge: N) -> Result<VcpuLeaseDrainGuard, CrashLeaseDrainTimeout> where N: FnMut()`.

- [ ] **Step 1: Add red helper and lifetime tests**

Add tests named:

```rust
crash_lease_drain_short_budget_reports_exact_waiting_tid
crash_lease_drain_short_budget_reports_busy_owner
crash_lease_drain_freezes_late_registration
crash_guard_source_spans_quorum_and_read_core_bytes
crash_teardown_releases_barrier_before_guard
crash_lease_drain_timeout_releases_collection_and_barriers
crash_lease_drain_deadline_reenrolls_after_waiting_member_leaves
crash_lease_drain_park_caps_to_remaining_budget
```

The source-contract test must locate the outer common-cleanup envelope,
`acquire_crash_lease_drain`, `quorum.poll()`, `engine.read_core_bytes`,
`authority.stop_collecting()`, `barrier.end_fork()`, and
`drop(lease_drain_guard)`. Assert that the fallible acquisition and both live
reads occur inside the envelope, while collection stop and both barrier lowers
occur on every exit before guard drop.

Provide a test-only short budget/failpoint for the timeout test. After forcing
a waiting lease through the deadline, assert collection is stopped,
`!barrier.is_quiescing()`, and a new `try_begin_fork()` succeeds (then balance
it with `end_fork()`). This pins cleanup of a failure that occurs after crash
authority and barriers have been acquired.

- [ ] **Step 2: Run tests to prove RED**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_guard_source --lib -- --nocapture
```

Expected: compilation/assertion failure because the helper and guard lifetime
do not exist.

- [ ] **Step 3: Implement the bounded helper**

Use the current thread as a one-shot wake target:

```rust
let waiter = std::thread::current();
let callback = Arc::new(move || waiter.unpark());
```

Loop on `subscribe_lease_drain`. `Frozen` returns the guard. For `Waiting`,
retain the exact tid and subscription; for `Busy`, retain the exact owner and
subscription. Keep that subscription across the corresponding park so
membership/thaw cannot wake a listener that has already been cancelled; drop it
only immediately before re-enrolling. Call the supplied nudge closure, compute
`remaining = deadline.saturating_duration_since(Instant::now())`, and park for
`min(budget.poll_interval, remaining)` so the configured timeout is a real
bound rather than an extra full poll interval. Put that minimum in a pure helper
covered by `crash_lease_drain_park_caps_to_remaining_budget`, avoiding a flaky
wall-clock assertion.

At the deadline, perform one final atomic `subscribe_lease_drain`, never a
diagnostic `poll_lease_drain`: `Frozen` succeeds and returns its guard;
`Waiting { tid, .. }` returns `CrashLeaseDrainTimeout::Waiting(tid)`;
`Busy { owner, .. }` returns `CrashLeaseDrainTimeout::Busy(owner)`. The
Waiting-to-Complete race test synchronizes a sibling unregister immediately
before this final enrollment (a zero timeout plus a nudge closure that performs
the unregister is sufficient) and requires `Frozen`, proving there is no
identity-free `Complete` timeout state. Never return a raw remaining count.

Implement `Display` for `CrashLeaseDrainTimeout` and map it explicitly at the
runtime boundary, for example
`RuntimeError::Configuration(timeout.to_string())`; do not rely on an unstated
`From` conversion for `?`.

- [ ] **Step 4: Replace the crash count loop and retain the guard**

After crash barrier ownership and optional `set_quiescing`, acquire the drain
guard *inside* the same fallible envelope whose epilogue always stops
collection and lowers barriers. The acquisition itself can time out, so it
must not sit before cleanup is installed:

```rust
authority.advertise(generation);
let mut quiesced = false;
let mut lease_drain_guard = None;
let result = (|| {
    if context.task().threads().len() > 1 {
        barrier.set_quiescing();
        quiesced = true;
    }
    lease_drain_guard = Some(
        acquire_crash_lease_drain(
            &*self.kicker,
            self.this_tid,
            CrashLeaseDrainBudget::DEFAULT,
            || {
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
            },
        )
        .map_err(|timeout| RuntimeError::Configuration(timeout.to_string()))?,
    );
    // prepare_core_snapshot, process snapshot, CrashQuorum,
    // read_core_bytes, serialization, and owned PreparedCorePublication
})();
authority.stop_collecting();
if quiesced { barrier.end_quiesce(); }
barrier.end_fork();
drop(lease_drain_guard);
result
```

`try_begin_fork` may remain before this envelope because its failure happens
before collection or quiesce publication. Do not move `CrashQuorum` or live
memory reads outside the envelope/guard.

- [ ] **Step 5: Run crash verification**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain_timeout_releases_collection_and_barriers --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-runtime core_publication --lib -- --nocapture
RUSTC_WRAPPER= cargo check -p carrick-runtime
```

Expected: all commands exit zero.

- [ ] **Step 6: Commit crash integration**

```bash
git add crates/carrick-runtime/src/vcpu_loop/mod.rs
git commit -m "feat(runtime): freeze vcpu leases through crash snapshot"
```

---

### Task 6: Probe ABI, Diagnostic Mapper, and Authority Documentation

**Files:**
- Modify: `crates/carrick-hal/src/threaded.rs:50-430`
- Modify: `crates/carrick-hal/src/pump_fork_coord.rs:70-120`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:200-275, 1479-1760`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs:1-30`
- Modify: `crates/carrick-observability/src/probes.rs:5135-5165, 6800-6810, 7660-7675`
- Modify: `scripts/dtrace/hvpatch-stop-the-world.d:1-130`
- Modify: `scripts/dtrace/hvpatch-fork-wait-amplification.d:1-35`
- Modify: `crates/carrick-runtime/src/kernel/guest_execution.rs:1-35`
- Modify: `crates/carrick-runtime/src/lib.rs:1470-1505`

**Interfaces:**
- Consumes: Task 1 `VcpuLeaseDrainPoll` and `poll_lease_drain`.
- Produces: `waiting_vcpu_tid(VcpuLeaseDrainPoll) -> i32` and
  `pt_pause_begin(tid, others_in_guest, waiting_vcpu_tid, executors)`, followed
  by deletion of the temporary `VcpuRegistry::register/count` compatibility
  methods.

- [ ] **Step 1: Add red mapper and source-contract tests**

```rust
#[test]
fn waiting_vcpu_tid_maps_only_complete_to_zero() {
    assert_eq!(waiting_vcpu_tid(VcpuLeaseDrainPoll::Complete), 0);
    assert_eq!(
        waiting_vcpu_tid(VcpuLeaseDrainPoll::Waiting(ThreadId::synthetic_for_tests(27))),
        27,
    );
}

#[test]
fn pt_pause_probe_uses_identity_mapper_not_scalar_count() {
    let source = include_str!("quiesce.rs");
    let pause = source.split("fn acquire_pt_pause").nth(1).unwrap();
    assert!(pause.contains("waiting_vcpu_tid(kicker.poll_lease_drain(tid))"));
    assert!(!pause.contains("kicker.count()"));
}
```

- [ ] **Step 2: Run tests to prove RED**

```bash
RUSTC_WRAPPER= cargo test -p carrick-runtime waiting_vcpu_tid --lib -- --nocapture
```

Expected: compilation failure because the mapper does not exist.

- [ ] **Step 3: Delegate the probe/docs rewrite from the exact red-test checkpoint to Antigravity**

Commit the red tests before creating the worker worktree so its copy of
`quiesce.rs` contains the same test contract:

```bash
git add crates/carrick-runtime/src/vcpu_loop/quiesce.rs
git commit -m "test(runtime): pin identity-aware pt pause diagnostics"
git rev-parse HEAD
```

The printed object is the exact Task 5 plus red-test checkpoint. Create a fresh
manual worktree and branch from that object, and verify both worktrees report
the same base before dispatch. The worker may modify only the six probe/docs files
listed above (excluding `carrick-hal/src/threaded.rs` and
`carrick-hal/src/pump_fork_coord.rs` and
`crates/carrick-runtime/src/threaded_loop.rs`, which Codex owns in Step 5).
This explicit checkpoint is required because Task 4 and Task 6 Step 1 already
changed `quiesce.rs`. Require:

```text
Implement the pure mapper and replace the third pt-pause-begin argument with
waiting_vcpu_tid. Rename all Rust parameters/docs and the DTrace ABI header.
Replace the old arg2<=1 metric with exactly arg2==0 && arg3>1 and label it
pt-raised-with-peer-executor-and-no-sibling-lease. State explicitly that it is
narrower, not equivalent to the retired count predicate. Correct
GuestExecutorCensus docs to say suspend drops participation. Do not change the
any_other_in_guest drain. Run the focused runtime test, observability tests,
and dtrace syntax/source checks available in the repo.
```

- [ ] **Step 4: Review semantic accuracy and ABI consistency**

Verify all three implementations/declarations use the same four `i32`
arguments, the disabled stub matches, `arg2` is the waiting identity, and no
comment says blocked loops remain in `GuestExecutorCensus`. Send every mismatch
back to the same worker.

- [ ] **Step 5: Delete compatibility APIs and run local probe/documentation verification**

After integrating the worker, migrate any remaining direct registry
`register` callers to `subscribe_register`. Prove the global caller
census is empty, then delete the temporary `VcpuRegistry::register` and
`VcpuRegistry::count` methods and their Generic/Inert implementations. Also
update `InGuestFlag`/registry rustdoc links that still name `register`, and
audit the old wrapper wording/call site in
`crates/carrick-runtime/src/threaded_loop.rs`. Do not replace either API with a
debug length used for authority.

```bash
rg -n "\.register\(|\.count\(\)|VcpuRegistry::register|VcpuRegistry::count" crates/carrick-hal crates/carrick-runtime crates/carrick-vmm-hvf crates/carrick-vmm-kvm
RUSTC_WRAPPER= cargo test -p carrick-runtime waiting_vcpu_tid --lib -- --nocapture
RUSTC_WRAPPER= cargo test -p carrick-observability --lib
RUSTC_WRAPPER= cargo check -p carrick-observability -p carrick-runtime
rg -n "leases <= 1|arg2 <= 1|kicker\.count|VcpuRegistry::count" crates/carrick-observability/src/probes.rs scripts/dtrace/hvpatch-stop-the-world.d crates/carrick-runtime/src/kernel/guest_execution.rs crates/carrick-runtime/src/lib.rs
```

Expected: tests/checks pass; final `rg` has no stale scalar-authority match.

- [ ] **Step 6: Commit the reviewed probe/docs migration**

```bash
git add crates/carrick-hal/src/threaded.rs crates/carrick-hal/src/pump_fork_coord.rs crates/carrick-runtime/src/vcpu_loop/quiesce.rs crates/carrick-runtime/src/threaded_loop.rs crates/carrick-observability/src/probes.rs scripts/dtrace/hvpatch-stop-the-world.d scripts/dtrace/hvpatch-fork-wait-amplification.d crates/carrick-runtime/src/kernel/guest_execution.rs crates/carrick-runtime/src/lib.rs
git commit -m "chore(runtime): expose identity-aware vcpu drain diagnostics"
```

---

### Task 7: Completion Receipt and Full Verification

**Files:**
- Modify: `docs/identity-and-scope-domains.md:125-205`

**Interfaces:**
- Consumes: Tasks 1-6 complete implementation and verification receipts.
- Produces: partial item-1/item-3 closure record with explicit remaining scope.

- [ ] **Step 1: Run the forbidden-shape audit**

```bash
rg -n "fn count\(&self\) -> usize|VcpuRegistry::count|kicker\.count\(\)|\.count\(\) > 1|saturating_sub\(1\).*vCPU|pt-raised-LEASES-WOULD-HAVE-MISSED" crates scripts docs
```

Expected: no production vCPU-registry scalar decisions or retired DTrace label.
Unrelated collection `.count()` calls are inspected and excluded by source
context, not bulk-edited.

- [ ] **Step 2: Run formatting and focused gates**

```bash
RUSTC_WRAPPER= just fmt-check
RUSTC_WRAPPER= cargo test -p carrick-hal generic_registry_tests --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime lease_drain --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime process_fork --lib
RUSTC_WRAPPER= cargo test -p carrick-runtime core_publication --lib
RUSTC_WRAPPER= cargo test -p carrick-thread fork_quiesce --lib
RUSTC_WRAPPER= cargo test -p carrick-observability --lib
```

Expected: every command exits zero.

- [ ] **Step 3: Run repository-wide gates**

Run serially:

```bash
RUSTC_WRAPPER= just clippy
RUSTC_WRAPPER= just doc
RUSTC_WRAPPER= just lint-domains
RUST_TEST_THREADS=1 RUSTC_WRAPPER= just ci
```

Expected: `clippy` and `doc` exit zero. `lint-domains` and therefore `just ci`
may stop nonzero only at the known host-authority positional inventory check;
inspect its JSON and accept that receipt only when `changed=[]`. Do not re-bless
it. If either command fails earlier, later, or with a nonempty `changed` set,
the gate is red.

Because that known stop prevents `just ci` from reaching its remaining recipes,
run the post-lint portion explicitly and require every command to exit zero:

```bash
RUSTC_WRAPPER= just deny
RUSTC_WRAPPER= just check-matrix
RUSTC_WRAPPER= just check --workspace
RUSTC_WRAPPER= just doc
RUSTC_WRAPPER= just test
RUSTC_WRAPPER= just test-integration
```

- [ ] **Step 4: Request independent code review and repair findings**

Give one reviewer the HAL/registration/fork diff and a second reviewer the
crash/probe/receipt diff. Require concrete failure scenarios. Verify every
finding against the current tree, then send confirmed mechanical findings back
to the original Antigravity conversation or fix Codex-owned architecture
locally. Re-run the affected focused test after every repair.

- [ ] **Step 5: Write the partial closure receipt**

Append a dated receipt that records:

```markdown
### Identity-aware vCPU lease drain — 2026-08-28

`VcpuRegistry::count() -> usize` is deleted. Fork and crash protected work now
requires a unique identity-aware `VcpuLeaseDrainGuard`; the same registry
atomically denies non-owner registration until barrier release. Membership and
thaw wakes are one-shot, registry-owned publications, and production admission
preserves census-before-registry ordering plus the existing logical phase.

This is a partial closure of population/lifecycle item 1 (runtime-audit Part 2
item 3). Per-purpose participant sets minted from `Task` and explicit kernel
thread run-state typing remain open and are not claimed complete here.
```

Include exact focused/full gate results and the semantic `changed=[]` receipt if
the known inventory drift appears.

- [ ] **Step 6: Commit the receipt**

```bash
git add docs/identity-and-scope-domains.md
git commit -m "docs(runtime): record identity-aware vcpu drain receipt"
```

- [ ] **Step 7: Verify final branch state**

```bash
git status --short
git diff --check main...HEAD
git log --oneline --decorate -12
```

Expected: clean status, no whitespace errors, and a narrow commit series for
Tasks 1-7. Do not merge or push unless separately requested.
