# Proposed Replacement `goal.md`

```markdown
# Goal: Staged BKL Retirement for Carrick

## Objective

Remove Carrick's big kernel lock from guest syscall execution without weakening Linux process/thread semantics, HVF ownership rules, or the permissive-license policy.

The current runtime already lets guest user-mode run on multiple host threads, but syscall handling still serializes through `SendKernel(Arc<Mutex<KernelState>>)` in `src/runtime.rs`. The goal is to replace that global safety net with explicit `Send + Sync` subsystem state, precise blocking primitives, and measurable no-regression gates.

## Current Evidence

- `src/runtime.rs` has a BKL around `SyscallDispatcher` and `CompatReporter`.
- `src/thread.rs` has `FutexTable { Mutex<HashMap<u64, u64>>, Condvar }` plus a 50ms `POLL_CAP`.
- `src/dispatch/mod.rs` still uses `Rc<RefCell<OpenDescription>>`, making the dispatcher unsafe to share without the BKL.
- `src/compat.rs` requires `&mut self` reporting, keeping observability coupled to serialized dispatch.
- Local baseline:
  - Passing: `cargo deny check licenses`
  - Passing: `cargo clippy --all-targets` with warnings only
  - Passing: `cargo test --lib thread::tests`
  - Passing: `cargo test --test syscall_thread`
  - Current full-suite gaps: `cargo test --test conformance` fails on `rename`, `mkdir_rmdir`, and `ppid`; concurrency work must not add new gaps.

## Research Constraints

- Linux futex wait is an atomic compare-and-block operation: the guest word check and sleeping must be ordered against wake operations on the same futex word. Source: [man7 futex(2)](https://www.man7.org/linux/man-pages/man2/futex.2.html).
- `parking_lot_core::park` / `unpark_filter` are viable futex substrates, but they are `unsafe`: keys must be addresses Carrick controls, and callbacks must not panic or call back into `parking_lot`. Sources: [park](https://docs.rs/parking_lot_core/latest/parking_lot_core/fn.park.html), [unpark_filter](https://docs.rs/parking_lot_core/latest/parking_lot_core/fn.unpark_filter.html).
- `DashMap` is useful as a concurrent map replacement, but its own docs warn that operations may deadlock when holding references into the map. It is not a blanket FD-table replacement. Source: [DashMap docs](https://docs.rs/dashmap/latest/dashmap/struct.DashMap.html).
- Apple HVF vCPU operations belong to the owning thread; do not move vCPUs onto dispatch queues or run them from arbitrary threads. Source: [Apple Hypervisor vCPU management](https://developer.apple.com/documentation/hypervisor/vcpu-management).
- ThreadSanitizer can help detect races on `aarch64-apple-darwin`, but requires nightly `-Z` flags and explicit target setup. It is evidence, not proof. Source: [Rust sanitizer docs](https://doc.rust-lang.org/stable/unstable-book/compiler-flags/sanitizer.html).
- Miri is useful for pure Rust logic but cannot validate arbitrary native/HVF/FFI behavior or the correctness of `parking_lot_core` internals. Source: [Miri README](https://github.com/rust-lang/miri/).

## Implementation Direction

### 1. Dependency Policy

Add only permissively licensed concurrency dependencies:

- `parking_lot = "0.12"`
- `parking_lot_core = "0.9"`
- `dashmap = "6.2"` only where guard lifetime hazards are small, such as reporter rare-event maps
- optional dev-only `loom = "0.7"` for pure concurrency model tests

Every dependency change must pass `cargo deny check licenses`.

### 2. Futex and Signal Wakeups

Replace the coarse futex table with a Carrick-owned keyed wait table:

- Use stable host-owned bucket keys, not raw guest addresses as parking-lot keys.
- Preserve the Linux wait contract: dispatcher checks `*uaddr == expected`, then runtime parks without holding dispatcher/subsystem locks.
- Replace `notify_all` and `POLL_CAP` with targeted wakeups via `parking_lot_core::unpark_filter`.
- Add a safe runtime-side interrupt path so pending guest signals wake futex waiters without relying on periodic polling.
- Return exact wake counts where the table can know them; otherwise document the remaining approximation and keep tests around it.

### 3. Reporter Independence

Make compatibility reporting usable from concurrent syscall paths:

- Change `CompatReporter::record` to take `&self`.
- Use `AtomicU64` for hot counters.
- Use guarded maps or `DashMap` for rare events.
- Add `snapshot()` for `RunResult`; keep `finish(self)` as a test/backcompat wrapper.

### 4. Dispatcher Send-Safety

Remove `Rc<RefCell<_>>` before removing `SendKernel`:

- Convert `OpenFile.description` to `Arc<parking_lot::RwLock<OpenDescription>>`.
- Convert pipe/shared descriptor state to `Arc<parking_lot::Mutex<_>>`.
- Keep the FD table as `parking_lot::RwLock<HashMap<i32, OpenFile>>` in the first pass so FD-wide operations remain auditable.
- Do not switch the FD table to `DashMap` until `dup2`, `close`, `close_cloexec_fds`, fork snapshots, and descriptor iteration have focused tests.

### 5. BKL Removal

After dispatcher and reporter are `Send + Sync`:

- Delete `SendKernel` and the unsafe `impl Send`.
- Store shared runtime state in explicit `Arc` fields.
- Let each vCPU thread call dispatcher methods concurrently.
- Never hold any subsystem lock while running HVF, waiting on host I/O, parking in futex, or spawning a guest thread.
- Preserve Apple's owning-thread vCPU rule.

### 6. Locking Rules

Use this lock order for multi-state syscalls:

`fd_table -> open_description -> fs -> mem -> proc -> creds -> signal`

Rules:

- Locks are held for the smallest practical scope.
- Reporter, thread registry, and futex operations are outside the subsystem lock hierarchy.
- Any new syscall handler that needs multiple locks must state its lock order in code comments.

## Verification Plan

Required gates for each stage:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets
cargo deny check licenses
cargo test --lib thread::tests
cargo test --test syscall_thread
cargo test
```

Until current conformance gaps are fixed, `cargo test --test conformance` may fail only on the known `rename`, `mkdir_rmdir`, and `ppid` cases.

Additional concurrency validation:

```sh
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test --target aarch64-apple-darwin -Zbuild-std
cargo +nightly miri test --lib thread::tests
```

Use Miri only for pure Rust logic. Use TSan output as supporting evidence, not as a correctness guarantee.

Performance validation:

- Add a local stress fixture with multiple guest threads repeatedly doing independent `read`, `stat`, `futex wait/wake`, and reporter-heavy syscalls.
- Measure before/after syscall throughput and idle CPU behavior.
- Acceptance is removal of the BKL and polling regression, not an unproven claim of linear scaling.

## Acceptance Criteria

- No `SendKernel` wrapper or unsafe `impl Send` remains for dispatcher sharing.
- No `Rc<RefCell<_>>` remains in runtime-shared dispatcher state.
- Futex waits no longer wake every waiter or poll every 50ms for signal delivery.
- Reporter works from concurrent syscall paths without the BKL.
- Required gates pass, with no new conformance failures beyond the current documented baseline.
- The implementation remains within the permissive license policy enforced by `deny.toml`.
```
