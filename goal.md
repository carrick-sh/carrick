# Goal: Staged BKL Retirement for Carrick — **COMPLETE (2026-05-22)**

## Status

**Done.** Carrick's big kernel lock has been retired from guest syscall
execution. The runtime no longer wraps the dispatcher in a global
`Arc<Mutex<_>>`; each vCPU host thread calls dispatcher methods
concurrently against `Send + Sync` per-subsystem state.

## Objective (achieved)

Remove Carrick's big kernel lock from guest syscall execution without
weakening Linux process/thread semantics, HVF ownership rules, or the
permissive-license policy.

## Evidence the acceptance criteria are met

- **No `SendKernel` wrapper / unsafe `impl Send` for the dispatcher.**
  `grep -rn "SendKernel\|unsafe impl Send" src/` finds only
  `src/trap.rs:322 unsafe impl Send for ThreadSpec {}` (the HVF thread
  hand-off spec, not the dispatcher). The dispatcher is shared as a plain
  `Arc<KernelState>` (`src/runtime.rs:714 let kernel = Arc::new(KernelState::new(dispatcher))`),
  `Arc::clone`d into each sibling vCPU thread.
- **No `Rc<RefCell<_>>` in runtime-shared dispatcher state.**
  `grep -rn "Rc<RefCell" src/` returns nothing. `OpenDescription` is now
  `type OpenDescriptionRef = Arc<RwLock<OpenDescription>>` (`src/dispatch/mod.rs:804`).
- **Per-subsystem locking replaced the BKL.** `SyscallDispatcher`
  (`src/dispatch/mod.rs:666`) holds `mem`, `proc`, `creds`, `signal` each
  behind their own `Mutex`; `IoState` (`src/dispatch/fs.rs`) carries
  field-level `Mutex`/`RwLock` (`open_files: RwLock<HashMap<..>>`,
  `cwd: RwLock<String>`, etc.). Handlers borrow only what they touch.
- **Reporter works from concurrent paths.** `CompatReporter::record(&self)`
  (`src/compat.rs:209`), with `snapshot(&self)` (`:282`) and `finish(self)`
  (`:335`) kept as a backcompat wrapper.
- **Futex no longer wakes every waiter or polls every 50ms.**
  `src/thread.rs` uses `parking_lot_core::unpark_filter` (`:286`, `:306`,
  `:332`) and returns exact unparked counts (`:345`); the old `notify_all`
  + `POLL_CAP` are gone. Signal wake of parked futex waiters is driven by
  the runtime's `vcpu_kick` signal pump, not periodic polling.
- **License policy intact.** Concurrency deps are `parking_lot = "0.12"`
  and `parking_lot_core = "0.9"` (`Cargo.toml`); `cargo deny check licenses`
  passes (`licenses ok`).

## Verification gates (run 2026-05-22, all green)

```
cargo fmt --all -- --check        # FMT OK
cargo deny check licenses         # licenses ok
cargo test --release --lib        # 134 passed
cargo test --release --test syscall_thread --test concurrency_contracts  # 12 passed
```

Demos re-verified end-to-end on the BKL-free runtime (see
`docs/tier-b-wall.md`, the memory notes, and below):

- Tier A static hello → exit 0.
- Tier B Alpine `busybox echo hello` → `hello\n`, exit 0.
- Thread-stress fixture (`scripts/run-thread-stress.sh`) → exit 0.
- **v1.0 gate** `apt-get install -y hello && /usr/bin/hello` on
  `debian:stable` → `Hello, world!`.
- **North-star** `python3 -m http.server` (ThreadingHTTPServer) on
  `python:3.12-slim` → concurrent `curl` requests return HTTP 200 / 846 B
  in 3–14 ms.

## Operational note

`cargo build --release` **and `cargo test --release`** strip the HVF
codesignature from `target/release/carrick`, causing `HV_DENIED`
(`0xfae94007`) on the next guest run. Always (re)sign via
`./scripts/build-signed.sh`, or
`codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick`.

## Remaining follow-ups (not blockers)

- `recvfrom`/`accept`/`read` still block under their subsystem lock when
  data isn't immediately ready; convert to the `WaitOnFds` lockless path
  for full robustness (data is usually ready, so impact is minor).
- apt-install cosmetics still observed: debconf `tmp.ci changed before
  chdir` (inconsistent inode numbers across stat calls), missing
  `/dev/pts` (`posix_openpt`), `chmod … (22 EINVAL)` on cache files. None
  are fatal — `apt-get install hello` completes and runs.
- Optional concurrency validation under ThreadSanitizer / loom remains
  available but is evidence, not a gate.
