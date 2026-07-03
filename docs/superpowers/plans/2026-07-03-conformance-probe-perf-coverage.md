# Conformance-probe perf coverage (host-op amplification) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every conformance probe a deterministic, always-on performance signal — how many logical host operations carrick issues per guest Linux syscall — with a committed baseline and a CI drift gate.

**Architecture:** A process-wide atomic counter in `carrick-observability`, tagged by the currently-dispatching guest syscall (`CanonicalNr`) via a thread-local set at the single `SyscallDispatcher::dispatch()` chokepoint. Carrick's host operations bump it through a thin `hostcall` seam (fs first). At guest exit, an env-gated JSON report is emitted; the conformance harness captures it per probe into `perf-baseline.jsonl`, and `just check-perf` gates regressions — mirroring the `baseline.jsonl` + `just check-matrix` machinery already in the tree.

**Tech Stack:** Rust (edition 2024, toolchain 1.96.0), `serde`/`serde_json`, `parking_lot`, `just`, the existing `carrick-conformance` harness and `carrick-observability` reporter.

## Global Constraints

- Workspace lints **deny** `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` in non-test code. Use `?`/`match`, never `.unwrap()`/`.expect()` outside `#[cfg(test)]`.
- Every commit must pass the pre-commit hook (`just fmt-check`). Never `git commit --no-verify`.
- The counter's hot path (`record`) must be a single relaxed atomic add — always compiled in; only the JSON *emission* is env-gated (`CARRICK_PERF_REPORT`). No heap allocation on the record path.
- Counts are **logical** carrick host-ops (one bump per carrick host operation), NOT raw libc syscalls and NOT cap-std internals. No `strace`, no Docker, no Linux differential anywhere.
- Wallclock is recorded and rendered but is NEVER a gate trigger.
- New ABI/number tables derive from the existing typed domains — reuse `CanonicalNr` and the `carrick_abi::syscall` name table; do not hand-number.
- Run `just ci` before any push.

---

### Task 1: Perf counter core in `carrick-observability`

Process-wide per-`CanonicalNr` host-op table + thread-local dispatch context + record/enter/snapshot. No I/O, no guest — pure unit-testable logic. Mirrors the lock-free `AtomicU64` design in `crates/carrick-observability/src/compat.rs` (see its THEORY OF OPERATION header).

**Files:**
- Create: `crates/carrick-observability/src/perf.rs`
- Modify: `crates/carrick-observability/src/lib.rs` (add `pub mod perf;`)
- Test: inline `#[cfg(test)] mod tests` in `perf.rs`

**Interfaces:**
- Consumes: `carrick_abi::syscall::CanonicalNr` (the typed guest syscall number; `.0` is the `u64`). If `carrick-observability` does not already depend on `carrick-abi`, add `carrick-abi = { workspace = true }` to its `[dependencies]` in `crates/carrick-observability/Cargo.toml`.
- Produces:
  - `pub enum HostOpDomain { Fs, Net, Mem, Proc }` (`#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]`)
  - `pub fn enter_dispatch(nr: u64) -> DispatchGuard` — sets thread-local current nr, bumps invocation count for `nr`; the returned guard clears the thread-local on drop.
  - `pub struct DispatchGuard` (holds the previous thread-local value; restores it on `Drop`).
  - `pub fn record(domain: HostOpDomain)` — bumps `host_ops[current_nr][domain]`, or an `overhead` bucket when no dispatch is active.
  - `pub fn snapshot() -> PerfSnapshot` — a consistent read of all counters.
  - `pub fn reset()` — zero all counters (test + per-run use).
  - `pub struct PerfSnapshot { pub per_syscall: Vec<SyscallPerf>, pub overhead_ops: u64 }`
  - `pub struct SyscallPerf { pub nr: u64, pub invocations: u64, pub host_ops_by_domain: Vec<(HostOpDomain, u64)>, pub total_host_ops: u64 }`

- [ ] **Step 1: Write the failing test**

Add to `crates/carrick-observability/src/perf.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: counters are process-global; tests that touch them must not run
    // concurrently with each other. Serialize via a shared lock.
    use std::sync::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn records_host_ops_against_the_active_dispatch() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        {
            let _d = enter_dispatch(56); // openat
            record(HostOpDomain::Fs);
            record(HostOpDomain::Fs);
        }
        record(HostOpDomain::Fs); // outside dispatch -> overhead
        let snap = snapshot();
        let openat = snap.per_syscall.iter().find(|s| s.nr == 56).unwrap();
        assert_eq!(openat.invocations, 1);
        assert_eq!(openat.total_host_ops, 2);
        assert_eq!(snap.overhead_ops, 1);
    }

    #[test]
    fn nested_dispatch_restores_previous_context() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let _outer = enter_dispatch(56);
        {
            let _inner = enter_dispatch(64); // write
            record(HostOpDomain::Fs);
        }
        record(HostOpDomain::Fs); // back to openat context
        let snap = snapshot();
        assert_eq!(snap.per_syscall.iter().find(|s| s.nr == 64).unwrap().total_host_ops, 1);
        assert_eq!(snap.per_syscall.iter().find(|s| s.nr == 56).unwrap().total_host_ops, 1);
        assert_eq!(snap.overhead_ops, 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p carrick-observability --lib perf:: 2>&1 | tail -20`
Expected: FAIL — `perf` module / `record` / `enter_dispatch` not found (does not compile).

- [ ] **Step 3: Write minimal implementation**

Write `crates/carrick-observability/src/perf.rs`:

```rust
//! Per-guest-syscall host-op accounting. See
//! docs/superpowers/specs/2026-07-03-conformance-probe-perf-coverage-design.md.
//!
//! `record` is a single relaxed atomic add on the hot path (always compiled in);
//! only the JSON emission is env-gated. Counts are LOGICAL carrick host-ops, not
//! raw libc syscalls. Mirrors the lock-free design in `compat.rs`.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Highest canonical syscall number we track (aarch64 canonical table tops out
/// well under this). Out-of-range numbers fold into `overhead` — they are never
/// a normal dispatch.
const MAX_NR: usize = 512;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum HostOpDomain {
    Fs,
    Net,
    Mem,
    Proc,
}

const DOMAINS: [HostOpDomain; 4] = [
    HostOpDomain::Fs,
    HostOpDomain::Net,
    HostOpDomain::Mem,
    HostOpDomain::Proc,
];

fn domain_ix(d: HostOpDomain) -> usize {
    match d {
        HostOpDomain::Fs => 0,
        HostOpDomain::Net => 1,
        HostOpDomain::Mem => 2,
        HostOpDomain::Proc => 3,
    }
}

// host_ops[nr * 4 + domain], invocations[nr], plus an overhead bucket.
struct Counters {
    host_ops: Vec<AtomicU64>,
    invocations: Vec<AtomicU64>,
    overhead: AtomicU64,
}

fn counters() -> &'static Counters {
    use std::sync::OnceLock;
    static C: OnceLock<Counters> = OnceLock::new();
    C.get_or_init(|| Counters {
        host_ops: (0..MAX_NR * 4).map(|_| AtomicU64::new(0)).collect(),
        invocations: (0..MAX_NR).map(|_| AtomicU64::new(0)).collect(),
        overhead: AtomicU64::new(0),
    })
}

thread_local! {
    // None = no guest syscall being dispatched on this thread.
    static CURRENT_NR: Cell<Option<usize>> = const { Cell::new(None) };
}

/// RAII: on drop, restores the previous dispatch context (supports the rare
/// nested/reentrant dispatch without losing the outer attribution).
pub struct DispatchGuard {
    prev: Option<usize>,
}

impl Drop for DispatchGuard {
    fn drop(&mut self) {
        CURRENT_NR.with(|c| c.set(self.prev));
    }
}

/// Enter dispatch of guest syscall `nr`: bump its invocation count and make it
/// the attribution target for subsequent `record` calls on this thread.
pub fn enter_dispatch(nr: u64) -> DispatchGuard {
    let ix = nr as usize;
    if ix < MAX_NR {
        counters().invocations[ix].fetch_add(1, Ordering::Relaxed);
    }
    let prev = CURRENT_NR.with(|c| c.replace(if ix < MAX_NR { Some(ix) } else { None }));
    DispatchGuard { prev }
}

/// Record one logical host operation against the active dispatch (or overhead).
#[inline]
pub fn record(domain: HostOpDomain) {
    let c = counters();
    match CURRENT_NR.with(|c| c.get()) {
        Some(nr) => c.host_ops[nr * 4 + domain_ix(domain)].fetch_add(1, Ordering::Relaxed),
        None => c.overhead.fetch_add(1, Ordering::Relaxed),
    };
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyscallPerf {
    pub nr: u64,
    pub invocations: u64,
    pub host_ops_by_domain: Vec<(HostOpDomain, u64)>,
    pub total_host_ops: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfSnapshot {
    pub per_syscall: Vec<SyscallPerf>,
    pub overhead_ops: u64,
}

/// Consistent-enough read of all counters (relaxed; the run is quiescent at
/// report time — the guest has exited).
pub fn snapshot() -> PerfSnapshot {
    let c = counters();
    let mut per_syscall = Vec::new();
    for nr in 0..MAX_NR {
        let invocations = c.invocations[nr].load(Ordering::Relaxed);
        let mut by_domain = Vec::new();
        let mut total = 0u64;
        for d in DOMAINS {
            let v = c.host_ops[nr * 4 + domain_ix(d)].load(Ordering::Relaxed);
            if v > 0 {
                by_domain.push((d, v));
                total += v;
            }
        }
        if invocations > 0 || total > 0 {
            per_syscall.push(SyscallPerf {
                nr: nr as u64,
                invocations,
                host_ops_by_domain: by_domain,
                total_host_ops: total,
            });
        }
    }
    PerfSnapshot {
        per_syscall,
        overhead_ops: c.overhead.load(Ordering::Relaxed),
    }
}

/// Zero all counters (per-run reset and tests).
pub fn reset() {
    let c = counters();
    for a in &c.host_ops {
        a.store(0, Ordering::Relaxed);
    }
    for a in &c.invocations {
        a.store(0, Ordering::Relaxed);
    }
    c.overhead.store(0, Ordering::Relaxed);
}
```

Add to `crates/carrick-observability/src/lib.rs` beside the existing `pub mod compat;`:

```rust
pub mod perf;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p carrick-observability --lib perf:: 2>&1 | tail -20`
Expected: PASS (2 tests). If `carrick-abi` was newly added as a dep it is unused yet — that is fine (no import in this task).

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-observability/src/perf.rs crates/carrick-observability/src/lib.rs crates/carrick-observability/Cargo.toml
git commit -m "feat(observability): add per-syscall host-op perf counter"
```

---

### Task 2: Perf report shape + env-gated JSON emission

The rendered report and the write-at-exit. Mirrors `CompatReporter::finish()` / `render()` (`crates/carrick-observability/src/compat.rs:409,490`).

**Files:**
- Modify: `crates/carrick-observability/src/perf.rs` (add `PerfReport`, `render_report`, `emit_if_enabled`)
- Test: inline tests in `perf.rs`

**Interfaces:**
- Consumes: `snapshot()` (Task 1).
- Produces:
  - `pub struct PerfReport { pub total_host_ops: u64, pub total_guest_syscalls: u64, pub amplification: f64, pub overhead_ops: u64, pub per_syscall: Vec<SyscallPerf> }`
  - `pub fn build_report() -> PerfReport` — derives totals + `amplification = total_host_ops / max(1, total_guest_syscalls)`.
  - `pub fn emit_if_enabled()` — if `CARRICK_PERF_REPORT` env var is set, write `serde_json::to_string_pretty(&build_report())` to that path. Errors are swallowed (best-effort telemetry, never fail a run).

- [ ] **Step 1: Write the failing test**

Add to `perf.rs` tests:

```rust
#[test]
fn report_derives_amplification_from_counts() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    {
        let _d = enter_dispatch(56);
        record(HostOpDomain::Fs);
        record(HostOpDomain::Fs);
        record(HostOpDomain::Fs);
    }
    {
        let _d = enter_dispatch(56);
        record(HostOpDomain::Fs);
        record(HostOpDomain::Fs);
        record(HostOpDomain::Fs);
    }
    let r = build_report();
    assert_eq!(r.total_guest_syscalls, 2);
    assert_eq!(r.total_host_ops, 6);
    assert!((r.amplification - 3.0).abs() < 1e-9);
    // round-trips through JSON
    let json = serde_json::to_string(&r).unwrap();
    let back: PerfReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_host_ops, 6);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p carrick-observability --lib perf::tests::report_derives 2>&1 | tail -15`
Expected: FAIL — `build_report` / `PerfReport` not found.

- [ ] **Step 3: Write minimal implementation**

Append to `perf.rs` (before the `#[cfg(test)]` block):

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerfReport {
    pub total_host_ops: u64,
    pub total_guest_syscalls: u64,
    pub amplification: f64,
    pub overhead_ops: u64,
    pub per_syscall: Vec<SyscallPerf>,
}

pub fn build_report() -> PerfReport {
    let snap = snapshot();
    let total_host_ops: u64 = snap.per_syscall.iter().map(|s| s.total_host_ops).sum();
    let total_guest_syscalls: u64 = snap.per_syscall.iter().map(|s| s.invocations).sum();
    let amplification = total_host_ops as f64 / total_guest_syscalls.max(1) as f64;
    PerfReport {
        total_host_ops,
        total_guest_syscalls,
        amplification,
        overhead_ops: snap.overhead_ops,
        per_syscall: snap.per_syscall,
    }
}

/// Best-effort: write the JSON report to `$CARRICK_PERF_REPORT` if set. Never
/// fails the run (telemetry). Call once, at guest exit.
pub fn emit_if_enabled() {
    let Ok(path) = std::env::var("CARRICK_PERF_REPORT") else {
        return;
    };
    if let Ok(json) = serde_json::to_string_pretty(&build_report()) {
        let _ = std::fs::write(path, json);
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p carrick-observability --lib perf:: 2>&1 | tail -15`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-observability/src/perf.rs
git commit -m "feat(observability): derive perf report + env-gated JSON emission"
```

---

### Task 3: Attribute host-ops at the dispatch chokepoint

Set the thread-local context for the duration of every guest syscall, and emit the report at guest exit.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:2236` (`dispatch`)
- Modify: the guest-exit path that already emits the compat report (find via `grep -rn "CompatReporter\|\.finish()\|emit" crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/run_result.rs`) — add `carrick_observability::perf::emit_if_enabled();` beside it.
- Test: inline test in `dispatch/mod.rs` tests module

**Interfaces:**
- Consumes: `carrick_observability::perf::{enter_dispatch, emit_if_enabled}` (Tasks 1-2), `request.number.0` (the `CanonicalNr`'s `u64`).
- Produces: nothing new — wires attribution.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` in `crates/carrick-runtime/src/dispatch/mod.rs` (there is already a large one — append):

```rust
#[test]
fn dispatch_attributes_perf_to_the_guest_syscall() {
    use carrick_observability::perf;
    // getpid (nr 172 canonical) issues no host fs ops; dispatch must still bump
    // its invocation count so amplification denominators are correct.
    perf::reset();
    let mut d = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0, vec![0u8; 4096]);
    let reporter = CompatReporter::default();
    let _ = d.dispatch(
        SyscallRequest::new(172, SyscallArgs::from([0, 0, 0, 0, 0, 0])),
        &mut memory,
        &reporter,
    );
    let snap = perf::snapshot();
    assert_eq!(
        snap.per_syscall.iter().find(|s| s.nr == 172).map(|s| s.invocations),
        Some(1)
    );
}
```

(If `SyscallRequest::new` takes different args, match the existing test-helper calls already in this module — grep `SyscallRequest::new(` in the file for the exact shape.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p carrick-runtime --lib dispatch_attributes_perf 2>&1 | tail -15`
Expected: FAIL — `per_syscall` for nr 172 is `None` (invocation not counted; guard not wired).

- [ ] **Step 3: Write minimal implementation**

In `crates/carrick-runtime/src/dispatch/mod.rs`, change `dispatch` (2236):

```rust
    pub fn dispatch(
        &mut self,
        request: SyscallRequest,
        memory: &mut impl GuestMemory,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Perf attribution: every host op recorded while this call runs is
        // attributed to this guest syscall. Guard clears on all exit paths.
        let _perf = carrick_observability::perf::enter_dispatch(request.number.0);
        // Tree-wide forward-progress beat for the deadlock watchdog.
        crate::deadlock_watchdog::tick();
        self.dispatch_inner(request, memory, reporter, None)
    }
```

Confirm `carrick-observability` is a dependency of `carrick-runtime` (it is — `CompatReporter` is used). Then, in the guest-exit path found above (e.g. `runtime.rs` where the compat report is finalized), add one line:

```rust
        carrick_observability::perf::emit_if_enabled();
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p carrick-runtime --lib dispatch_attributes_perf 2>&1 | tail -15`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-runtime/src/runtime.rs
git commit -m "feat(runtime): attribute host-ops per guest syscall at dispatch"
```

---

### Task 4: `hostcall::fs` seam + route `fs_backend` through it

The first real coverage. A thin fs wrapper that records one logical op per carrick fs host operation, plus routing the `HostFsBackend` host calls through it. Start with the amplifier the design names: the redundant `symlink_metadata`, the per-stat xattr reads, the open attempts.

**Files:**
- Create: `crates/carrick-runtime/src/hostcall.rs` (fs domain wrappers)
- Modify: `crates/carrick-runtime/src/lib.rs` (add `mod hostcall;`)
- Modify: `crates/carrick-runtime/src/fs_backend.rs` — at each host fs operation the amplification doc lists (`symlink_metadata` at ~1377, `with_entry_fd`/`open_with` at ~1115, `open_raw_fd` at ~1751), add a `crate::hostcall::fs::record()` call. (Do NOT reimplement cap-std; just record once per carrick host op immediately before/after each cap-std call.)
- Test: `crates/carrick-runtime/tests/integration/perf_fs_amplification.rs` (new integration test)

**Interfaces:**
- Consumes: `carrick_observability::perf::{record, HostOpDomain}`.
- Produces: `pub mod hostcall { pub mod fs { pub fn record() } }` — `crate::hostcall::fs::record()` calls `perf::record(HostOpDomain::Fs)`.

- [ ] **Step 1: Write the failing test**

Create `crates/carrick-runtime/tests/integration/perf_fs_amplification.rs` (and register it in the integration test module list — grep `mod ` in `crates/carrick-runtime/tests/integration/main.rs` and add `mod perf_fs_amplification;`):

```rust
//! A guest openat on the layered fs backend must record MORE THAN ONE logical
//! fs host-op (carrick issues several cap-std ops per open), and the perf
//! counter must attribute them to the openat syscall.
use carrick_observability::perf::{self, HostOpDomain};

#[test]
fn host_backend_open_records_multiple_fs_ops_for_one_guest_open() {
    perf::reset();
    // Build a HostFsBackend over a temp dir with one file, mirror the setup used
    // by the existing syscall_fs_open integration tests (grep HostFsBackend in
    // crates/carrick-runtime/tests/integration/).
    let scratch = tempfile::tempdir().unwrap();
    std::fs::write(scratch.path().join("target"), b"payload").unwrap();
    let dir = cap_std::fs::Dir::open_ambient_dir(scratch.path(), cap_std::ambient_authority()).unwrap();
    let backend = carrick_runtime::fs_backend::HostFsBackend::from_existing_dir(dir);

    // Drive one carrick open of "/target" through the backend's public path,
    // wrapped in a dispatch context so ops attribute to nr 56 (openat).
    {
        let _d = perf::enter_dispatch(56);
        let _ = backend.open_raw_fd_with_metadata("/target", false, false, false);
    }
    let snap = perf::snapshot();
    let openat = snap.per_syscall.iter().find(|s| s.nr == 56).expect("openat recorded");
    assert!(openat.total_host_ops >= 1, "at least one fs op recorded");
    assert!(
        openat.host_ops_by_domain.iter().any(|(d, _)| *d == HostOpDomain::Fs),
        "recorded in the Fs domain"
    );
}
```

(Adjust `open_raw_fd_with_metadata`'s exact signature/visibility to what `fs_backend.rs` exposes; if it is not `pub`, drive through the nearest public entry the other integration tests use.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p carrick-runtime --test integration perf_fs_amplification 2>&1 | tail -20`
Expected: FAIL — `total_host_ops` is 0 (no `record` calls wired into `fs_backend`), or `hostcall` module missing.

- [ ] **Step 3: Write minimal implementation**

Create `crates/carrick-runtime/src/hostcall.rs`:

```rust
//! Logical host-operation accounting seam. Carrick's host operations call the
//! matching `record()` so `carrick_observability::perf` can attribute them to
//! the dispatching guest syscall. LOGICAL ops (one per carrick host op), not raw
//! libc calls or cap-std internals — see
//! docs/superpowers/specs/2026-07-03-conformance-probe-perf-coverage-design.md.

pub mod fs {
    #[inline]
    pub fn record() {
        carrick_observability::perf::record(carrick_observability::perf::HostOpDomain::Fs);
    }
}
```

Add to `crates/carrick-runtime/src/lib.rs`:

```rust
mod hostcall;
```

In `crates/carrick-runtime/src/fs_backend.rs`, at each host fs operation the amplification doc catalogs, add a record immediately before the cap-std call. Example at the `symlink_metadata` site (~1377):

```rust
        crate::hostcall::fs::record();
        let md = self.dir.symlink_metadata(rel)?;
```

Repeat at `with_entry_fd`'s `open_with` (~1115), `open_raw_fd`'s open attempts (~1751 — record once per attempt), and the xattr reads (`read_mode_xattr`/`read_socket_xattr`). One `record()` per real host operation.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p carrick-runtime --test integration perf_fs_amplification 2>&1 | tail -20`
Expected: PASS — `total_host_ops >= 1` in the Fs domain, attributed to nr 56.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-runtime/src/hostcall.rs crates/carrick-runtime/src/lib.rs crates/carrick-runtime/src/fs_backend.rs crates/carrick-runtime/tests/integration/perf_fs_amplification.rs crates/carrick-runtime/tests/integration/main.rs
git commit -m "feat(runtime): route fs_backend host ops through the perf seam"
```

---

### Task 5: Harness captures the report → `perf-baseline.jsonl`

Add a `--perf-bless` mode to `carrick-conformance` that runs every probe under carrick with `CARRICK_PERF_REPORT`, reads the emitted JSON, and writes one record per probe to `scripts/conformance/perf-baseline.jsonl`. Reuse the probe discovery the probe gate already does (`crates/carrick-cli/tests/conformance.rs` auto-discovers `conformance-probes/src/bin/*.rs`) — but the writer lives in `carrick-conformance` beside `--render-matrix`/`--check-matrix`.

**Files:**
- Modify: `crates/carrick-conformance/src/main.rs` (add `--perf-bless` arg + handler; mirror the `--render-matrix` block at ~195)
- Create: `crates/carrick-conformance/src/perf.rs` (probe run + report parse + baseline read/write/compare — pure functions, unit-tested)
- Create (generated): `scripts/conformance/perf-baseline.jsonl`
- Test: inline tests in `crates/carrick-conformance/src/perf.rs`

**Interfaces:**
- Consumes: the built `carrick` binary path (`args.carrick_bin`), the probe list.
- Produces:
  - `pub struct ProbePerf { pub probe: String, pub total_host_ops: u64, pub total_guest_syscalls: u64, pub amplification: f64, pub wallclock_ms: f64, pub per_syscall: Vec<carrick_observability::perf::SyscallPerf> }` (add `carrick-observability` + `carrick-abi` to `carrick-conformance/Cargo.toml` deps — reuse the `SyscallPerf`/`PerfReport` types rather than redefining).
  - `pub fn read_perf_baseline(path) -> Vec<ProbePerf>` / `pub fn write_perf_baseline(path, &[ProbePerf])` (JSONL, stable sort by `probe`).
  - `pub fn compare_perf(baseline: &[ProbePerf], fresh: &[ProbePerf]) -> Vec<PerfRegression>` where `PerfRegression { probe, kind, baseline, fresh }` and a regression is `fresh.total_host_ops > baseline.total_host_ops + max(2, ceil(0.10 * baseline))`.

- [ ] **Step 1: Write the failing test**

Create `crates/carrick-conformance/src/perf.rs` with the comparison logic under test first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn probe(name: &str, ops: u64, sysc: u64) -> ProbePerf {
        ProbePerf {
            probe: name.into(),
            total_host_ops: ops,
            total_guest_syscalls: sysc,
            amplification: ops as f64 / sysc.max(1) as f64,
            wallclock_ms: 0.0,
            per_syscall: vec![],
        }
    }

    #[test]
    fn flags_a_count_regression_beyond_tolerance() {
        let base = vec![probe("p", 20, 3)];
        // +2 is within tolerance (max(2, ceil(2.0)) = 2); +3 is over.
        assert!(compare_perf(&base, &[probe("p", 22, 3)]).is_empty());
        assert_eq!(compare_perf(&base, &[probe("p", 23, 3)]).len(), 1);
        // improvements never regress
        assert!(compare_perf(&base, &[probe("p", 10, 3)]).is_empty());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p carrick-conformance --lib perf::tests 2>&1 | tail -15`
Expected: FAIL — `perf` module / `compare_perf` not found.

- [ ] **Step 3: Write minimal implementation**

Write `crates/carrick-conformance/src/perf.rs` with `ProbePerf`, `PerfRegression`, `read_perf_baseline`, `write_perf_baseline`, `compare_perf`, and `run_probe_perf(bin, probe) -> ProbePerf` (spawn `Command::new(bin).arg("run").arg(<probe elf>)` with `.env("CARRICK_PERF_REPORT", tmp)` and `CARRICK_RUN_ID`, time it, read+parse the JSON). Add `pub mod perf;` to `crates/carrick-conformance/src/main.rs`. Implement `compare_perf` exactly as the test specifies:

```rust
pub fn compare_perf(baseline: &[ProbePerf], fresh: &[ProbePerf]) -> Vec<PerfRegression> {
    let mut out = Vec::new();
    for b in baseline {
        let Some(f) = fresh.iter().find(|f| f.probe == b.probe) else { continue };
        let tol = std::cmp::max(2, (b.total_host_ops as f64 * 0.10).ceil() as u64);
        if f.total_host_ops > b.total_host_ops + tol {
            out.push(PerfRegression {
                probe: b.probe.clone(),
                kind: "host_ops".into(),
                baseline: b.total_host_ops,
                fresh: f.total_host_ops,
            });
        }
    }
    out
}
```

Add the `--perf-bless` arg (mirror `render_matrix` at main.rs:107) and its handler (mirror the `if args.render_matrix { ... }` block at main.rs:195): discover probes, `run_probe_perf` each, `write_perf_baseline`. Then run it once to generate the committed baseline: `cargo run -p carrick-conformance -- --perf-bless` (requires a signed binary — run `just build` first).

- [ ] **Step 4: Run test to verify it passes; generate the baseline**

Run: `cargo test -p carrick-conformance --lib perf::tests 2>&1 | tail -15`
Expected: PASS.
Then: `just build && cargo run -p carrick-conformance -- --perf-bless && head -1 scripts/conformance/perf-baseline.jsonl`
Expected: a JSON record with a probe name and `total_host_ops`.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-conformance/src/perf.rs crates/carrick-conformance/src/main.rs crates/carrick-conformance/Cargo.toml scripts/conformance/perf-baseline.jsonl
git commit -m "feat(conformance): capture per-probe host-op perf baseline"
```

---

### Task 6: `just check-perf` drift gate + wire into `just ci`

The deterministic gate. Mirrors `--check-matrix` / `just check-matrix` exactly (main.rs `check_matrix` handler + justfile recipe + ci wiring — all added earlier in this tree; copy that structure).

**Files:**
- Modify: `crates/carrick-conformance/src/main.rs` (add `--check-perf` arg + handler)
- Modify: `justfile` (add `check-perf` recipe; add `j check-perf` to the `ci` recipe after `j check-matrix`)
- Modify: `AGENTS.md` (commands table: add `check-perf` row; update the `just ci` sequence)
- Test: reuse Task 5's `compare_perf` unit test (already covers the logic); a red/green shell check for the gate

**Interfaces:**
- Consumes: `read_perf_baseline`, `run_probe_perf`, `compare_perf` (Task 5).
- Produces: `--check-perf` exits non-zero when `compare_perf(committed, fresh)` is non-empty; prints each regression + the `--perf-bless` hint; exit 0 when clean. Never reads/writes wallclock into the verdict.

- [ ] **Step 1: Write the failing check (red)**

Run (before implementing the handler):
`cargo run -p carrick-conformance -- --check-perf; echo "exit=$?"`
Expected: FAIL/usage error — `--check-perf` not defined yet.

- [ ] **Step 2: Implement the `--check-perf` handler**

Add the `check_perf: bool` arg (mirror `check_matrix` at main.rs). Handler: `read_perf_baseline(&args.perf_baseline)`, run each baselined probe via `run_probe_perf`, `compare_perf`; on non-empty, `eprintln!` each regression + `regenerate with: cargo run -p carrick-conformance -- --perf-bless` and `return Ok(ExitCode::FAILURE)`; else `Ok(ExitCode::SUCCESS)`. Add the justfile recipe:

```make
# Drift gate: each probe's logical host-op count must not regress past tolerance
# vs the committed scripts/conformance/perf-baseline.jsonl. Deterministic, no
# Docker; wallclock is not gated. Runs inside `just ci`.
check-perf: build
    cargo run -p carrick-conformance -- --check-perf
```

Add `j check-perf` to the `ci` recipe after `j check-matrix`, and update `AGENTS.md`'s command table + `just ci` sequence string.

- [ ] **Step 3: Verify green on HEAD, red on a seeded regression**

Run: `just check-perf 2>&1 | tail -3; echo "exit=$?"`
Expected: exit 0 (in sync — baseline just blessed in Task 5).
Then seed a regression: temporarily edit `scripts/conformance/perf-baseline.jsonl` to halve one probe's `total_host_ops`, re-run `just check-perf`.
Expected: exit non-zero, prints the regressed probe. Restore the file with `git checkout -- scripts/conformance/perf-baseline.jsonl`.

- [ ] **Step 4: Full gate**

Run: `cargo test -p carrick-conformance --lib 2>&1 | tail -3` and `just check-perf 2>&1 | tail -2`
Expected: tests PASS; gate exit 0.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-conformance/src/main.rs justfile AGENTS.md
git commit -m "feat(conformance): gate per-probe host-op drift in CI"
```

---

### Task 7: Render `docs/perf-matrix.md`

The human-readable review surface. Deterministic render from `perf-baseline.jsonl` (mirrors `matrix::render` in `crates/carrick-conformance/src/matrix.rs`).

**Files:**
- Create: `crates/carrick-conformance/src/perf_matrix.rs` (`pub fn render(&[ProbePerf]) -> String`)
- Modify: `crates/carrick-conformance/src/main.rs` (add `--render-perf-matrix`; `--perf-bless` also writes the matrix, mirroring how `--bless` writes both baseline + support-matrix)
- Create (generated): `docs/perf-matrix.md`
- Modify: `AGENTS.md` (add a `docs/perf-matrix.md` row to the "Where to look next" table)
- Test: inline `render` test in `perf_matrix.rs`

**Interfaces:**
- Consumes: `Vec<ProbePerf>` (Task 5).
- Produces: `pub fn render(probes: &[ProbePerf]) -> String` — a stable Markdown table sorted by probe: `| probe | guest syscalls | host-ops | amplification | top syscall | wallclock ms |`. Deterministic (no timestamps).

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renders_a_stable_sorted_table() {
        let probes = vec![
            crate::perf::ProbePerf { probe: "b".into(), total_host_ops: 6, total_guest_syscalls: 3, amplification: 2.0, wallclock_ms: 1.0, per_syscall: vec![] },
            crate::perf::ProbePerf { probe: "a".into(), total_host_ops: 10, total_guest_syscalls: 2, amplification: 5.0, wallclock_ms: 2.0, per_syscall: vec![] },
        ];
        let md = render(&probes);
        let a = md.find("| `a` |").unwrap();
        let b = md.find("| `b` |").unwrap();
        assert!(a < b, "sorted by probe name");
        assert!(md.contains("5.0"), "amplification rendered");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p carrick-conformance --lib perf_matrix 2>&1 | tail -10`
Expected: FAIL — module/`render` missing.

- [ ] **Step 3: Implement `render` + wire `--render-perf-matrix`**

Write `perf_matrix.rs::render` (sort a clone by `probe`, emit the header + one row each, format floats with one decimal). Add `pub mod perf_matrix;` and a `--render-perf-matrix` handler (read baseline, render, write `docs/perf-matrix.md`); have the `--perf-bless` handler also call it after writing the baseline. Regenerate: `cargo run -p carrick-conformance -- --render-perf-matrix`.

- [ ] **Step 4: Run test + regenerate**

Run: `cargo test -p carrick-conformance --lib perf_matrix 2>&1 | tail -10`
Expected: PASS.
Then: `cargo run -p carrick-conformance -- --render-perf-matrix && head -8 docs/perf-matrix.md`
Expected: a Markdown table.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-conformance/src/perf_matrix.rs crates/carrick-conformance/src/main.rs docs/perf-matrix.md AGENTS.md
git commit -m "feat(conformance): render docs/perf-matrix.md from the perf baseline"
```

---

## Final verification

- [ ] Run `just ci` (now includes `check-perf`) and confirm green.
- [ ] Confirm two back-to-back `--perf-bless` runs produce a byte-identical `perf-baseline.jsonl` (determinism), ignoring the `wallclock_ms` field.

## Notes for the implementer

- **Determinism caveat:** `wallclock_ms` is inherently non-deterministic; it is stored and rendered but MUST be excluded from `compare_perf` and from the byte-stability check. If a future refactor makes the baseline diff churn on wallclock, that is a bug — the gate compares counts only.
- **Coverage grows later:** only `fs` is routed in this plan (Task 4). `net`/`mem`/`proc` domains exist in the enum but read zero until routed in follow-up work; a probe showing `0` host-ops means "no instrumented ops," not "no work." Do not over-interpret zeros.
- **`SyscallRequest::new` / backend signatures:** the exact test-helper and backend method signatures shift over time — grep the current callers in the target file before pasting the test code, and match them.
</content>
