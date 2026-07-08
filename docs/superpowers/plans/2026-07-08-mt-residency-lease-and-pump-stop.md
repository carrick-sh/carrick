# Multi-Threaded VM Residency Lease + Fork Pump-Stop Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two performance/capacity gaps E4 left open — multi-threaded blocked processes holding HVF VM slots (capacity ceiling at 127), and the ~1.27 ms constant every fork pays in `prepare_host_fork()` — with red-first gates for both.

**Architecture:** Two independent workstreams. (A) The pump fix replaces a 1 ms sleep-poll in `SignalPump::stop_inner` with an event wait the pump signals on exit. (B) The MT residency lease generalizes the runtime's existing park branch: today a *single-threaded* process's blocking wait routes to `save_shared_wait_state()` (HVF destroys the whole VM, rebuilds on wake); the new condition is "this thread is the **last unparked** live thread," with a wake-side protocol where whichever thread wakes first rebuilds the VM. **No engine-trait or HVF-mechanism changes** — `shared_wait_park`/`shared_wait_resume` already do the work per-thread (each `HvfVmState` has its own `mappings` copy and its own `reclaim_snapshot`); the entire feature is runtime+registry-side condition and coordination logic.

**Tech Stack:** Rust; carrick-thread (registry accounting), carrick-runtime (vcpu_loop park/wake), carrick-vmm-hvf (pump fix + stale-comment fixes only), conformance probes (musl aarch64), DTrace USDT gates.

## Global Constraints

- NEVER `git commit --no-verify`; `cargo fmt` before every commit (hooks enforce).
- Never run a carrick guest and a Docker oracle concurrently; measurement runs one at a time, no retry loops (report a failed run, don't loop it).
- Conformance probes: deterministic booleans only via `report!`; default knob values must keep the probe gate green (gate runs every built probe with no env set); byte-identical stdout at any knob value.
- Reclaim engagement conditions are LOAD-BEARING and must not change: parks happen only for indefinite waits (`timeout=None`) or timed waits > `SHORT_TIMED_WAIT_RECLAIM_CUTOFF` (250 ms, `crates/carrick-runtime/src/vcpu_loop/mod.rs:58`). Hot short waits (futex ping-pong ~33 µs) must not regress.
- Lock-ordering rule for the new code: **fork_quiesce `topology_lock` → registry inner lock is permitted; taking `topology_lock` while HOLDING the registry lock is forbidden.** The park path takes only the registry lock; the wake path claims the rebuild under `topology_lock` (Task 5 Step 3). No cycle: fork-quiesce takes topology then kicks, and kicked threads park without holding the registry lock.
- The MT lease has an env kill switch: `CARRICK_MT_VM_LEASE=0` disables the last-unparked branch (falls back to current vCPU-only behavior). Default: enabled.
- One-Linux-process-one-host-process invariant untouched; no daemon, no hot-path RPC.
- E4 regression guards that must stay green at the end: `procladder`@160 MATCH, `perf_fork`/`perf_fork_exec` small+large within noise of E4 finals (`docs/2026-07-08-hvf-residency-e4-evidence.md`), `MATCH clonebasic`, futex short-wait perf unchanged.

## Background for the implementer (read once)

- E4 evidence: `docs/2026-07-08-hvf-residency-e4-evidence.md`. Ceiling = 127 VM slots (per-VM, quiet host). Single-threaded blocked processes already release the whole VM: `park_vcpu_for_blocking_wait` (`crates/carrick-runtime/src/vcpu_loop/mod.rs:613`) branches on `registry.live_count() == 1` → `engine.save_shared_wait_state()` → HVF `shared_wait_park` (`crates/carrick-vmm-hvf/src/trap.rs:3729`, destroys vCPU **and** VM) — wake rebuilds via `rebind_shared_wait_state` → `shared_wait_resume` (`trap.rs:3757`: `create_vm_with_admission(SharedWaitResume)` + replay `self.mappings` + fresh vCPU + register restore). Multi-threaded processes take `save_guest_state()` → `reclaim_park` (vCPU-only; VM stays alive) — that VM is the capacity leak this plan closes.
- The same park/branch pattern is INLINED a second time in `wait_on_shared_word_retval` (`crates/carrick-runtime/src/vcpu_loop/threads.rs:239-256`) — Task 5 deduplicates it.
- Each sibling thread's `HvfVmState` (`trap.rs:1998`) carries its own `mappings: Vec<HvfMappedRegion>` and its own `reclaim_snapshot`, so ANY parked thread can perform the VM rebuild from its own state. **Open verification item (Task 5, Step 1):** confirm sibling `mappings` copies stay coherent when one thread mmaps while another is parked — the fork path has sibling-union replay logic (`fork__rebuild` phase 2 "sibling-map"); if copies diverge, the rebuild must use the same union mechanism, and the probe in Task 2 has a memory-integrity check designed to catch exactly this.
- `ThreadRegistry` is `crates/carrick-thread/src/thread.rs` — a `Mutex<HashMap<ThreadId, Entry>>` shared per process; `live_count()` at line 257. Both park sites already hold `self.registry`.
- The pump: `SignalPump::stop_inner` (`crates/carrick-vmm-hvf/src/vcpu_kick.rs:128-160`) wakes the pump then polls `self.exited` with `thread::sleep(1ms)`; the pump thread sets `exited` via `ExitGuard` (`vcpu_kick.rs:201`) when its loop ends. E2.2 measured this as the constant 1267-1277 µs "role 0 phase 52" (`kernel.fork.prepare_host_fork()`) in `scripts/dtrace/fork-phases.d` output — ~40% of small-footprint fork p50.
- DTrace harness (committed, working): `sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'`.

---

### Task 1: Event-driven pump stop (the 1 ms sleep-tick fix)

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/vcpu_kick.rs` (struct `SignalPump` ~line 110, `stop_inner` ~line 128, `ExitGuard` + `spawn_signal_pump` ~lines 185-201 and 422-423)

**Interfaces:**
- Produces: no API change; `SignalPump::stop()` semantics identical (bounded, detaches on wedge), just event-driven. Task 7 cites the before/after phase-52 numbers.

- [ ] **Step 1: Record the RED baseline (fork lifecycle phase 52)**

```bash
mkdir -p target/conformance/logs/mt-lease
just build && scripts/build-probes.sh
timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d \
  -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic' \
  | tee target/conformance/logs/mt-lease/fork-phases-pump-before-$(date +%Y%m%d-%H%M%S).log
```

Expected: the role 0 phase 52 line reports ~1200-1300 µs. Record the exact value — this is the red measurement.

- [ ] **Step 2: Replace the poll with an event wait**

In `vcpu_kick.rs`, extend the exit signal from a bare `AtomicBool` to a signaled pair. Replace the `exited` field type in `SignalPump` and thread the same `Arc` into the pump's `ExitGuard`:

```rust
/// Exit signal the pump thread raises when its loop ends: `flag` for lock-free
/// checks, `mu`/`cv` so `stop_inner` can WAIT for the exit event instead of
/// sleep-polling (the old 1 ms poll put a full sleep quantum — ~1.3 ms — into
/// EVERY fork's `prepare_host_fork()`, measured as fork-lifecycle phase 52).
struct ExitSignal {
    flag: std::sync::atomic::AtomicBool,
    mu: std::sync::Mutex<()>,
    cv: std::sync::Condvar,
}

impl ExitSignal {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            flag: std::sync::atomic::AtomicBool::new(false),
            mu: std::sync::Mutex::new(()),
            cv: std::sync::Condvar::new(),
        })
    }
    fn raise(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let _g = self.mu.lock().unwrap_or_else(|e| e.into_inner());
        self.cv.notify_all();
    }
    fn raised(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }
}
```

Change `SignalPump.exited: Arc<AtomicBool>` → `exited: Arc<ExitSignal>`, change `ExitGuard` to hold `Arc<ExitSignal>` and call `raise()` in its `Drop`, and update `spawn_signal_pump`'s construction (`let exited = ExitSignal::new();` etc. at ~lines 186-188 and 422-423).

Rewrite the wait loop in `stop_inner` (keep the wake-both-mechanisms retry and the 2 s detach backstop — they exist for the CPython forkserver-from-forkserver lost-wake race documented in the comment above the loop; preserve that comment):

```rust
let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
loop {
    crate::host_signal::wake_signal_pump_all();
    if self.exited.raised() {
        let _ = handle.join();
        return;
    }
    if std::time::Instant::now() >= deadline {
        drop(handle); // detach (does NOT join) — never hang the fork
        return;
    }
    // Event wait: the pump's ExitGuard raises the signal the moment its loop
    // ends, so the common case returns in microseconds. The 10 ms timeout is
    // only the re-wake cadence for the lost-wake race (pump still setting up
    // its kqueue when the first wake fired).
    let g = self.exited.mu.lock().unwrap_or_else(|e| e.into_inner());
    let _ = self
        .exited
        .cv
        .wait_timeout(g, std::time::Duration::from_millis(10));
}
```

- [ ] **Step 3: Run the pump unit tests**

```bash
cargo test -p carrick-vmm-hvf --lib vcpu_kick -- --test-threads=1
```

Expected: existing pump tests pass (the test module at the bottom of `vcpu_kick.rs` exercises spawn/stop; if a test asserted on the old field type, update it to `raised()`).

- [ ] **Step 4: Measure GREEN + regression probes**

```bash
just build
timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d \
  -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic' \
  | tee target/conformance/logs/mt-lease/fork-phases-pump-after-$(date +%Y%m%d-%H%M%S).log
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 240 \
  target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  | tee target/conformance/logs/mt-lease/perf_fork-pump-after-$(date +%Y%m%d-%H%M%S).log
scripts/run-probe.sh getrandomvdsofork
scripts/run-probe.sh vforkvmshare
```

Expected: phase 52 < 300 µs (was ~1270); `perf_fork` p50 ≈ 2.0-2.5 ms (was ~3.4 ms in E4 finals); both probes MATCH. The CPython forkserver robustness case (the reason the retry loop exists) is covered in Task 6's battery.

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt -p carrick-vmm-hvf
git add crates/carrick-vmm-hvf/src/vcpu_kick.rs
git commit -m "perf(hvf): event-driven signal-pump stop removes the 1ms fork sleep-tick"
```

---

### Task 2: `procladder_mt` — red-first probe for the MT residency gap

**Files:**
- Create: `conformance-probes/src/bin/procladder_mt.rs`

**Interfaces:**
- Produces: the red-first gate Task 6 turns green. Default N=8 keeps the gate green today; `PROC_LADDER_N=160` is the over-ceiling configuration, currently expected to FAIL (bounded fork error or stall — record which).

- [ ] **Step 1: Write the probe**

Same skeleton as `procladder.rs` (its header documents the measured single-threaded release), but each child spawns a second thread before blocking, and each child verifies memory integrity across the block/wake cycle — designed to catch a VM rebuild that replays stale/incomplete mappings:

```rust
//! Multi-threaded variant of `procladder`: N simultaneously-alive children,
//! each TWO-threaded (a std::thread sibling parked in pause(2) plus the main
//! thread), all blocked. Under carrick/HVF a multi-threaded process's blocking
//! park historically destroyed only the vCPU (`reclaim_park`), keeping one HVF
//! VM alive per blocked process — so >127 such children exhaust the per-VM
//! slot budget (E4). This probe is the red-first gate for the last-unparked
//! whole-VM residency lease: green requires blocked MT processes to release
//! their VM like single-threaded ones already do.
//!
//! Each child also writes a pattern into a private mmap BEFORE blocking and
//! verifies it after waking, so a VM rebuild that loses or mis-replays
//! mappings turns a boolean false instead of a silent pass.
//!
//! Invariants encoded:
//!   * ladder_forked_all — all N forks succeeded
//!   * ladder_children_ok — every child exited 0 (pattern intact, sibling joined)
//!
//! N defaults to 8 (under the ceiling; probe gate stays green);
//! PROC_LADDER_N=160 is the over-ceiling gate configuration.
//!
//! Deterministic output only — booleans, never counts/times/pids.

use conformance_probes::report;
use std::env;

fn ladder_n() -> usize {
    env::var("PROC_LADDER_N")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(8)
        .clamp(1, 1024)
}

const PAGE: usize = 4096;
const PAT_PAGES: usize = 16;

fn child_body() -> ! {
    unsafe {
        let pat = libc::mmap(
            std::ptr::null_mut(),
            PAT_PAGES * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if pat == libc::MAP_FAILED {
            libc::_exit(3);
        }
        for i in 0..PAT_PAGES {
            *pat.cast::<u8>().add(i * PAGE) = (i as u8) ^ 0x5a;
        }
        // Sibling thread: parks in pause() until the process is SIGKILLed.
        std::thread::spawn(|| loop {
            libc::pause();
        });
        // Main thread: block in an indefinite sigtimedwait-shaped wait via
        // pause(); the parent SIGKILLs us. If a SIGCONT-style wake ever
        // returns from pause, re-verify the pattern and block again.
        loop {
            libc::pause();
            for i in 0..PAT_PAGES {
                if *pat.cast::<u8>().add(i * PAGE) != (i as u8) ^ 0x5a {
                    libc::_exit(4);
                }
            }
        }
    }
}

fn main() {
    let n = ladder_n();
    let mut pids: Vec<i32> = Vec::with_capacity(n);
    unsafe {
        for _ in 0..n {
            let pid = libc::fork();
            if pid == 0 {
                child_body();
            }
            if pid < 0 {
                break;
            }
            pids.push(pid);
        }
        let forked = pids.len();
        // Let every child reach its blocked state before the kill sweep, so
        // the probe actually exercises N simultaneously-BLOCKED MT processes.
        libc::sleep(1);
        for &pid in &pids {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut reaped_killed = 0usize;
        for &pid in &pids {
            let mut status = 0i32;
            if libc::waitpid(pid, &mut status, 0) == pid
                && libc::WIFSIGNALED(status)
                && libc::WTERMSIG(status) == libc::SIGKILL
            {
                reaped_killed += 1;
            }
        }
        report!(
            ladder_forked_all = forked == n,
            ladder_children_ok = reaped_killed == forked,
        );
    }
}
```

Note the child exit-status check differs from `procladder`: children die by SIGKILL while healthy, so "ok" = reaped with `WTERMSIG == SIGKILL` (a child that `_exit(3)`/`_exit(4)`'d on mmap/pattern failure reaps as WIFEXITED and fails the boolean).

- [ ] **Step 2: Build; verify green at default N**

```bash
scripts/build-probes.sh
scripts/run-probe.sh procladder_mt
```

Expected: `MATCH procladder_mt` with both booleans true (N=8 is under every budget today).

- [ ] **Step 3: Record the RED run at N=160 (one shot, no retry)**

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
PROBE=conformance-probes/target/aarch64-unknown-linux-musl/release/procladder_mt
RUN_ID="cr-mtlease-$$"
base64 -i "$PROBE" | CARRICK_RUN_ID=$RUN_ID CARRICK_HVF_ADMISSION_TRACE=1 \
  timeout 180 target/release/carrick run ubuntu:24.04 --raw --fs host \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p' 2>&1 \
  | tee "target/conformance/logs/mt-lease/procladder_mt-160-red-$STAMP.log"
echo "rc=$?" | tee -a "target/conformance/logs/mt-lease/procladder_mt-160-red-$STAMP.log"
sudo -n scripts/sudo/kill.sh "$RUN_ID" 2>/dev/null || pkill -9 -f "carrick:$RUN_ID:"
pgrep -f "carrick:$RUN_ID:" || echo "cleanup-clean"
```

Expected red, in one of two shapes — record which: (a) `ladder_forked_all=false` after ~10 s+ (the 128th VM create hits hard `HV_NO_RESOURCES`, bounded park+retry, error propagates to guest fork), or (b) timeout rc=124 (stall in the soft-budget permit wait if blocked MT threads still held permits). If it unexpectedly PASSES, stop and report — that invalidates the premise and the controller must re-verify the E4 residual-exposure analysis before any implementation.

- [ ] **Step 4: fmt + commit**

```bash
rustfmt conformance-probes/src/bin/procladder_mt.rs
git add conformance-probes/src/bin/procladder_mt.rs
git commit -m "probe(conformance): procladder_mt red-first gate for MT VM residency"
```

---

### Task 3: MAP_SHARED-file descriptor sweep (E4's named follow-up)

**Files:**
- Modify: `conformance-probes/src/bin/clonebasic.rs` (add third knob alongside `FORK_MEM_MB`/`FORK_MAPS`)

**Interfaces:**
- Produces: measured descriptor growth per guest MAP_SHARED file mapping — the number that de-provisionalizes the lease reacquire budget (E4 §3 caveat). Task 7 records it.

- [ ] **Step 1: Add the `FORK_SHARED_MAPS` knob**

Below `fragmented_mappings` in `clonebasic.rs`:

```rust
fn shared_maps_arg_or_env() -> usize {
    std::env::args()
        .nth(3)
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or_else(|| env_usize("FORK_SHARED_MAPS"))
}

/// `count` disjoint MAP_SHARED mappings of ONE temp file (distinct 64 KiB
/// offsets), each touched. Unlike the anonymous-private arena (one host
/// backing), guest MAP_SHARED file mappings materialize host-side alias
/// mappings — E4 §3 flagged their per-mapping stage-2 descriptor growth as
/// the unmeasured half of the lease reacquire budget.
fn shared_file_mappings(count: usize) -> usize {
    if count == 0 {
        return 0;
    }
    const CHUNK: usize = 64 * 1024;
    let path = std::ffi::CString::new("/tmp/clonebasic-shared-maps").unwrap();
    let mut made = 0usize;
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT, 0o600);
        if fd < 0 {
            return 0;
        }
        if libc::ftruncate(fd, (count * CHUNK) as i64) != 0 {
            libc::close(fd);
            return 0;
        }
        for i in 0..count {
            let p = libc::mmap(
                std::ptr::null_mut(),
                CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                (i * CHUNK) as i64,
            );
            if p == libc::MAP_FAILED {
                break;
            }
            *p.cast::<u8>() = 1;
            made += 1;
        }
        libc::close(fd);
    }
    made
}
```

In `main()`, after the `fragmented_mappings` call: `let shared_made = shared_file_mappings(shared_maps_arg_or_env());` and add `hint::black_box(shared_made);` next to the existing black_boxes. No output changes.

- [ ] **Step 2: Gate green, then DTrace sweep**

```bash
scripts/build-probes.sh
scripts/run-probe.sh clonebasic
STAMP=$(date +%Y%m%d-%H%M%S)
for sm in 0 64 256; do
  timeout 240 sudo -n /usr/sbin/dtrace -q -s scripts/dtrace/fork-phases.d \
    -c "target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic -- 0 0 $sm" \
    | tee "target/conformance/logs/mt-lease/fork-phases-shared${sm}-$STAMP.log"
done
```

Expected: `MATCH clonebasic`; the sweep records per-side `desc_count` and replay elapsed at 0/64/256 shared file maps. Record the slope (expected: desc_count grows with shared maps — that is the point; if it stays flat, that too is a verdict: record it).

- [ ] **Step 3: fmt + commit**

```bash
rustfmt conformance-probes/src/bin/clonebasic.rs
git add conformance-probes/src/bin/clonebasic.rs
git commit -m "probe(conformance): clonebasic FORK_SHARED_MAPS knob measures MAP_SHARED descriptor growth"
```

---

### Task 4: Registry accounting — parked-vCPU tracking with last-unparked query

**Files:**
- Modify: `crates/carrick-thread/src/thread.rs` (entry struct ~line 210-220, new methods near `live_count` at line 257)
- Test: same file, `#[cfg(test)]` module (follow the file's existing test placement)

**Interfaces:**
- Produces (Task 5 consumes verbatim):
  - `ThreadRegistry::park_vcpu(&self, tid: ThreadId) -> bool` — marks `tid` parked; returns **true iff every OTHER live thread is already parked** (i.e. the caller is the last unparked thread).
  - `ThreadRegistry::unpark_vcpu(&self, tid: ThreadId) -> bool` — clears the mark; returns **true iff the process-wide VM-released flag was set**, atomically claiming the rebuild (first claimant flips it back; subsequent callers get false).
  - `ThreadRegistry::set_vm_released(&self, released: bool)` — records that the parking thread destroyed the VM.
  - `ThreadRegistry::vm_released(&self) -> bool` — read-only peek (diagnostics/tests).
  - All under the registry's existing inner mutex — one lock, no new lock type.

- [ ] **Step 1: Write the failing tests**

In the `#[cfg(test)]` module of `thread.rs`:

```rust
#[test]
fn park_vcpu_reports_last_unparked() {
    let reg = ThreadRegistry::new();
    let t1 = reg.register_main_thread();
    let t2 = reg.register_thread_like_main(t1); // use the file's existing clone/register helper
    assert!(!reg.park_vcpu(t1), "t2 still unparked");
    assert!(reg.park_vcpu(t2), "t2 is the last unparked thread");
    assert!(!reg.park_vcpu(t2), "re-parking an already-parked tid is not 'last' again");
}

#[test]
fn unpark_claims_vm_rebuild_exactly_once() {
    let reg = ThreadRegistry::new();
    let t1 = reg.register_main_thread();
    let t2 = reg.register_thread_like_main(t1);
    assert!(!reg.park_vcpu(t1));
    assert!(reg.park_vcpu(t2));
    reg.set_vm_released(true);
    assert!(reg.unpark_vcpu(t2), "first waker claims the rebuild");
    assert!(!reg.unpark_vcpu(t1), "second waker must not rebuild again");
    assert!(!reg.vm_released());
}

#[test]
fn exit_of_parked_thread_updates_last_unparked() {
    let reg = ThreadRegistry::new();
    let t1 = reg.register_main_thread();
    let t2 = reg.register_thread_like_main(t1);
    assert!(!reg.park_vcpu(t2));
    let _ = reg.exit(t2); // parked thread dies; t1 is now the only live thread
    assert!(reg.park_vcpu(t1), "t1 is last unparked after t2 exited");
}
```

Adapt the two registration helper names to whatever `thread.rs` actually exposes for creating entries in tests (read the existing tests in the file first; if none register two threads, use the same constructor path `run_vcpu` uses — the test must create two real entries).

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test -p carrick-thread --lib park_vcpu -- --test-threads=1
```

Expected: compile FAIL — `park_vcpu` not found.

- [ ] **Step 3: Implement**

Add `vcpu_parked: bool` (default `false`) to the per-thread entry struct, and to the registry a `vm_released: bool` field guarded by the same inner mutex (wrap the existing `HashMap` in a small struct if the mutex currently guards the map directly — keep one mutex):

```rust
pub fn park_vcpu(&self, tid: ThreadId) -> bool {
    let mut inner = self.inner.lock();
    let already_parked = inner
        .map
        .get(&tid)
        .map(|e| e.vcpu_parked)
        .unwrap_or(true);
    if let Some(e) = inner.map.get_mut(&tid) {
        e.vcpu_parked = true;
    }
    !already_parked
        && inner
            .map
            .iter()
            .filter(|(t, _)| **t != tid)
            .all(|(_, e)| e.vcpu_parked)
}

pub fn unpark_vcpu(&self, tid: ThreadId) -> bool {
    let mut inner = self.inner.lock();
    if let Some(e) = inner.map.get_mut(&tid) {
        e.vcpu_parked = false;
    }
    let claimed = inner.vm_released;
    inner.vm_released = false;
    claimed
}

pub fn set_vm_released(&self, released: bool) {
    self.inner.lock().vm_released = released;
}

pub fn vm_released(&self) -> bool {
    self.inner.lock().vm_released
}
```

(Adapt field access to the actual inner shape; the semantics in the Interfaces block are the contract.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test -p carrick-thread --lib -- --test-threads=1
```

Expected: new tests pass, all existing registry tests pass.

- [ ] **Step 5: fmt + commit**

```bash
cargo fmt -p carrick-thread
git add crates/carrick-thread/src/thread.rs
git commit -m "feat(thread): registry tracks parked vCPUs and last-unparked/VM-release claims"
```

---

### Task 5: Runtime last-unparked VM release + first-waker rebuild

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs` (`park_vcpu_for_blocking_wait` :613, `resume_vcpu_after_blocking_wait` :650, `BlockingWaitReclaim` :550)
- Modify: `crates/carrick-runtime/src/vcpu_loop/threads.rs` (`wait_on_shared_word_retval` :225-256 — deduplicate its inlined park/resume copy onto the mod.rs methods)

**Interfaces:**
- Consumes: Task 4's four registry methods, exactly as specified there.
- Produces: `BlockingWaitReclaim` gains no public surface; behavior contract for Task 6: an MT process whose threads are ALL parked in reclaim-eligible waits holds zero HVF VMs; first thread to wake rebuilds.

- [ ] **Step 1: Verify sibling-mappings coherence (investigation gate — do this FIRST)**

Read how `HvfVmState.mappings` is maintained for sibling threads when one thread mmaps: start from `hv_vm_map` call sites in `crates/carrick-vmm-hvf/src/trap.rs` (pushes at :2995, :4233, :4319, :4524) and determine whether a mapping created by thread A lands in thread B's `mappings` vec (shared `Arc`? broadcast? or per-thread divergence with fork-time sibling-union repair). Write the answer into your report. If copies diverge: the wake-side rebuild must replay the UNION — reuse the fork path's sibling-union source (the `fork__rebuild` phase-2 machinery) or route the rebuild through the same descriptor source fork uses. If they are shared/coherent: proceed as below. **Do not skip this step; the Task 2 probe's pattern check is the empirical backstop but not a substitute.**

- [ ] **Step 2: Add the kill switch and generalized park condition**

In `mod.rs`, next to `should_reclaim_vcpu_for_timed_wait` (:60):

```rust
/// MT whole-VM residency lease (E4 Track 3): when the LAST unparked thread of
/// a multi-threaded process parks for a reclaim-eligible wait, release the
/// whole VM like single-threaded parks already do (`save_shared_wait_state`),
/// so >127 blocked MT processes don't exhaust the per-VM slot budget.
/// `CARRICK_MT_VM_LEASE=0` reverts to vCPU-only parks for bisection.
fn mt_vm_lease_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("CARRICK_MT_VM_LEASE")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}
```

Rewrite `park_vcpu_for_blocking_wait` (keep everything not shown):

```rust
fn park_vcpu_for_blocking_wait(&self, engine: &mut E) -> Option<BlockingWaitReclaim> {
    if !engine.reclaims() {
        return None;
    }
    let single_threaded_process = self.registry.live_count() == 1;
    let last_unparked = self.registry.park_vcpu(self.this_tid);
    let release_vm =
        single_threaded_process || (mt_vm_lease_enabled() && last_unparked);
    let state = if release_vm {
        let st = engine.save_shared_wait_state();
        self.registry.set_vm_released(true);
        st
    } else {
        engine.save_guest_state()
    };
    let old_slot = carrick_hal::vcpu_sched::current_slot();
    if let Some(lease) = carrick_hal::vcpu_sched::take_current_lease() {
        carrick_hal::vcpu_sched::global()
            .release(lease, carrick_hal::vcpu_sched::Yield::Blocked);
    }
    if engine.reclaim_refreshes_kicker() {
        self.kicker.unregister(self.this_tid);
    }
    Some(BlockingWaitReclaim {
        state,
        old_slot,
        single_threaded_process,
    })
}
```

Ordering note for the single-threaded case: `park_vcpu`/`set_vm_released` bookkeeping is harmless there (one thread, no contention) and keeps one code path.

- [ ] **Step 3: Wake side — claim-based rebuild**

In `resume_vcpu_after_blocking_wait`, replace both `if reclaim.single_threaded_process { rebind_shared_wait_state } else { rebind_to_slot }` branch pairs (:680-688 and :702-710) with a claim made ONCE at the top of the function, before the lease-acquire loop:

```rust
let rebuild_vm = self.registry.unpark_vcpu(self.this_tid) || reclaim.single_threaded_process;
```

then in both branch sites:

```rust
if rebuild_vm {
    engine
        .rebind_shared_wait_state(new_lease.slot, &reclaim.state)
        .map_err(RuntimeError::Trap)?;
} else {
    engine
        .rebind_to_slot(new_lease.slot, &reclaim.state)
        .map_err(RuntimeError::Trap)?;
}
```

**Wake-ordering hazard this resolves — verify you preserve it:** when the VM was released by thread A but thread B wakes first, B's `unpark_vcpu` claim returns true and B performs the VM rebuild from its OWN `reclaim_snapshot` + `mappings` (HVF `shared_wait_resume` works from any parked thread's state); A later wakes, claims false, and takes the vCPU-only `rebind_to_slot` into the rebuilt VM. Two simultaneous wakers: the registry mutex makes exactly one claim true. A waker taking `rebind_to_slot` while the rebuild is still in flight is prevented by the existing `topology_lock` serialization inside the rebind paths (`resume` already takes it in the kicker-refresh branch at :677; confirm the non-refresh branch's rebinds are also safe or hoist the topology lock to cover both — HVF always takes the refresh branch since `reclaim_refreshes_kicker()==true`, so for HVF the lock already covers it; state in your report what the KVM/non-refresh branch does).

**vCPU-only wake against a still-dead VM:** claim-true is granted to the FIRST waker, so any waker that gets claim-false must be guaranteed the VM is alive. It is: claim-false means either the VM was never released, or a previous waker's claim-true already ran its rebuild under the topology lock before releasing it — but ONLY if the claim and the rebuild are not separated by a window where a second waker can pass the claim and reach `rebind_to_slot` first. Both wakers serialize on the topology lock, but lock ORDER alone doesn't guarantee the claimer goes first. Close the window: make claim-false wakers wait until `!self.registry.vm_released()`... which is already false the moment the claimer took it (the claim flips the flag under the registry mutex). The remaining window is claim taken but rebuild not yet done. Since both rebind paths take the same `topology_lock`, add the claim INSIDE the topology-locked region for the kicker-refresh branch (move `let rebuild_vm = ...` to just after `let _topo = ...lock()` at :677-679, and compute it before the rebinds in the else-branch under its own topology lock if that branch lacks one). With the claim under the same lock as the rebuild, a claim-false result proves the claimer's rebuild already completed. Respect the global lock-ordering rule (registry → topology): taking the registry lock while HOLDING topology is the reverse order — so instead take topology FIRST then registry here is FORBIDDEN by the rule... resolve by making the rule directional the other way for this pair and audit the park path: park takes registry (park_vcpu, set_vm_released) WITHOUT topology held — no cycle. Fork-quiesce takes topology then kicks; kicked threads park at the barrier without holding the registry lock — no cycle. Document the final ordering (topology → registry permitted; registry → topology forbidden) in a comment at `mt_vm_lease_enabled` and ensure `park_vcpu_for_blocking_wait` never runs under topology_lock (it doesn't today — verify with a caller scan and say so in your report).

- [ ] **Step 4: Deduplicate the threads.rs inline copy**

`wait_on_shared_word_retval` (`threads.rs:239-256`) inlines the same park logic (branching on `live_count() == 1`) and its resume twin later in the same function stores `Some((st, old_slot))`. Replace the inline park block with a call to `self.park_vcpu_for_blocking_wait(engine)` and the resume with `self.resume_vcpu_after_blocking_wait(engine, reclaim)?`, converting the local tuple to the `BlockingWaitReclaim` the mod.rs methods use (both files are `impl` blocks of the same loop struct — verify and, if the tuple carries anything `BlockingWaitReclaim` lacks, extend `BlockingWaitReclaim` rather than keeping two shapes). This makes the shared-futex wait path (the E4-era `shared_wait_park` trigger) and every other blocking wait go through ONE park/resume pair.

- [ ] **Step 4b: Close the signal-wait park gap (discovered by Task 2's sigwait red)**

`DispatchOutcome::WaitOnSignals` (`mod.rs:1032-1088`) never calls any `park_vcpu_*` — a thread blocked in `sigwait`/`rt_sigtimedwait` keeps its vCPU, its global permit, AND (via never becoming "parked") blocks the whole-VM release for its process, forever. Task 2 measured the consequence: 160 sigwait-blocked children silently stall the fork storm in the unbounded permit wait (0 bytes of output, no admission-trace lines — the permit backoff loop has none). Mirror the `WaitOnSleep` arm's shape (`mod.rs:1122-1134`):

```rust
DispatchOutcome::WaitOnSignals {
    wait_set,
    block_mask,
    timeout,
} => {
    let slice = match signal_wait_slice(&mut signal_wait_deadline, timeout) {
        Some(slice) => slice,
        None => {
            break Ok(DispatchOutcome::Errno {
                errno: crate::linux_abi::LINUX_EAGAIN,
            });
        }
    };
    self.waiter.ensure_full();
    crate::run_state::publish(crate::run_state::RunState::Blocked);
    // Park for reclaim-eligible waits, judged by the GUEST's overall
    // timeout (None = indefinite sigwait), not the 50 ms service slice —
    // otherwise signal-wait threads hold vCPU+permit+VM forever (the
    // sigwait-shaped procladder_mt red). While parked, stretch the slice:
    // real wakes arrive via the waiter kick in microseconds; the slice is
    // only the lost-kick safety net, and 20 park/resume cycles per second
    // per blocked thread would be pointless VM churn.
    let guest_remaining = signal_wait_remaining(signal_wait_deadline, timeout);
    let reclaim = self.park_vcpu_for_timed_wait(engine, guest_remaining);
    let slice = if reclaim.is_some() {
        slice.max(Duration::from_secs(1))
    } else {
        slice
    };
    let wait_result = self.waiter.wait(&[], Some(slice), block_mask);
    if let Some(outcome) = self.exec_replaced_thread_exit() {
        return Ok(outcome);
    }
    self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
    match wait_result {
        // ... existing match arms unchanged ...
```

where `signal_wait_remaining` is a small helper next to `signal_wait_slice` returning the guest's remaining total timeout (`None` for an indefinite wait; `Some(deadline - now)` otherwise — reuse `signal_wait_deadline`'s existing bookkeeping; read `signal_wait_slice` first and match its conventions). Keep the existing `TimedOut`/`Interrupted`/`Ready` arms exactly (the deadline-expiry check still uses the ORIGINAL slice bookkeeping — verify `signal_wait_expired` semantics survive the stretched slice: a stretched slice may overshoot a finite guest deadline by up to 1 s, so only stretch when `guest_remaining` is `None` OR > 1 s, and cap the stretched slice at `guest_remaining`).

- [ ] **Step 4c: Fork-path resource exhaustion degrades to guest EAGAIN, loudly**

Two robustness fixes the Task 2 reds exposed (precedent: fork-time process-record exhaustion → guest `EAGAIN`, commit 9bed118d):

1. `acquire_global_vcpu_permit` (`crates/carrick-vmm-hvf/src/trap.rs:867`): the backoff loop is silent and unbounded. Add gated admission-trace lines (same `admission_trace_enabled()` style as the `HV_NO_RESOURCES` path) on first park and every ~100 parks, and a bound: after 60 s of waiting, return an error that the fork/vCPU-create caller propagates as a typed resource-exhaustion error rather than looping forever.
2. The fork-rebuild `HV_NO_RESOURCES` fatal (Task 2's pause-shaped red killed 19 engines with "trap engine failed"): trace how `create_with_no_resources_backpressure`'s post-10s error propagates through the fork-rebuild path, and convert BOTH exhaustion errors above into guest `fork(2) = EAGAIN` instead of a fatal engine abort. Follow the 9bed118d plumbing (`git show 9bed118d` shows the process-record precedent end-to-end). A red-first probe is NOT required here (the Task 2 red logs are the red); the green evidence is procladder_mt at an over-ceiling N with the kill switch ON (lease disabled): expected `ladder_forked_all=false` + clean completion instead of engine fatals/stalls.

- [ ] **Step 5: Build + unit tests + focused probes**

```bash
just build
cargo test -p carrick-runtime --lib -- --test-threads=1
scripts/run-probe.sh procladder
scripts/run-probe.sh procladder_mt
scripts/run-probe.sh clonebasic
scripts/run-probe.sh getrandomvdsofork
scripts/run-probe.sh vforkvmshare
```

Expected: all MATCH (these run at default N=8 — the over-ceiling gate is Task 6). Any hang here is a wake-ordering bug — take a core per the debugging docs (`lldb -p PID -o 'process save-core ...'`), do not add prints.

- [ ] **Step 6: fmt + commit**

```bash
cargo fmt -p carrick-runtime
git add crates/carrick-runtime/src/vcpu_loop/mod.rs crates/carrick-runtime/src/vcpu_loop/threads.rs
git commit -m "feat(runtime): last-unparked MT park releases the whole VM; first waker rebuilds"
```

---

### Task 6: Green the gate + regression battery

**Files:**
- Create (logs, uncommitted): `target/conformance/logs/mt-lease/*.log`

**Interfaces:**
- Consumes: Tasks 1-5 all landed.
- Produces: the measured green run + regression evidence Task 7 records.

- [ ] **Step 1: The gate — procladder_mt at N=160 (one shot)**

Re-run Task 2 Step 3's exact command block (fresh STAMP, log name `procladder_mt-160-green-$STAMP.log`).
Expected: completes in seconds, `ladder_forked_all=true`, `ladder_children_ok=true`, rc=0, cleanup clean. Then the Docker side, sequentially:

```bash
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/procladder_mt | \
  docker run --rm -i --platform linux/arm64 ubuntu:24.04 \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && PROC_LADDER_N=160 /tmp/p'
```

Expected: identical booleans. Also re-run `procladder` (single-threaded twin) at 160 the same way — it must stay green.

- [ ] **Step 2: Kill-switch sanity**

Re-run the gate once with `CARRICK_MT_VM_LEASE=0` in the carrick env. Expected: NOT green-by-lease — with Task 5 Step 4c landed, the run should complete with `ladder_forked_all=false` and NO engine fatals and NO silent stall (graceful EAGAIN degradation at the ceiling). This one run proves both the kill switch and the exhaustion-degradation fix. (Task 2 recorded the two pre-fix red shapes: pause-shaped fatal `procladder_mt-160-red-rework-*.log`, sigwait-shaped silent stall `procladder_mt-160-red-sigwait-*.log` — neither shape may reappear.)

- [ ] **Step 3: Perf regression gates**

```bash
# fork perf (pump fix + lease code on the fork path)
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork | timeout 240 \
  target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  | tee target/conformance/logs/mt-lease/perf_fork-final-$(date +%Y%m%d-%H%M%S).log
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork_exec | timeout 300 \
  target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  | tee target/conformance/logs/mt-lease/perf_fork_exec-final-$(date +%Y%m%d-%H%M%S).log
# short-wait hot path must be untouched (parks only engage >250ms/indefinite)
just bench   # quick profile; compare futex_pingpong / wait_pipe_pingpong / epoll_pipe_loop p50s vs docs/perf-results/2026-07-06-syscall.jsonl
```

Expected: `perf_fork` p50 ≤ ~2.5 ms (pump fix win vs E4's 3.69 ms final; must not regress above it), `perf_fork_exec` at-or-below E4 final; futex/pipe/epoll p50s within noise of the 2026-07-06 lane (33.6/36.6/33.2 µs).

- [ ] **Step 4: MT-workload conformance battery**

```bash
just build -p carrick-cli -p carrick-conformance
target/release/carrick-conformance --workers 1 --no-image-refresh \
  --suite ltp-ptrace06 --suite ltp-clone08 --suite ltp-kill10 \
  --suite ltp-waitpid06 --suite ltp-waitpid08 --suite ltp-waitpid10 \
  --jsonl target/conformance/mt-lease-battery-$(date +%Y%m%d-%H%M%S).jsonl
cargo test -p carrick-cli --test conformance -- --nocapture 2>&1 | tail -20
```

Expected: 6/6 MATCH on the suite set (same set the E1/arena phase used), probe gate fully green.

Then the MANDATORY MT/fork witnesses — find their suite ids in `scripts/conformance/suites.toml` by grepping `forkserver` and `osexec`, and run them with the same `carrick-conformance --workers 1 --no-image-refresh --suite <id> --jsonl ...` shape: the CPython forkserver suite is the pump fix's regression witness (the pump-stop retry loop exists specifically for the forkserver-from-forkserver lost-wake race) — treat a hang there as a Task 1 failure, not noise; the Go os/exec suite is the MT fork/park stress witness for Task 5. Record both results in the log dir.

- [ ] **Step 5: Commit nothing (measurement task) — logs stay under target/**

---

### Task 7: Evidence doc, stale-comment fixes, memo + memory updates

**Files:**
- Create: `docs/2026-07-09-mt-residency-lease-evidence.md`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` (comments only: :761-775 and :3665/:3702)
- Modify: `docs/superpowers/specs/2026-07-08-carrick-architecture-strategy-memo.md` (short addendum update)
- Modify (user memory): `/Users/tjfontaine/.claude/projects/-Volumes-CaseSensitive-carrick/memory/project_hvf_residency_e4.md` (+ MEMORY.md hook if the title changes)

**Interfaces:**
- Consumes: every log from Tasks 1-6.

- [ ] **Step 1: Fix the two stale trap.rs comment blocks (E4's named follow-up — comments only, zero behavior)**

At `trap.rs:761-775` (`GLOBAL_VCPU_CEILING` doc): rewrite to the E4 facts — the measured limit is a per-VM slot budget (127 in five exact quiet-host runs, E4; not a "system-wide vCPU budget": 508 concurrent vCPUs ran fine at 127 VMs), the earlier "~126" reading's cause is undetermined, 120 remains the soft pre-throttle, and cite `docs/2026-07-08-hvf-residency-e4-evidence.md`. Keep the paragraph about park+retry discovery of the true limit.

At `trap.rs:3665` and `:3702`: delete the "NOT YET WIRED" paragraphs (both methods ARE wired via `hvf_aarch64_engine.rs:536`/`:558` — `save_guest_state`/`rebind_to_slot`) and remove the now-false `#[allow(dead_code)]` attributes at :3672/:3705 if the compiler agrees they're used (build will tell you).

```bash
cargo check -p carrick-vmm-hvf && cargo fmt -p carrick-vmm-hvf
```

- [ ] **Step 2: Write the evidence doc**

`docs/2026-07-09-mt-residency-lease-evidence.md`, E-series template (Verdict → Instrumentation/Changes → Measurements → Verification Commands → Next Track), recording: pump phase-52 before/after and perf_fork delta; procladder_mt red shape (Task 2) → green (Task 6) with kill-switch cross-check; the sibling-mappings coherence answer from Task 5 Step 1; the MAP_SHARED descriptor slope from Task 3 and what it means for the reacquire budget (de-provisionalize or bound it); the regression battery results. Next Track: whatever the MAP_SHARED slope implies (descriptor coalescing? nothing?), plus any residual shapes (processes blocked in short-timed-wait storms keep vCPUs by design — state it).

- [ ] **Step 3: Update memo addendum + memory**

Append 4-6 lines to the strategy memo's E4 addendum: Track 3's narrowed scope is now IMPLEMENTED (last-unparked whole-VM lease); acceptance tests green (procladder_mt@160, procladder@160); reacquire budget de-provisionalized per the MAP_SHARED sweep result. Update `project_hvf_residency_e4.md`'s residual-exposure line to point at the new evidence doc (or add a linked `[[hvf-residency-e4]]` sibling memory if cleaner), and refresh its MEMORY.md hook line if the description changed.

- [ ] **Step 4: Commit**

```bash
git add docs/2026-07-09-mt-residency-lease-evidence.md \
  docs/superpowers/specs/2026-07-08-carrick-architecture-strategy-memo.md \
  crates/carrick-vmm-hvf/src/trap.rs
git commit -m "docs(arch): MT residency-lease evidence; retire refuted trap.rs comments"
```

---

## Explicitly out of scope

- Pressure-driven eviction of SHORT-wait vCPU holders (threads in <250 ms timed waits keep vCPUs by design; revisit only if a real workload shows vCPU-permit pressure).
- KVM/bhyve/NVMM analogues of the whole-VM lease (their `save_shared_wait_state` impls decide their own semantics; the runtime condition change applies generically but greening THEIR gates is per-backend follow-up).
- The I/O-burst (5-10x) and park/wake (~2x) overhead campaigns — separate E-series, unchanged priority.
