# HVF Fork Floor E2.2 Host Fork RSS Decomposition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Determine whether the remaining HVF fork floor is driven by host address-space/RSS cost inside `libc::fork` or by Carrick runtime pre-engine bookkeeping.

**Architecture:** Keep the change diagnostics-only. Split the broad runtime role 0 phase 5 bucket into narrower `fork__lifecycle` subphases, add a five-argument `fork__footprint` USDT probe for host address-space samples, and add optional memory-footprint knobs to the existing fork perf probes so the same binaries can measure small and large guest footprints.

**Tech Stack:** Rust 2024, `carrick-observability` USDT probes, `carrick-host` Darwin process/VM introspection, shared AArch64 fork engine, HVF fork DTrace script, `conformance-probes`, signed macOS/HVF release binary via `just build`.

## Global Constraints

- Preserve Carrick's one-Linux-process-to-one-host-process invariant.
- Do not introduce a hot-path daemon, supervisor RPC on fork/block/wake, or guest-kernel fallback.
- Use `just build` before HVF guest/probe runs.
- Never run Carrick and the Docker oracle concurrently.
- Keep unrelated dirty files out of commits.
- Current code and fresh measurements win over prior narrative.
- Do not optimize VM/vCPU create, teardown, or stage-2 replay unless fresh E2.2 evidence overturns E2.1.
- Keep new USDT payloads at five arguments or fewer; macOS DTrace reports sixth arguments as zero on these provider paths.

---

## File Structure

- `crates/carrick-observability/src/probes.rs`: add `fork__footprint` provider/wrapper/stub.
- `crates/carrick-host/src/host_proc.rs`: expose `self_vm_region_count()` for Darwin Mach VM region counting, with inert stubs elsewhere.
- `crates/carrick-aarch64/src/engine.rs`: cache runtime-published arena high-water and emit footprint samples immediately before host `libc::fork`.
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`: split runtime role 0 phase 5 into subphases 50-55 and keep phase 5 as the total broad bucket.
- `scripts/dtrace/fork-phases.d`: print and aggregate `fork-footprint` samples.
- `conformance-probes/src/bin/perf_fork.rs`: accept optional `FORK_MEM_MB` and report `mem_mb`.
- `conformance-probes/src/bin/perf_fork_exec.rs`: accept optional `FORK_MEM_MB` and report `mem_mb`.
- `conformance-probes/src/bin/clonebasic.rs`: accept optional `FORK_MEM_MB` for one-fork DTrace large-footprint captures without changing default output.
- `docs/2026-07-08-hvf-fork-e22-evidence.md`: final verdict artifact.

---

### Task 1: Add Footprint Probe and Host Region Count

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-host/src/host_proc.rs`

**Interfaces:**
- Produces: `carrick_observability::probes::fork_footprint(phase: i32, vm_region_count: u64, arena_high_water: u64, resident_bytes: u64, virtual_bytes: u64)`.
- Produces: `carrick_host::host_proc::self_vm_region_count() -> Option<u64>`.

- [x] **Step 1: Add `fork__footprint`**

Add a five-argument provider next to `fork__lifecycle`, plus real/stub wrappers:

```rust
fn fork__footprint(_: i32, _: u64, _: u64, _: u64, _: u64) {}

pub fn fork_footprint(
    phase: i32,
    vm_region_count: u64,
    arena_high_water: u64,
    resident_bytes: u64,
    virtual_bytes: u64,
) {
    carrick_usdt::fork__footprint!(|| {
        (phase, vm_region_count, arena_high_water, resident_bytes, virtual_bytes)
    });
}
```

- [x] **Step 2: Add Darwin VM region counting**

On macOS, walk `mach_vm_region` from address 0 to the end of the task map and count each returned region. Deallocate non-null returned object-name ports with `mach_port_deallocate`. Return `None` only if the first query fails before counting any region or the walk stops on overflow/zero-size pathology. Non-macOS implementations return `None`.

---

### Task 2: Instrument Runtime Pre-Engine Subphases

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`

**Interfaces:**
- Consumes: existing `crate::probes::fork_lifecycle`.
- Produces runtime role 0 subphases:
  - phase 50: arena high-water publication
  - phase 51: pidfd/vfork pipe setup input bucket
  - phase 52: host-fork prepare hook
  - phase 53: paused-lock acquisition
  - phase 54: child parent/subreaper/ns-pid allocation
  - phase 55: `prepare_child_record_pre_fork`
  - phase 5: unchanged total pre-engine bucket

- [x] **Step 1: Split the current role 0 phase 5 block**

Wrap each operation in a local `Instant::now()` / `elapsed_us` span and emit the subphase after the operation. On `prepare_child_record_pre_fork` failure, emit phase 55 with negative sentinel fields before unwinding.

- [x] **Step 2: Preserve behavior**

Keep operation order, fork error handling, vfork pipe cleanup, fork barrier handling, and returned Linux `EAGAIN` behavior unchanged.

---

### Task 3: Emit Host Footprint Near Host Fork

**Files:**
- Modify: `crates/carrick-aarch64/src/engine.rs`

**Interfaces:**
- Consumes: `carrick_host::host_proc::{self_resource_usage, self_vm_region_count}`.
- Consumes: `carrick_observability::probes::fork_footprint`.
- Produces footprint phase 0 immediately before host `libc::fork`.

- [x] **Step 1: Cache arena high-water**

Add a `fork_arena_high_water: u64` field to `Aarch64EngineCore`, initialize it to `u64::MAX`, and implement `ThreadedEngine::set_vfork_arena_high_water` to store the value runtime publishes before every fork.

- [x] **Step 2: Emit pre-fork footprint**

Immediately before `libc::fork`, read VM region count, `self_resource_usage().resident_bytes`, `self_resource_usage().virtual_bytes`, and the cached arena high-water. Emit `fork_footprint(0, region_count, arena_high_water, resident_bytes, virtual_bytes)`.

---

### Task 4: Add Large-Footprint Probe Knobs

**Files:**
- Modify: `conformance-probes/src/bin/perf_fork.rs`
- Modify: `conformance-probes/src/bin/perf_fork_exec.rs`
- Modify: `conformance-probes/src/bin/clonebasic.rs`

**Interfaces:**
- Consumes: optional `FORK_MEM_MB=<usize>`.
- Produces: resident guest memory by allocating and touching one byte per page.
- Default behavior remains unchanged when `FORK_MEM_MB` is absent or zero.

- [x] **Step 1: Add memory shaping helper**

Each probe reads `FORK_MEM_MB`, allocates `mem_mb * 1024 * 1024` bytes, touches every 4096-byte page, and keeps the vector alive through the fork measurement or one-fork clone.

- [x] **Step 2: Report memory for perf probes**

Add `mem_mb=<n>` to `perf_fork` and `perf_fork_exec` output. Do not alter existing key names.

---

### Task 5: DTrace, Measurements, Evidence, Commit

**Files:**
- Modify: `scripts/dtrace/fork-phases.d`
- Create: `docs/2026-07-08-hvf-fork-e22-evidence.md`

**Interfaces:**
- Consumes: `fork-footprint`, `fork-lifecycle`, `fork-rebuild`, `fork-pre`, `fork-post`, and `guest-exit`.
- Produces: committed E2.2 verdict artifact.

- [x] **Step 1: Add DTrace footprint handling**

Print:

```text
fork-footprint phase=<phase> regions=<regions> arena_high_water=<addr> resident_bytes=<bytes> virtual_bytes=<bytes>
```

Aggregate each field by `phase`.

- [x] **Step 2: Run verification**

Run:

```bash
cargo fmt -p carrick-observability -p carrick-host -p carrick-aarch64 -p carrick-runtime
cargo check -p carrick-observability -p carrick-host -p carrick-aarch64 -p carrick-runtime -p carrick-vmm-hvf
just build
scripts/build-probes.sh
```

- [x] **Step 3: Run measurements**

Run small-footprint:

```bash
perf_fork
perf_fork_exec
sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'
```

Run large-footprint with `FORK_MEM_MB=256`:

```bash
perf_fork
perf_fork_exec
sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'env FORK_MEM_MB=256 target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'
```

Use the same base64 `/tmp/p` injection path for `perf_fork` and `perf_fork_exec` as E2/E2.1.

- [x] **Step 4: Record verdict**

Write `docs/2026-07-08-hvf-fork-e22-evidence.md` with:

- runtime role 0 phase 5 subphase timing table
- host footprint table for small and large samples
- `perf_fork` and `perf_fork_exec` p50/p95 for both footprint points
- focused one-fork DTrace timing for both footprint points
- final recommendation: host-fork/RSS reduction, runtime pre-engine optimization, or precise blocker handoff

- [x] **Step 5: Commit scoped files**

Run:

```bash
git diff --check
git diff --cached --check
git status --short
```

Commit only E2.2 files and leave unrelated dirty files unstaged.
