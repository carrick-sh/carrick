# HVF Fork Floor E2.1 Lifecycle Decomposition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify the non-stage-2 phase that dominates HVF fork cost after E2 measured eager stage-2 replay as non-material.

**Architecture:** Add a five-argument `fork__lifecycle` USDT probe alongside the existing `fork__rebuild` replay probe. Emit it from the shared runtime fork coordinator, the shared AArch64 engine that owns `libc::fork`, and the HVF backend that owns VM/vCPU teardown and rebuild. Keep the change diagnostics-only: no fork behavior, scheduling policy, VM residency model, guest ABI, or exit path changes.

**Tech Stack:** Rust 2024, `carrick-observability` USDT probes, `carrick-runtime` fork quiesce loop, `carrick-aarch64` shared fork engine, `carrick-vmm-hvf`, `scripts/dtrace/fork-phases.d`, signed macOS/HVF release binary via `just build`, `perf_fork` and `perf_fork_exec`.

## Global Constraints

- Preserve Carrick's one-Linux-process-to-one-host-process invariant.
- Do not introduce a hot-path daemon, supervisor RPC on fork/block/wake, or guest-kernel fallback.
- Use `just build` before any HVF guest/probe run that needs codesigning.
- Never run Carrick and the Docker oracle concurrently.
- Keep unrelated dirty files out of commits.
- Current code and fresh measurements win over prior narrative.
- Keep the USDT payload at five arguments or fewer; macOS DTrace reports sixth arguments as zero on these provider paths.

---

## File Structure

- `crates/carrick-observability/src/probes.rs`: add `fork__lifecycle` and its wrapper/stub.
- `crates/carrick-aarch64/Cargo.toml`: add `carrick-observability` so the shared AArch64 fork engine can emit host-`fork(2)` timing.
- `crates/carrick-aarch64/src/engine.rs`: emit snapshot, freeze, host fork, parent rebuild, child rebuild, and child engine-reset timings.
- `crates/carrick-vmm-hvf/src/trap.rs`: emit child snapshot construction, `hv_vcpu_destroy`, `hv_vm_destroy`, admission/`hv_vm_create`, `hv_vcpu_create`, restore, DTrace re-register, and RNG stamp timings.
- `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`: emit fork-token/quiesce/topology/bookkeeping/runtime parent/child repair timings.
- `scripts/dtrace/fork-phases.d`: print and aggregate `fork-lifecycle` events.
- `docs/2026-07-08-hvf-fork-e21-evidence.md`: final verdict artifact.

---

### Task 1: Add `fork__lifecycle`

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`

**Interfaces:**
- Produces: `crate::probes::fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64)`.
- Role values: `0=runtime-parent/common`, `1=runtime-child`, `2=aarch64-parent/common`, `3=aarch64-child`, `4=hvf-parent/common`, `5=hvf-child`.
- `phase` values are documented in the evidence artifact and DTrace output.
- `elapsed_us` is elapsed time for the phase just completed, or zero for instant markers.
- `a`/`b` carry phase-specific counts or return codes.

- [x] **Step 1: Add provider function**

Add next to `fork__rebuild`:

```rust
/// Fork lifecycle phase timing. `role`: 0=runtime-parent/common,
/// 1=runtime-child, 2=aarch64-parent/common, 3=aarch64-child,
/// 4=hvf-parent/common, 5=hvf-child. `phase` is domain-local and documented in
/// `docs/2026-07-08-hvf-fork-e21-evidence.md`; `elapsed_us` is the just-finished
/// phase duration. `a` and `b` are phase-specific counts or return codes.
fn fork__lifecycle(_: i32, _: i32, _: u64, _: i64, _: i64) {}
```

- [x] **Step 2: Add wrapper and stub**

```rust
pub fn fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64) {
    carrick_usdt::fork__lifecycle!(|| (role, phase, elapsed_us, a, b));
}
```

```rust
stub!(fork_lifecycle(role: i32, phase: i32, elapsed_us: u64, a: i64, b: i64));
```

---

### Task 2: Instrument Runtime and AArch64 Boundaries

**Files:**
- Modify: `crates/carrick-aarch64/Cargo.toml`
- Modify: `crates/carrick-aarch64/src/engine.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs`

**Interfaces:**
- Consumes: `carrick_observability::probes::fork_lifecycle` in `carrick-aarch64`; `crate::probes::fork_lifecycle` in `carrick-runtime`.
- Produces: phase events for `libc::fork`, engine rebuild hooks, quiesce drain, and runtime repair.

- [x] **Step 1: Add the AArch64 dependency**

Add:

```toml
carrick-observability = { path = "../carrick-observability" }
```

- [x] **Step 2: Add timing helpers**

Use this helper in each modified Rust module:

```rust
fn elapsed_us(start: std::time::Instant) -> u64 {
    let micros = start.elapsed().as_micros();
    micros.min(u128::from(u64::MAX)) as u64
}
```

If a helper already exists in a function, keep it local.

- [x] **Step 3: Emit AArch64 phases**

In `Aarch64EngineCore::fork`, emit:

- role 2 phase 0: snapshot complete
- role 2 phase 1: `freeze_ram_for_fork` complete
- role 2 phase 2: page-table manager clone complete
- role 2 phase 3: `libc::fork` complete; `a=pid` in parent, `a=0` in child
- role 2 phase 4: parent rebuild hook complete
- role 3 phase 5: child rebuild hook complete
- role 3 phase 6: child engine-local state reset complete

- [x] **Step 4: Emit runtime phases**

In `ThreadRuntimeState::handle_fork`, emit:

- role 0 phase 0: fork token acquired
- role 0 phase 1: topology lock acquired
- role 0 phase 2: quiesce siblings drained; `a=others`, `b=kicker count`
- role 0 phase 3: HVF `VCPU_LIVE` drain complete; `a=VCPU_LIVE`
- role 0 phase 4: exit cleanup drain complete; `a=in-flight count`
- role 0 phase 5: pre-engine bookkeeping complete
- role 0 phase 6: engine fork call returned
- role 0 phase 7: parent runtime repair complete
- role 1 phase 8: child runtime repair complete
- role 0 phase 9: vfork parent suspend complete, only when a vfork pipe exists

---

### Task 3: Instrument HVF Teardown and Rebuild

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`

**Interfaces:**
- Consumes: `crate::probes::fork_lifecycle`.
- Produces: HVF-specific phase timings that isolate descriptor prep, destroy, VM create, vCPU create, restore, and child-only post-rebuild work.

- [x] **Step 1: Instrument `fork_prepare_and_teardown`**

Emit role 4 phases:

- phase 0: `VM_INHERIT_SHARE` loop complete; `a=mappings.len()`
- phase 1: parent descriptor capture complete; `a=mapping_descs.len()`
- phase 2: child descriptor construction complete; `a=child_descs.len()`
- phase 3: `hv_vcpu_destroy` complete; `a=rc`
- phase 4: `hv_vm_destroy` complete; `a=rc`, `b=VCPU_LIVE`
- phase 5: descriptor stash complete

- [x] **Step 2: Instrument `fork_rebuild`**

Emit role 4 for parent and role 5 for child:

- phase 10: admission reset complete, child only
- phase 11: `create_vm_with_admission` complete
- phase 12: `create_vcpu_with_permit` complete; `a=vcpu id`
- phase 13: counter/handle replacement complete
- phase 14: protection/page-table metadata reset complete
- phase 15: vfork inherit-copy restore complete, parent/vfork only
- phase 16: `restore_vcpu_into` complete
- phase 17: DTrace probe re-register complete, child only
- phase 18: `stamp_rng_generation` complete, child only

---

### Task 4: DTrace and Measurements

**Files:**
- Modify: `scripts/dtrace/fork-phases.d`
- Create: `docs/2026-07-08-hvf-fork-e21-evidence.md`

**Interfaces:**
- Consumes: `fork-lifecycle`, `fork-rebuild`, `fork-pre`, `fork-post`, and `guest-exit`.
- Produces: log-backed phase table and final dominant-phase verdict.

- [x] **Step 1: Add DTrace handling**

Add:

```d
carrick*:::fork-lifecycle
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-lifecycle role=%d phase=%d elapsed_us=%d a=%d b=%d\n",
        pid, (int)arg0, (int)arg1, (uint64_t)arg2, (int64_t)arg3, (int64_t)arg4);
    @lifecycle_us[(int)arg0, (int)arg1] = avg((uint64_t)arg2);
    @lifecycle_count[(int)arg0, (int)arg1] = count();
}
```

At END, print `@lifecycle_us` and `@lifecycle_count`.

- [x] **Step 2: Run verification**

Run:

```bash
cargo check -p carrick-observability -p carrick-aarch64 -p carrick-runtime -p carrick-vmm-hvf
just build
scripts/build-probes.sh
scripts/run-probe.sh getrandomvdsofork
scripts/run-probe.sh vforkvmshare
```

- [x] **Step 3: Run measurements**

Run Carrick-only `perf_fork` and `perf_fork_exec` with the conformance-style base64 injection used in `docs/2026-07-08-hvf-fork-e2-evidence.md`.

Run:

```bash
sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c 'target/release/carrick run-elf conformance-probes/target/aarch64-unknown-linux-musl/release/clonebasic'
```

- [x] **Step 4: Record verdict**

Create `docs/2026-07-08-hvf-fork-e21-evidence.md` with:

- dominant phase and timing table
- exact verification commands and results
- p50/p95 for `perf_fork` and `perf_fork_exec`
- recommendation: VM/vCPU create optimization, teardown/quiesce optimization, host-fork/RSS reduction, admission-path cleanup, or blocked/handoff

---

### Task 5: Commit

**Files:**
- Stage only files listed above plus `docs/2026-07-08-hvf-fork-e21-evidence.md`.

- [x] **Step 1: Final checks**

Run:

```bash
git diff --check
git diff --cached --check
git status --short
```

- [x] **Step 2: Commit**

Use:

```bash
git commit -m "diagnostics(hvf): decompose fork lifecycle cost"
```

The commit body must include measured dominant phase, verification results, and `Co-Authored-By: Codex <codex@openai.com>`.
