# HVF Fork Floor E2: Lazy Stage-2 Replay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove whether HVF fork rebuild cost can be reduced by avoiding eager stage-2 replay, while preserving Carrick's one-Linux-process-to-one-host-process invariant.

**Architecture:** E1 refuted parent-keeps-VM, so the parent and child must still rebuild their HVF VM after `fork(2)`. E2 keeps that residency shape but separates fork metadata reconstruction from `hv_vm_map` materialization: rebuild always restores `HvfMappedRegion` metadata and host ownership, while a flag-gated path reduces the stage-2 map set to a safe bootstrap subset and lazily maps ordinary regions on translation faults. Instrumentation lands first so the default eager path and any flag-gated experiment have comparable counts and timings.

**Tech Stack:** Rust 2024, `applevisor_sys` HVF bindings, Carrick USDT probes in `carrick-observability`, `scripts/dtrace/fork-phases.d`, `perf_fork` and `perf_fork_exec` conformance probes, signed macOS/HVF release binary via `just build`.

## Global Constraints

- Preserve Carrick's one-Linux-process-to-one-host-process invariant.
- Do not introduce a hot-path daemon, supervisor RPC on fork/block/wake, or guest-kernel fallback.
- Use repo-local evidence over narrative: current code, existing plans, probe logs, tests, conformance artifacts, and fresh measurements.
- Run `just build` before any HVF guest/probe run that needs codesigning.
- Never run Carrick and the Docker oracle concurrently.
- Keep unrelated dirty files out of commits.
- Default behavior must remain the current eager rebuild path unless `CARRICK_HVF_FORK_LAZY_STAGE2=1` is explicitly set.
- The E2 verdict artifact must list verification commands and results, including fork p50/p95 and fork rebuild map counts.

---

## File Structure

- `crates/carrick-observability/src/probes.rs`: add a stable `fork__rebuild` USDT probe and stub with scalar payloads for role, phase, descriptor count, map count, and elapsed microseconds.
- `crates/carrick-vmm-hvf/src/trap.rs`: fire the new probe from `fork_rebuild` around eager local replay, sibling replay, and total rebuild; later add the flag-gated lazy materialization path here.
- `scripts/dtrace/fork-phases.d`: consume `fork-rebuild` and print parent/child map count and timing aggregates.
- `docs/superpowers/plans/2026-07-08-hvf-fork-e2-lazy-stage2.md`: this executable plan.
- `docs/2026-07-08-hvf-fork-e2-evidence.md`: final verdict and handoff artifact.

---

### Task 1: Fork Rebuild Measurement Probes

**Files:**
- Modify: `crates/carrick-observability/src/probes.rs`
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`
- Modify: `scripts/dtrace/fork-phases.d`

**Interfaces:**
- Consumes: existing `fork_pre`, `fork_quiesce`, `fork_post`, and `hv_vm_map_alias` probe style in `carrick-observability`.
- Produces: `crate::probes::fork_rebuild(role: i32, phase: i32, desc_count: u64, map_count: u64, elapsed_us: u64)`.
- Role values: `0=parent`, `1=child`.
- Phase values: `0=begin`, `1=local-map-end`, `2=sibling-map-end`, `3=restore-end`.

- [ ] **Step 1: Add the USDT declaration**

Add this provider function next to `fork__post`:

```rust
/// Fork rebuild detail. `role`: 0=parent, 1=child. `phase`: 0=begin,
/// 1=local-map-end, 2=sibling-map-end, 3=restore-end. `desc_count` is the local
/// descriptor set for phases 0/1/3 and the sibling candidate set for phase 2.
/// `map_count` is the number of `hv_vm_map` calls completed in that phase.
/// `elapsed_us` is measured from the phase start, except phase 3 which is total
/// rebuild elapsed. Keep this at five args; macOS DTrace has dropped the sixth
/// arg in this provider path.
fn fork__rebuild(_: i32, _: i32, _: u64, _: u64, _: u64) {}
```

- [ ] **Step 2: Add the public wrapper and stub**

Add this real wrapper:

```rust
pub fn fork_rebuild(
    role: i32,
    phase: i32,
    desc_count: u64,
    map_count: u64,
    elapsed_us: u64,
) {
    carrick_usdt::fork__rebuild!(|| (role, phase, desc_count, map_count, elapsed_us));
}
```

Add this stub:

```rust
stub!(fork_rebuild(role: i32, phase: i32, desc_count: u64, map_count: u64, elapsed_us: u64));
```

- [ ] **Step 3: Fire probes in `fork_rebuild`**

At the top of `fork_rebuild`, compute `role` and `rebuild_start`:

```rust
let role = if is_child { 1 } else { 0 };
let rebuild_start = std::time::Instant::now();
```

After selecting `descs`, fire phase 0 with `desc_total = descs.len() as u64`. During the local replay loop, increment `local_maps` after each successful `hv_vm_map`. Fire phase 1 with elapsed time from a `local_map_start`. During parent sibling replay, record `sibling_total` and increment `sibling_maps` after successful maps; fire phase 2 from the parent only. After `restore_vcpu_into`, fire phase 3 with `rebuild_start.elapsed().as_micros() as u64`.

- [ ] **Step 4: Update the DTrace script**

Add `carrick*:::fork-rebuild` actions to print raw events and aggregate:

```d
carrick*:::fork-rebuild
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-rebuild role=%d phase=%d desc=%d maps=%d elapsed_us=%d\n",
        pid, (int)arg0, (int)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4);
    @rebuild_us[(int)arg0, (int)arg1] = avg((uint64_t)arg4);
    @rebuild_maps[(int)arg0, (int)arg1] = avg((uint64_t)arg3);
    @rebuild_descs[(int)arg0, (int)arg1] = avg((uint64_t)arg2);
}
```

At END, print `@rebuild_us`, `@rebuild_maps`, and `@rebuild_descs`.

- [ ] **Step 5: Verify compile and probe surface**

Run:

```bash
cargo check -p carrick-observability -p carrick-vmm-hvf
just build
otool -l target/release/carrick | grep dof
```

Expected: both cargo checks pass, `just build` signs `target/release/carrick`, and `otool` shows a `__dof_carrick` section.

---

### Task 2: Baseline Eager Rebuild Measurements

**Files:**
- Create: `docs/2026-07-08-hvf-fork-e2-evidence.md`
- Append logs under: `target/conformance/logs/hvf-fork-e2/`

**Interfaces:**
- Consumes: `fork__rebuild` probe from Task 1.
- Produces: eager baseline table with fork p50/p95, local descriptor count, local `hv_vm_map` count, sibling replay count, and rebuild elapsed microseconds for parent and child.

- [ ] **Step 1: Build signed binary and probes**

Run:

```bash
just build
scripts/build-probes.sh
```

Expected: `target/release/carrick` exists and is signed; `conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork` and `perf_fork_exec` exist.

- [ ] **Step 2: Run Carrick-only `perf_fork`**

Run:

```bash
mkdir -p target/conformance/logs/hvf-fork-e2
RUN_ID="cr-e2-perf-fork-$(date +%Y%m%d-%H%M%S)"
export CARRICK_RUN_ID="$RUN_ID"
base64 -i conformance-probes/target/aarch64-unknown-linux-musl/release/perf_fork \
  | timeout 120 target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  | tee "target/conformance/logs/hvf-fork-e2/perf_fork-${RUN_ID}.log"
sudo -n scripts/sudo/kill.sh "$RUN_ID" >/dev/null 2>&1 || true
```

Expected: output contains `fork_p50_us=`, `fork_p95_us=`, `iters=300`, and `nproc=`.

- [ ] **Step 3: Run Carrick-only `perf_fork_exec`**

Run the same command with `perf_fork_exec` as the probe name and log prefix.

Expected: output contains `fork_exec_p50_us=`, `fork_exec_p95_us=`, `iters=200`, and `nproc=`.

- [ ] **Step 4: Capture DTrace fork phase details**

Run:

```bash
RUN_ID="cr-e2-dtrace-$(date +%Y%m%d-%H%M%S)"
export CARRICK_RUN_ID="$RUN_ID"
sudo -n dtrace -q -s scripts/dtrace/fork-phases.d -c "target/release/carrick run ubuntu:24.04 --raw --fs host /bin/sh -c 'for i in \$(seq 1 20); do /bin/true; done'" \
  | tee "target/conformance/logs/hvf-fork-e2/fork-phases-${RUN_ID}.log"
sudo -n scripts/sudo/kill.sh "$RUN_ID" >/dev/null 2>&1 || true
```

Expected: output contains `fork-rebuild role=0`, `fork-rebuild role=1`, `rebuild us`, `rebuild maps`, and `rebuild descs`.

- [ ] **Step 5: Record the eager baseline**

Write `docs/2026-07-08-hvf-fork-e2-evidence.md` with the sections below. The committed file must contain concrete numeric values copied from the logs, not angle-bracket placeholders. Use `awk -F= '/fork_/ {print}' target/conformance/logs/hvf-fork-e2/perf_fork-*.log` and the `rebuild us` / `rebuild maps` / `rebuild descs` DTrace summaries to populate the table.

```markdown
# HVF Fork Floor E2 Evidence

## Verdict

Status: in progress.

## Eager Baseline

| Measurement | Result | Evidence |
|---|---:|---|
```

Add one row per measured value. Do not commit target logs.

---

### Task 3: Flag-Gated Lazy Stage-2 Materialization Spike

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs`

**Interfaces:**
- Consumes: full `HvfMappedRegion` metadata reconstructed during `fork_rebuild`.
- Produces: default-off environment switch `CARRICK_HVF_FORK_LAZY_STAGE2=1` and helper `try_lazy_fork_region_remap(&mut self, fault_ipa: u64, fault_va: u64) -> Result<bool, TrapError>`.

- [ ] **Step 1: Add default-off flag parser**

Add a process-local helper near other HVF fork helpers:

```rust
fn lazy_stage2_fork_enabled() -> bool {
    std::env::var_os("CARRICK_HVF_FORK_LAZY_STAGE2")
        .and_then(|v| v.into_string().ok())
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}
```

- [ ] **Step 2: Add stage-2 materialization state**

Extend `HvfMappedRegion` with:

```rust
stage2_mapped: bool,
```

Set it to `true` for every existing allocation and alias mapping path that calls `hv_vm_map` immediately. In the flag-gated lazy fork path, push the metadata with `stage2_mapped: false` for regions whose stage-2 replay was skipped.

- [ ] **Step 3: Preserve eager metadata reconstruction**

Refactor the current descriptor replay loop so `self.mappings.push(HvfMappedRegion { ... })` always happens after descriptor validation, independent of whether `hv_vm_map` is called. The metadata must remain complete so syscall-path memory access through `mapping_for_range` still finds the host backing before first guest hardware touch.

- [ ] **Step 4: Add general lazy remap helper**

Add:

```rust
fn try_lazy_fork_region_remap(
    &mut self,
    fault_ipa: u64,
    fault_va: u64,
) -> Result<bool, TrapError> {
    let Some(region) = self
        .mappings
        .iter_mut()
        .find(|m| !m.stage2_mapped && fault_ipa >= m.ipa && fault_ipa < m.ipa.saturating_add(m.size as u64))
    else {
        return Ok(false);
    };
    let perms_raw: u64 = u64::from(region.perms);
    let rc = unsafe {
        applevisor_sys::hv_vm_map(
            region.host_addr as *mut std::ffi::c_void,
            region.ipa,
            region.size,
            perms_raw,
        )
    };
    crate::probes::fork_rebuild(
        if self.is_forked_child { 1 } else { 0 },
        4,
        1,
        u64::from(rc == 0),
        0,
    );
    if rc != 0 {
        return Err(TrapError::ChildMapFailed {
            host_addr: region.host_addr as u64,
            guest_start: fault_va,
            size: region.size,
            code: rc as u32,
        });
    }
    region.stage2_mapped = true;
    Ok(true)
}
```

If borrow checking conflicts with `TrapError` construction, copy the scalar fields out before the `hv_vm_map` call.

- [ ] **Step 5: Call the lazy helper from the EL0 translation-fault path**

In `run_to_exit`, before the fatal `EL0Fault` return, try `try_lazy_fork_region_remap(fault_ipa, far)` after `try_lazy_alias_remap`. On `Ok(true)`, `continue`; on `Ok(false)`, preserve current behavior; on `Err`, return the error.

- [ ] **Step 6: Keep bootstrap-critical mappings eager**

In the first flag-gated spike, skip eager stage-2 replay only for high-VA arena and sibling mappings. Keep low boot regions, page tables, trampolines, stack, vvar, and any region needed before EL0 translation faults eager. This is conservative by design: a later E2.1 can shrink the eager set after traces prove first-touch safety.

- [ ] **Step 7: Verify default-off behavior**

Run:

```bash
cargo check -p carrick-vmm-hvf
just build
scripts/run-probe.sh getrandomvdsofork
scripts/run-probe.sh vforkvmshare
```

Expected: both probes report `MATCH`; no Docker process overlaps the Carrick phase because `scripts/run-probe.sh` is sequential.

---

### Task 4: Flag-On Measurement or Blocker Handoff

**Files:**
- Modify: `docs/2026-07-08-hvf-fork-e2-evidence.md`

**Interfaces:**
- Consumes: flag-gated implementation from Task 3.
- Produces: E2 verdict: confirmed improvement, refuted improvement, or blocked with exact failing phase and evidence.

- [ ] **Step 1: Run the flag-on smoke**

Run:

```bash
CARRICK_HVF_FORK_LAZY_STAGE2=1 scripts/run-probe.sh getrandomvdsofork
CARRICK_HVF_FORK_LAZY_STAGE2=1 scripts/run-probe.sh vforkvmshare
```

Expected: both probes either `MATCH`, or the evidence file records the first failing command, exit status, and the relevant `fork-rebuild` or fault trace.

- [ ] **Step 2: Run flag-on perf if smoke passes**

Run `perf_fork` and `perf_fork_exec` using the Task 2 Carrick-only commands with `CARRICK_HVF_FORK_LAZY_STAGE2=1` in the environment.

Expected: output contains p50/p95 metrics, and the evidence file compares eager vs flag-on results.

- [ ] **Step 3: Record a clear verdict**

Use one of these verdict shapes with concrete measured values and named logs:

```markdown
## Verdict

E2 confirmed: flag-gated lazy stage-2 replay reduced `perf_fork` p50 and parent/child eager map counts without regressing focused fork probes. The measurement table below gives the exact eager and flag-on values.
```

```markdown
## Verdict

E2 refuted: lazy stage-2 replay did not materially reduce `perf_fork` p50. The measurement table below shows the remaining dominant fork phase and the next fork-floor track.
```

```markdown
## Verdict

E2 blocked: the first safe flag-gated lazy set fails before it can produce a comparable perf measurement. The blocker section below names the failing command, observed result, and next implementation track.
```

No placeholders may remain in the committed file.

---

### Task 5: Final Verification and Commit

**Files:**
- Modify: `docs/2026-07-08-hvf-fork-e2-evidence.md`
- Possibly modify: `docs/superpowers/plans/2026-07-08-hvf-fork-e2-lazy-stage2.md`

**Interfaces:**
- Consumes: measurements and smoke results from Tasks 1-4.
- Produces: one or more narrow commits with no unrelated dirty files.

- [ ] **Step 1: Run final verification**

Run:

```bash
git diff --check
cargo check -p carrick-observability -p carrick-vmm-hvf
just build
scripts/run-probe.sh getrandomvdsofork
scripts/run-probe.sh vforkvmshare
```

Expected: all commands pass. If flag-on behavior is blocked, default-off probes must still pass and the evidence file must name the blocking command and log.

- [ ] **Step 2: Stage only related files**

Run:

```bash
git status --short
git add crates/carrick-observability/src/probes.rs crates/carrick-vmm-hvf/src/trap.rs scripts/dtrace/fork-phases.d docs/superpowers/plans/2026-07-08-hvf-fork-e2-lazy-stage2.md docs/2026-07-08-hvf-fork-e2-evidence.md
git diff --cached --stat
```

Expected: no unrelated pre-existing dirty files are staged.

- [ ] **Step 3: Commit**

Run:

```bash
git commit -m "diagnostics(hvf): measure fork rebuild stage-2 replay"
```

Commit body must explain why E2 follows the E1 refutation, what was measured or implemented, and the verification commands/results. Include `Co-Authored-By: Codex <codex@openai.com>`.
