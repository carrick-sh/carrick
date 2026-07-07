# HVF Fork Floor E1: Parent-Keeps-VM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove or refute, with a host-level probe, that an HVF fork child can clear its inherited hypervisor state and create its own VM while the PARENT'S VM stays alive — and if proven, land a flag-gated engine change that stops destroying/rebuilding the parent VM on every fork.

**Architecture:** Today `fork_prepare_and_teardown` (crates/carrick-vmm-hvf/src/trap.rs:3854) destroys the parent's vCPU + whole VM before every `libc::fork` because "a live VM at fork time makes the child's `hv_vm_create` fail" (trap.rs:3955-3959), then BOTH sides rebuild in `fork_rebuild` (trap.rs:3989) — parent rebuild ~2.1–3.1 ms + child ~2.4–3.5 ms, against a raw `hv_vm_create` of only 300–700 µs. KVM already has the target shape: the child's inherited fds point at the parent's VM, the child rebuilds its own, the parent keeps running (crates/carrick-vmm-kvm/src/guest_setup.rs:740-746). E1 asks whether HVF permits the same: can the CHILD run `hv_vm_destroy()` on the inherited state to unblock its own `hv_vm_create`, without perturbing the parent? Probe first; engine change only behind the probe's verdict, gated by `CARRICK_HVF_FORK_PARENT_KEEPS_VM=1`.

**Tech Stack:** Rust, `applevisor_sys` raw HVF bindings, the existing `hvf_fork_probe` binary (crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs), `perf_fork` conformance probe, dtrace fork-phase script (`scripts/dtrace/fork-phases.d`).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-06-carrick-kernel-authority-design.md` (rev 2), section "VMM residency and the fork floor".
- HVF binaries MUST be codesigned or every `hv_*` call returns HV_DENIED (0xfae94007): build via `just build`, never bare `cargo build`, before running anything.
- The engine change ships default-OFF behind `CARRICK_HVF_FORK_PARENT_KEEPS_VM`; the default flip is a separate later decision with its own conformance evidence (not in this plan).
- Success metric is the checked-in `perf_fork` probe p50 (target: parent-side rebuild cost gone; fork p50 materially below the current ~3.3–3.5 ms) plus the fork-heavy LTP ratios — never a single LTP row.
- Debugging: `carrick trace` / `carrick debug lldb-run` (skills: carrick-trace, carrick-lldb); no eprintln.
- This plan is INDEPENDENT of the arena plans; it can execute in parallel. It must be re-based mentally on whatever fork-path code is current — anchors below are as of commit 76995ad6.
- macOS HVF facts to respect (from code comments, do not re-litigate without evidence): HVF kernel state is not fork-safe (trap.rs:3955); `hv_vm_destroy()` is process-scoped (one VM per process); vCPUs must be destroyed before `hv_vm_destroy` succeeds (fork_quiesce probe, trap.rs:3968-3976).

---

### Task 1: `parent-keeps-vm` probe mode

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs` (new mode alongside `"recreate-loop"` / `"fork-churn"` / `"concurrent-ceiling"`, dispatch in `imp::main()` at :185-230)

**Interfaces:**
- Consumes (verified in the file): `Vm::create() -> Result<(Vm, Duration), hv_return_t>`, `Vm::destroy(self) -> (hv_return_t, hv_return_t, Duration)`, `Vm::run_spin_for(&self, run_us: u64) -> Result<SpinRun, hv_return_t>`, error constants `HV_SUCCESS`/`HV_BUSY`/`HV_DENIED`/etc. (:24-32).
- Produces: mode `parent-keeps-vm [iterations]` printing one machine-parseable line per iteration plus a summary. Exit code 0 = child path viable AND parent unperturbed in every iteration; 1 = any failure (so scripts can gate on it).

- [ ] **Step 1: Write the mode** (inside `mod imp`, wired into the `match` in `imp::main()`)

```rust
/// E1 probe: fork while the parent VM is LIVE; the child tries to clear the
/// inherited HVF state and build its own VM; the parent proves it is
/// unperturbed by running its vCPU again afterwards.
///
/// Per-iteration protocol:
///   parent: Vm::create + run_spin_for(200) [sanity]
///   parent: fork
///     child: rc_direct   = hv_vm_create(null cfg)      (expect failure today)
///            rc_destroy  = hv_vm_destroy()             (clear inherited state)
///            rc_create   = Vm::create()                (the E1 question)
///            rc_run      = run_spin_for(200)
///            exit code encodes which step failed (0 = all good)
///   parent: waitpid, then run_spin_for(200) again      (perturbation check)
///   parent: hv_vcpu_run rc + exit reason must match the pre-fork run
fn parent_keeps_vm(iterations: u32) -> i32 {
    let mut failures = 0u32;
    for iter in 0..iterations {
        let (vm, create_elapsed) = match Vm::create() {
            Ok(v) => v,
            Err(rc) => {
                println!("iter={iter} stage=parent-create rc={rc:#x} FAIL");
                return 1;
            }
        };
        let pre = vm.run_spin_for(200);
        let pre_ok = pre.is_ok();

        let child = unsafe { libc::fork() };
        if child == 0 {
            // CHILD: never touch the parent's Vm wrapper; raw calls only.
            let rc_direct = unsafe { hv_vm_create(ptr::null_mut()) };
            let rc_destroy = unsafe { hv_vm_destroy() };
            let created = Vm::create();
            let (rc_create, rc_run) = match created {
                Ok((cvm, _)) => {
                    let run = cvm.run_spin_for(200);
                    let ok = run.is_ok();
                    let _ = cvm.destroy();
                    (HV_SUCCESS, if ok { HV_SUCCESS } else { HV_ERROR })
                }
                Err(rc) => (rc, HV_ERROR),
            };
            println!(
                "iter={iter} stage=child rc_direct={rc_direct:#x} rc_destroy={rc_destroy:#x} rc_create={rc_create:#x} rc_run={rc_run:#x}"
            );
            // exit code: 0 all-good, 2 create failed, 3 run failed
            let code = if rc_create != HV_SUCCESS {
                2
            } else if rc_run != HV_SUCCESS {
                3
            } else {
                0
            };
            std::process::exit(code);
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
        let child_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        // PARENT perturbation check: the SAME vCPU must still run.
        let post = vm.run_spin_for(200);
        let post_ok = post.is_ok();
        let (vcpu_rc, vm_rc, _d) = vm.destroy();
        let ok = pre_ok && post_ok && child_code == 0 && vcpu_rc == HV_SUCCESS && vm_rc == HV_SUCCESS;
        if !ok {
            failures += 1;
        }
        println!(
            "iter={iter} stage=verdict pre_ok={pre_ok} post_ok={post_ok} child_code={child_code} parent_destroy=({vcpu_rc:#x},{vm_rc:#x}) create_us={} ok={ok}",
            create_elapsed.as_micros()
        );
    }
    println!("parent-keeps-vm failures={failures}");
    i32::from(failures != 0)
}
```

Dispatch arm in `imp::main()` (match at :194-230):

```rust
"parent-keeps-vm" => {
    let iterations = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    std::process::exit(parent_keeps_vm(iterations));
}
```

Adjust to the file's local conventions (it already `allow`s `print_stdout`/`unwrap_used` at the top; `libc::WIFEXITED` is a fn in the libc crate — if the crate exposes them as `unsafe fn` on this platform, wrap accordingly; `hv_vm_create(ptr::null_mut())` — check `Vm::create`'s config plumbing at :57-76 and pass a null config the same way the direct-create error path does).

- [ ] **Step 2: Build signed + run**

Run: `just build 2>&1 | tail -2` then
`target/release/hvf_fork_probe parent-keeps-vm 50 | tee target/conformance/logs/hvf-probes/parent-keeps-vm-$(date +%Y%m%d-%H%M%S).log`
(if the probe binary lands elsewhere, `find target/release -name 'hvf_fork_probe' -perm -111`; codesign is handled by the just build wrapper — HV_DENIED on every call means it was NOT signed, rebuild via just).

Expected: 50 verdict lines. The load-bearing observations:
- `rc_direct` — today's expectation is a failure code (this documents WHICH: HV_BUSY vs HV_ERROR vs HV_DENIED).
- `rc_destroy` + `rc_create` — THE E1 ANSWER: can the child clear inherited state and create?
- `post_ok=true` on every line — the parent's live vCPU survived a child doing `hv_vm_destroy` on inherited state. `post_ok=false` anywhere = E1 REFUTED (child destroy reaches the parent's kernel object).

- [ ] **Step 3: Also probe the threaded shape** — re-run with the parent holding a SECOND vCPU on a second thread mid-`hv_vcpu_run` during the fork (add a `parent-keeps-vm-threaded` variant reusing the same iteration body with a spawned sibling running `run_spin_for(5000)` across the fork window) IF Step 2 passes. Carrick's real fork happens with sibling vCPUs quiesced but the VM multi-vCPU; the probe should match at least one extra live vCPU.

- [ ] **Step 4: Commit the probe regardless of verdict**

```bash
git add crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs
git commit -m "feat(hvf): parent-keeps-vm fork probe (E1)"
```

---

### Task 2: Record the verdict + decision gate

**Files:**
- Modify: the current conformance/fork diary (`docs/2026-07-07-conformance-bless-diary.md` or its successor)

- [ ] **Step 1: Write the evidence entry** — probe log paths, the rc values observed, pass/fail counts for plain and threaded variants, and the one-line verdict:
  - **E1 CONFIRMED** (child creates after destroy; parent unperturbed, both variants) → proceed to Task 3.
  - **E1 REFUTED** (child cannot create, or parent perturbed) → STOP this plan after committing the diary entry; the fallback ladder is spec E1b/E2 (measure + shrink the rebuild via lazy stage-2 replay) — write a one-paragraph handoff naming E2 as next and which probe numbers justify it.
- [ ] **Step 2: Commit**

```bash
git add docs/
git commit -m "docs(hvf): E1 parent-keeps-vm probe verdict"
```

---

### Task 3 (CONDITIONAL on E1 CONFIRMED): flag-gated engine change

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs:3854-3981` (`fork_prepare_and_teardown`), `:3989-4210` (`fork_rebuild`)
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:450-500` (the fork orchestration calling the two halves)
- Test: `crates/carrick-vmm-hvf/src/trap.rs` unit tests + conformance rows

**Interfaces:**
- Produces: env flag `CARRICK_HVF_FORK_PARENT_KEEPS_VM` (unset/0 = today's behavior, byte-identical); helper `fn fork_parent_keeps_vm() -> bool` reading it once via `OnceLock<bool>` (same pattern as `CARRICK_HVF_ATOMIC_PERMIT`, trap.rs:1434-1450).
- Behavior under the flag:
  - `fork_prepare_and_teardown`: still fires `fork_pre`, still does the vfork `VM_INHERIT_SHARE` minherit pass, still captures `mapping_descs`/`child_descs` (the CHILD needs its descriptor set exactly as today) — but SKIPS the parent `hv_vcpu_destroy`/`hv_vm_destroy` (trap.rs:3963-3967). Fire `fork_quiesce(2, ...)` with a distinguishing arg so traces show which mode ran.
  - CHILD side of `fork_rebuild`: FIRST `let _ = unsafe { applevisor_sys::hv_vm_destroy() };` (clear inherited state — per the probe, ignore rc if the probe showed a benign code for "nothing usable inherited"; assert on codes the probe never produced), then the existing path unchanged: `reset_admission_permits_after_fork_child`, `create_vm_with_admission(ForkRebuild)`, remap `child_descs`, alias re-registration, protections/page-tables clone.
  - PARENT side: `fork_rebuild` becomes a no-op that only drops the stashed descriptor Vecs' CHILD copies (`fork_child_descs`) and restores `VM_INHERIT_COPY` for the vfork share (trap.rs:4138-4150 logic). The parent's VM, vCPU, mappings, `protections`, `page_tables`, and the sibling-union remap (trap.rs:4167-4210) are all untouched because nothing was destroyed. The parent does NOT release/reacquire its admission permit (its VM never went away) — verify no permit accounting drift: occupancy is derived from slots, and the parent's slot was never freed.
- Sibling vCPU handling stays EXACTLY as today in this task (quiesced siblings still park/recreate their vCPUs); letting siblings keep live vCPUs across fork is a follow-up optimization once this lands.

- [ ] **Step 1: Write the failing unit test** (trap.rs test mod; pure policy, no HVF)

```rust
#[test]
fn parent_keeps_vm_flag_defaults_off_and_parses() {
    // SAFETY/test-hygiene: same env-var test pattern as the atomic-permit flag.
    assert!(!fork_parent_keeps_vm_from(None));
    assert!(!fork_parent_keeps_vm_from(Some("0")));
    assert!(!fork_parent_keeps_vm_from(Some("false")));
    assert!(fork_parent_keeps_vm_from(Some("1")));
}
```
(`fork_parent_keeps_vm_from(v: Option<&str>) -> bool` is the pure parser; the `OnceLock` wrapper calls it with the real env — mirror the existing `CARRICK_HVF_ATOMIC_PERMIT` structure at trap.rs:1434-1450.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p carrick-vmm-hvf fork_parent_keeps_vm --lib` — compile error.
- [ ] **Step 3: Implement** per the Interfaces block. Key care points, each already commented in the file:
  - Do NOT drop the old mappings Vec in the parent path (there is no old Vec to replace — the parent keeps `self.mappings`; the leak-discipline comment at trap.rs:4049-4064 applies only to the rebuild path).
  - The child's `hv_vm_destroy`-first must happen BEFORE `create_vm_with_admission` so `HV_NO_RESOURCES` backpressure semantics are unchanged.
  - `replace_destroyed_vm` must NOT run in the parent (grep its uses; it swaps the engine's VM handle — parent keeps the original).
  - `is_forked_child`/`forked_no_exec`/vvar RNG re-stamp remain child-only and unchanged.
- [ ] **Step 4: Signed build + probe-level regression** — `just build`, then re-run BOTH probe modes from Task 1 (still green — the engine change must not have altered the host-level facts), then run the E1 flag smoke by hand:

```bash
CARRICK_HVF_FORK_PARENT_KEEPS_VM=1 target/release/carrick run --raw --fs host ubuntu:24.04 /bin/sh -c 'echo forked-$( (echo child) )-ok'
```
Expected: `forked-child-ok`, exit 0.

- [ ] **Step 5: Measure the floor** — the whole point:

```bash
# untraced, flag OFF then ON, 300 iterations each (perf_fork is the raw
# fork+exit+waitpid probe used in the 2026-07-07 diary):
target/release/carrick-conformance --suite bench-process-spawn --jsonl target/conformance/e1-off.jsonl
CARRICK_HVF_FORK_PARENT_KEEPS_VM=1 target/release/carrick-conformance --suite bench-process-spawn --jsonl target/conformance/e1-on.jsonl
```
(if the process-spawn bench suite name differs, find it: `grep -n "process-spawn\|perf_fork" scripts/conformance/suites.toml crates/carrick-conformance/src/generate.rs`.)
Expected: flag-ON p50 materially below flag-OFF; record exact numbers. Also `scripts/dtrace/fork-phases.d` under the flag: parent rebuild phase should vanish from the trace.

- [ ] **Step 6: Conformance ladder under the flag**

```bash
CARRICK_HVF_FORK_PARENT_KEEPS_VM=1 target/release/carrick-conformance \
  --suite ltp-epoll-ltp --suite ltp-getpid01 --suite ltp-fork09 \
  --suite ltp-waitid07 --suite ltp-clone08 --suite ltp-ptrace06 \
  --jsonl target/conformance/e1-fork-rows.jsonl
```
Expected: all MATCH; `ltp-epoll-ltp` and `ltp-getpid01` ratios sharply down from 36x/7-39x. Then `CARRICK_HVF_FORK_PARENT_KEEPS_VM=1 just conformance smoke` — exit 0. Run the fork-heavy rows THREE times (fork changes are race-sensitive; single greens don't count).

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-vmm-hvf
git commit -m "feat(hvf): parent keeps VM across fork behind CARRICK_HVF_FORK_PARENT_KEEPS_VM"
```

- [ ] **Step 8: Diary the measurements** — before/after `perf_fork` p50/p95, fork-phase trace deltas, the six-row ratios, and the explicit list of what the default flip still needs (full-tier run under the flag; threaded/Go workloads: `go-osexec`, `cpython-forkserver` rows; vfork/`posix_spawn` shells; bhyve/KVM untouched confirmation). Commit docs.

```bash
git add docs/
git commit -m "docs(hvf): E1 engine-change measurements and flip criteria"
```

---

## Self-Review Notes

- Spec coverage: "VMM residency and the fork floor" E1 ✓ (probe Task 1, verdict gate Task 2, flag-gated change Task 3, perf_fork ratchet Step 5, explicit no-auto-flip). E2/E3 intentionally out of scope; Task 2 hands off to E2 if refuted.
- The probe's exit-code contract (0 viable / 1 not) lets Task 3's Step 4 use it as a regression guard.
- Type consistency: probe uses only verified helpers (`Vm::create`/`destroy`/`run_spin_for`, constants at :24-32); engine change touches only the two functions whose current bodies were read and whose line anchors are cited.
- Honesty note: `rc_direct`'s exact failure code today is UNKNOWN (the "resource busy" comment at trap.rs:3955 predates structured probing) — the probe documents it rather than asserting it; only `rc_create`/`rc_run`/`post_ok` gate the verdict.
