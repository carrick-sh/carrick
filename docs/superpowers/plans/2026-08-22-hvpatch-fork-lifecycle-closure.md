# HVPatch Fork Lifecycle Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the HVPatch kernel's process lifecycle correct on one honest code path — retire the dead execution model, fix fork and exec teardown, and restore every gate to actually gating.

**Architecture:** Three phases with different execution models, because guest runs cannot be parallelized. Phase 1 is a SOLO compiler-driven collapse: deleting the single-variant `ExecutionBackend` turns every unreachable branch into a build failure rather than an assertion, so live responsibilities hiding in dead code surface as broken builds. Phase 2 fans out file-disjoint mechanical cleanup across worktrees. Phase 3 is SERIALIZED fix-and-verify on one lane, with read-only subagents for analysis only.

**Tech Stack:** Rust 1.96 (pinned), macOS/Apple Silicon, Hypervisor.framework, `just` recipes, clippy `-D warnings`, DTrace via `carrick trace`, lldb via `carrick debug`.

**Spec:** `docs/superpowers/specs/2026-08-22-hvpatch-fork-lifecycle-closure-design.md`

## Global Constraints

- **Canonical lane only:** macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest. Non-macOS hardware lanes (bsdvm, KVM smoke) are OUT OF SCOPE.
- **Never run carrick and Docker concurrently.** Both are heavy VMs and starve each other, producing wrong verdicts. The conformance harness is two-phase by design; do not defeat it.
- **Never parallelize guest runs.** Fan-out is permitted ONLY in Phase 2, which touches no guest.
- **Always build with `just build`** (codesigns the `com.apple.security.hypervisor` entitlement). A bare `cargo build` strips it and every guest dies `HV_DENIED (0xfae94007)`. After changing `carrick-runtime`, rebuild `-p carrick-cli` or you test a stale binary.
- **Never `git stash`** — the stash is repo-global and shared by every worktree.
- **Never `git commit --no-verify`.**
- **Gate logs are never truncated.** `just ci | tail` reports `tail`'s exit status, not the gate's. Redirect to a file and read `$?`. Grep gate logs with `-a`; they carry binary bytes.
- **Scoped cleanup only.** Export a unique `CARRICK_RUN_ID` per run and reap with `./scripts/sudo/kill.sh "$CARRICK_RUN_ID"`. Never `pkill -f carrick`.
- **Red-first.** Prove each reducer fails against the broken binary before fixing, and re-run after.
- **Attribute before believing.** Reproduce any suspected regression on unmodified HEAD in a separate worktree before calling it one.
- Commit messages: Conventional Commits with a real body (Why / What / Verified), ending `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

---

## File Structure

| File | Responsibility | Phase |
|---|---|---|
| `crates/carrick-runtime/src/page_profile.rs` | `ExecutionBackend` enum — deleted | 1 |
| `crates/carrick-runtime/src/runtime.rs` | `persistent_hvf_vm_lifecycle` tautology — deleted | 1 |
| `crates/carrick-runtime/src/vcpu_loop/mod.rs` | welded loop, `OwnerThreadEngine`, `CompatibilityThreadWaiter`, `VcpuThreadHandle::Job` — deleted | 1 |
| `crates/carrick-runtime/src/vcpu_loop/quiesce.rs` | host-fork `handle_fork` — deleted | 1 |
| `crates/carrick-runtime/src/vcpu_loop/continuation.rs` | transitional runner cluster — deleted; `include_str!` gates inverted | 1 |
| `crates/carrick-runtime/src/threaded_loop.rs` | mature-VMM bootstrap branch — deleted | 1 |
| `crates/carrick-vmm-hvf/src/trap.rs` | 18 `!persistent_vm_lifecycle` arms — collapsed | 1 |
| `crates/carrick-spec/src/lib.rs`, `crates/carrick-cli/src/args.rs` | `--native-page-profile` surface — deleted | 2 |
| `scripts/dtrace/*.d`, `docs/*.md` | header recipes naming retired backends — corrected | 2 |
| `crates/carrick-runtime/src/vcpu_loop/executor.rs` | terminal path for a forked child | 3 |
| `scripts/migrate/host-authority-transition-inventory.json` | census rows surviving deletion | 3 |

---

## Phase 0 — Baseline (must complete before Task 1)

### Task 0: Freeze the pre-change baseline

**Files:**
- Create: `docs/perf-results/2026-08-22-fork-closure-baseline.md`

**Interfaces:**
- Produces: the failure-shape table every later phase compares against.

- [ ] **Step 1: Record the exact signed artifact**

```bash
cd /Volumes/CaseSensitive/carrick
just build -p carrick-cli
BIN=target/release/carrick
echo "HEAD: $(git rev-parse HEAD)"; echo "dirty: $(git status --porcelain | wc -l)"
shasum -a 256 $BIN
codesign -dvvv --entitlements :- $BIN 2>&1 | grep -E "Identifier=|CDHash=|hypervisor"
otool -l $BIN | grep -A2 LC_UUID | grep uuid
otool -l $BIN | grep -c __dof_carrick
```

- [ ] **Step 2: Record the fork battery failure SHAPES**

This table is the phase-1 exit criterion: deletion must not change any shape.

```bash
P=conformance-probes/target/aarch64-unknown-linux-musl/release
for p in clonebasic forkcow forkfiletable forkshared waitexitstorm waitidsiuid \
         mqnotifycrossproc futexpingpong cloneexitsig sigchld xsignal \
         forkexecpthread execpipe clone3args cloneexithandled \
         threadspawn manythreads epollinmemwake epolloutrearm rtsigqueueinfo \
         vforkpid vforkvmshare; do
  RID="base-$p"
  CARRICK_RUN_ID=$RID timeout 20 ./target/release/carrick run-elf --raw \
    --exec-backend hvpatch $P/$p >/tmp/$RID.out 2>/tmp/$RID.err
  printf '%-20s exit=%-4s lines=%-3s %s\n' "$p" "$?" \
    "$(wc -l </tmp/$RID.out | tr -d ' ')" \
    "$(grep -ao 'FATAL[^:]*: [a-z ]*' /tmp/$RID.err | head -1)"
  ./scripts/sudo/kill.sh $RID >/dev/null 2>&1
done
```

- [ ] **Step 3: Record the two reducers**

```bash
for sh in /bin/sh /bin/bash; do
  RID="base-$(basename $sh)"
  CARRICK_RUN_ID=$RID timeout 25 ./target/release/carrick run ubuntu:24.04 \
    --raw --fs host $sh -c '/bin/echo hi' >/tmp/$RID.out 2>/tmp/$RID.err
  echo "$sh exit=$? out=[$(cat /tmp/$RID.out)] err=[$(tail -1 /tmp/$RID.err | head -c 80)]"
  ./scripts/sudo/kill.sh $RID >/dev/null 2>&1
done
```

Expected at baseline: `/bin/sh` exits 125 with `hi` on stdout; `/bin/bash` exits 0.

- [ ] **Step 4: Record the gate baseline**

```bash
RUST_TEST_THREADS=1 just ci > target/perf/ci-baseline.log 2>&1
echo "JUST_CI_EXIT=$?"
tail -5 target/perf/ci-baseline.log
```

- [ ] **Step 5: Write the baseline doc and commit**

Record the artifact identity, the shape table, both reducer results, and the
`just ci` stopping point verbatim.

```bash
git add docs/perf-results/2026-08-22-fork-closure-baseline.md
git commit -m "docs: freeze the fork-closure phase-0 baseline"
```

---

## Phase 1 — Collapse (SOLO — do not dispatch these tasks in parallel)

### Task 1: Collapse the `ExecutionBackend` tautology

**Files:**
- Modify: `crates/carrick-runtime/src/page_profile.rs:14-19`
- Modify: `crates/carrick-runtime/src/runtime.rs:902-904`, `runtime.rs:2678`
- Modify: the 8 negative guards: `vcpu_loop/mod.rs:334`, `dispatch/mod.rs:4747`, `dispatch/mod.rs:7433`, `dispatch/fs.rs:1722`, `dispatch/fs.rs:7864`, `dispatch/signal.rs:1315`, `hvpatch/mod.rs:1183`, `hvpatch/mod.rs:1425`

**Interfaces:**
- Consumes: nothing.
- Produces: a tree where the welded loop is a COMPILE ERROR rather than an unreachable branch. Every later Phase 1 task depends on that.

- [ ] **Step 1: Confirm the enum is single-variant**

```bash
sed -n '14,19p' crates/carrick-runtime/src/page_profile.rs
grep -rn "ExecutionBackend::" --include='*.rs' crates/carrick-runtime/src | wc -l
```

Expected: one variant `HvPatch`; ~52 comparison sites.

- [ ] **Step 2: Delete the enum and its accessor**

Remove `ExecutionBackend` entirely. Remove `SyscallDispatcher::execution_backend()`. Remove `persistent_hvf_vm_lifecycle()` (`runtime.rs:902`) and the unit test asserting the tautology (`runtime.rs:2678`).

- [ ] **Step 3: Build and let the compiler enumerate the fallout**

```bash
cargo check -p carrick-runtime --lib 2>&1 | tee /tmp/collapse-errors.log | grep -c "^error"
grep -E "^error|--> " /tmp/collapse-errors.log | head -60
```

Do NOT fix these yet — read them. Every error is either a tautology to delete or dead code Task 2/3 removes. If any error names a function you cannot classify as one of those two, STOP: it is a live responsibility hiding in dead code, and it must be ported before deletion continues.

- [ ] **Step 4: Remove each tautological comparison**

For each of the 52 sites, delete the condition and keep the HvPatch arm. For the 8 negative guards, delete the guarded block entirely — it is unreachable.

- [ ] **Step 5: Verify compile and no behaviour change**

```bash
cargo check -p carrick-runtime --lib && just build -p carrick-cli
RID=t1-shape; CARRICK_RUN_ID=$RID timeout 20 ./target/release/carrick run-elf --raw \
  --exec-backend hvpatch conformance-probes/target/aarch64-unknown-linux-musl/release/forkcow \
  >/tmp/$RID.out 2>/tmp/$RID.err; echo "exit=$?"; tail -1 /tmp/$RID.err
./scripts/sudo/kill.sh $RID >/dev/null 2>&1
```

Expected: the SAME exit code and SAME FATAL text as the Task 0 baseline. A different shape means the collapse changed behaviour — revert and find out why.

- [ ] **Step 6: Commit**

```bash
just fmt && git add -u crates/
git commit -m "refactor(runtime): delete the single-variant ExecutionBackend"
```

### Task 2: Delete the welded-thread loop and invert its source-text gates

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:8292-8384`, `8942-10723`, `6448-6685`, `6686-6817`, `8233-8253`, `8821-8921`, `2293-2345`
- Modify: `crates/carrick-runtime/src/vcpu_loop/quiesce.rs:445-1176`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs:284-312`, `180-184`, `168`
- Test: `crates/carrick-runtime/src/vcpu_loop/continuation.rs:4907,4922,4949,8471,8482,8526,8542`; `vcpu_loop/mod.rs:10970,11051`

**Interfaces:**
- Consumes: Task 1's compile errors.
- Produces: a tree with exactly one vCPU entry path, `launch_persistent_hvpatch_job`.

- [ ] **Step 1: Invert the source-text gates FIRST**

Do this before deleting, so a `split()` on absent text cannot silently return the whole file. Each assertion that the text is PRESENT becomes an assertion that it is ABSENT, with a comment naming what was deleted and why.

```bash
grep -n 'run_vcpu_until_exit\|launch_vcpu_until_exit\|TransitionalDedicatedRunner\|engine.save_guest_state()' \
  crates/carrick-runtime/src/vcpu_loop/continuation.rs \
  crates/carrick-runtime/src/vcpu_loop/mod.rs | grep -n 'include_str\|split\|contains'
```

- [ ] **Step 2: Run the inverted gates and watch them FAIL**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 2>&1 | grep -A6 "^failures:"
```

Expected: the inverted assertions fail, because the text is still present. This is the red-first proof that the gates actually test what they claim.

- [ ] **Step 3: Delete the dead functions**

Delete in this order so each deletion's callers are already gone: `launch_compatibility_vcpu_future`, `prepare_initial_runner_handoff`, the tail of `launch_vcpu_until_exit`, `run_vcpu_until_exit`, `run_vcpu_until_exit_inner`, `suspend_hvpatch_continuation`, `yield_hvpatch_quantum`, `handle_fork`, `OwnerThreadEngine`, and the `threaded_loop.rs` mature-VMM bootstrap branch with its `root_linux_tid` and `main_registry_id_for_backend` else-arms.

- [ ] **Step 4: Verify the gates now pass and behaviour is unchanged**

```bash
cargo check -p carrick-runtime --lib
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 2>&1 | tail -3
just build -p carrick-cli
```

Then re-run the Task 0 shape table. Every shape must be identical.

- [ ] **Step 5: Commit**

```bash
just fmt && git add -u crates/
git commit -m "refactor(runtime): delete the welded-thread vcpu loop"
```

### Task 3: Delete the transitional runner and its shims

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/continuation.rs:3273-4126` and its `#[cfg(test)]` block `4617-8628`
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:737-742` (`transitional_runner` field), `1493` (accessor), `2217-2233` (`CompatibilityThreadWaiter`), `8044-8137` (`VcpuThreadHandle::Job`)

**Interfaces:**
- Consumes: Task 2's deletions.
- Produces: one fewer host pthread per run; `VcpuThreadHandle` reduced to two variants.

- [ ] **Step 1: Confirm the pool has no work path**

```bash
grep -n "transitional_runner" crates/carrick-runtime/src/vcpu_loop/mod.rs
```

Expected: only the field, the accessor, and the (now-deleted) read at the old `mod.rs:8293`.

- [ ] **Step 2: Delete the `Transitional*` symbols**

Delete `TransitionalWorkerKick`, `TransitionalWorkerContext`, `RunnerWork`, `TransitionalRunnerPool`, `TransitionalDedicatedRunner`, `TransitionalRunnerError`, the `transitional_runner` field and accessor, and the test block exercising them.

**Do NOT delete** `LogicalJobCompletion`, `LogicalTaskReceipt` or `RunnerTask` — they are shared with the persistent path (`VcpuThreadHandle::Persistent` uses `terminal_settlement.completion()`).

- [ ] **Step 3: Delete `CompatibilityThreadWaiter` and `VcpuThreadHandle::Job`**

Remove the enum, the `waiter` field on `ThreadRuntimeState`, and collapse the three-armed matches in `is_finished`/`join`/`completion`/`finish_completed` to two. Keep `io_wait::ThreadWaiter` — it has live consumers at `runtime.rs:1020`, `1325`, `1723`.

- [ ] **Step 4: Verify**

```bash
cargo check -p carrick-runtime --lib --tests
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib 2>&1 | tail -3
just build -p carrick-cli
```

Re-run the Task 0 shape table; shapes must be identical. Additionally confirm the idle thread is gone:

```bash
RID=t3-threads; CARRICK_RUN_ID=$RID timeout 20 ./target/release/carrick run-elf --raw \
  --exec-backend hvpatch fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello \
  >/dev/null 2>&1; ./scripts/sudo/kill.sh $RID >/dev/null 2>&1
```

- [ ] **Step 5: Commit**

```bash
just fmt && git add -u crates/
git commit -m "refactor(runtime): delete the transitional dedicated runner"
```

### Task 4: Collapse the non-persistent branch arms in the HVF trap engine

**Files:**
- Modify: `crates/carrick-vmm-hvf/src/trap.rs` — 18 negated guards including `9603`, `9713`, `10404`, `10622`, `11136`, `13772`, `13937`, `13945`, `14145`, `14169`, `7580`, `7655`, `5776`; the field itself; the constructor defaults at `4890` and `9839`
- Modify: `crates/carrick-hal/src/threaded.rs:1448`, `crates/carrick-aarch64/src/vmm.rs:363`, `crates/carrick-aarch64/src/engine.rs:2538`, `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:996` (`set_persistent_vm_lifecycle`)

**Interfaces:**
- Consumes: Task 1 (the sole production setter is gone).
- Produces: `sparse_mmap_arena_enabled()` becomes unconditionally true.

- [ ] **Step 1: Confirm every negated arm is test-only**

```bash
grep -c "persistent_vm_lifecycle" crates/carrick-vmm-hvf/src/trap.rs
grep -n "!self.persistent_vm_lifecycle\|!state.persistent_vm_lifecycle\|persistent_vm_lifecycle: false" crates/carrick-vmm-hvf/src/trap.rs
```

Note `4890` and `9839` initialize the field to the DEAD value — that inversion is itself a hazard and disappears with the field.

- [ ] **Step 2: Delete the field and collapse each arm to the persistent branch**

Update the HVF unit tests that construct with `false` to the persistent shape.

- [ ] **Step 3: Verify**

```bash
cargo check -p carrick-vmm-hvf --lib --tests
RUST_TEST_THREADS=1 cargo test -p carrick-vmm-hvf --lib 2>&1 | tail -3
just build -p carrick-cli
```

Re-run the Task 0 shape table; shapes must be identical.

- [ ] **Step 4: Run the full gate and compare to baseline**

```bash
RUST_TEST_THREADS=1 just ci > target/perf/ci-phase1.log 2>&1
echo "JUST_CI_EXIT=$?"; tail -5 target/perf/ci-phase1.log
```

Expected: no WORSE than `target/perf/ci-baseline.log`.

- [ ] **Step 5: Commit**

```bash
just fmt && git add -u crates/
git commit -m "refactor(hvf): collapse the non-persistent vm lifecycle arms"
```

---

## Phase 2 — Sweep (FAN OUT — one agent per task, each in its own worktree)

Every Phase 2 task is verified by `cargo check` + `just fmt-check` ONLY. No task in this phase may run a guest.

### Task 5: Retire the stale dead-code markers

**Files:**
- Modify: `crates/carrick-runtime/src/namespace/pid.rs:19` (whole module), `crates/carrick-runtime/src/dispatch/net/unix_pure.rs:10` and `network/mod.rs:340,408,423`, `dispatch/fd_table.rs:584-701,1334-1375`, `dispatch/ioring.rs:19,693,710`, `dispatch/time.rs:136,1102,1107`, `dispatch/mem.rs:1760,1770,1778`, `dispatch/sysv.rs:786,2184`, `dispatch/mount_api.rs:143,146`, `seccomp.rs:311,347`, `dispatch/fs/pipe.rs:85,133`, `fs_backend.rs:3699`, `dispatch/fs.rs:696`, `dispatch/mod.rs:5364,4225`, `dispatch/fs/state.rs:32`, `exec_stamps.rs:228`, `bpf.rs:256,258`, `mqueue.rs:52`, `vcpu_loop/continuation.rs:363,365`, `carrick-vmm-hvf/src/trap.rs:6736`

**Interfaces:**
- Consumes: nothing.
- Produces: no public API change.

- [ ] **Step 1: For each marker, classify by grep**

```bash
grep -rn "allow(dead_code)" --include='*.rs' crates/carrick-runtime/src crates/carrick-vmm-hvf/src | wc -l
```

For each item, count non-definition references. Zero references outside tests ⇒ delete the CODE. Non-zero production references ⇒ delete only the MARKER.

- [ ] **Step 2: Keep these — they are correct, non-promissory**

`carrick-vmm-hvf/src/trap.rs:5215,5217` (RAII holders kept for `Drop` side effects) and `dispatch/mod.rs:735,780` (`WaitFdGuard`). Also keep `fd_table.rs:1367 reexec_kind_name` (live at `net.rs:6462`, `fs.rs:4569`) and `time.rs:144 rlimit_cpu_after_fork_child`.

- [ ] **Step 3: Verify and commit**

```bash
cargo check --workspace --all-targets && just fmt-check
git commit -am "refactor: retire stale dead-code markers"
```

### Task 6: Delete the retired `--native-page-profile` surface

**Files:**
- Modify: `crates/carrick-cli/src/args.rs:227,413,532`
- Modify: `crates/carrick-spec/src/lib.rs:296-305`
- Modify: `crates/carrick-runtime/src/page_profile.rs:82-86`
- Modify: `crates/carrick-cli/tests/cli.rs:139`, `tests/dsr_trace_overhead.rs:733-784`, `tests/perf_runner.rs:136`, `tests/perf_support/invoke.rs:168`

**Interfaces:**
- Consumes: nothing.
- Produces: `ExecutionPlan.page_geometry` becomes a constant.

- [ ] **Step 1: Confirm the flag only produces an error**

```bash
sed -n '82,86p' crates/carrick-runtime/src/page_profile.rs
```

Expected: "native page profile is not supported (native backend retired)".

- [ ] **Step 2: Delete `NativePageProfileRequest`, the three `#[arg]`s, the `RunSpec` field, and the rejection branch. Update the four test call sites.**

- [ ] **Step 3: Verify and commit**

```bash
cargo check --workspace --all-targets && just fmt-check
git commit -am "refactor(cli): delete the retired native-page-profile flag"
```

### Task 7: Correct the script and doc recipes that invoke retired backends

**Files:**
- Modify headers only: `scripts/dtrace/native-cpu-attribution.d:37`, `guest-translation-census.d:32`, `native-exec-close-attribution.d:70-73`, `guest-mmap-shape.d:31`, `guest-process-census.d:28`, `native-condvar-reasons.d:25`, `native-translated-range-catalog.d:21`, `exec-window-syscall-latency.d:38`
- Modify: `scripts/test-native-x86-child-proctitle.sh:22-24`, `scripts/perf/workload-spread.sh:56,68`, `scripts/perf/container-lifecycle-split.sh:37`
- Modify: `docs/architecture-overview.md`, `docs/diagnostics-and-debugging.md`, `docs/dynamic-syscall-rewriter.md`, `docs/native-dsr-*.md`, `docs/native-x86-conformance-plan.md`

**Interfaces:**
- Consumes: nothing. Produces: no code change.

- [ ] **Step 1: Correct each recipe to the surviving invocation**

`.d` scripts are DURABLE ARTIFACTS — correct the header recipe, never delete the script. Leave `docs/perf-results/*` alone; they are historical receipts.

- [ ] **Step 2: Verify no remaining live recipe hard-errors**

```bash
grep -rn -- "--exec-backend native" scripts/ docs/ | grep -v "docs/perf-results/"
```

Expected: empty.

- [ ] **Step 3: Commit**

```bash
git commit -am "docs: correct recipes naming the retired native backend"
```

### Task 8: Wire in or delete the never-run `carrick-cli` suites

**Files:**
- Modify: `justfile:236` (`test-integration`)
- Modify or delete: `crates/carrick-cli/tests/{cli,fs_backend_flag,linux_fixture,nested_pipe,serve}.rs`

**Interfaces:**
- Consumes: Task 6 (those suites pass the deleted flag).
- Produces: either gate coverage or fewer files.

- [ ] **Step 1: Confirm which suites no gate runs**

```bash
sed -n '230,240p' justfile
```

`just test` runs `-p carrick-cli --bin carrick`; `test-integration` runs only `--test trace_profile`.

- [ ] **Step 2: For each suite, either add it to `test-integration` or delete it.** A suite that needs a guest or Docker must NOT be added — say so in the commit body and delete it instead.

- [ ] **Step 3: Verify and commit**

```bash
just test-integration > /tmp/t8.log 2>&1; echo "exit=$?"; tail -5 /tmp/t8.log
git commit -am "test(cli): gate or delete the unrun integration suites"
```

---

## Phase 3 — Fix and verify (SERIALIZED — one lane, no parallel guests)

### Task 9: Make a forked child's terminal run

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs:3148-3257` (terminal retirement block)
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:3183-3322` (`finalize_persistent_process_terminal`)
- Test: `crates/carrick-runtime/src/vcpu_loop/executor.rs` unit tests

**Interfaces:**
- Consumes: the authority transition wired in `d0ed04105` (`retire_detached_address_space_with`), currently unexercised.
- Produces: a forked child whose MM authority reaches `Retired`.

- [ ] **Step 1: Reproduce red and capture the ordering signal**

```bash
RID=t9-red; CARRICK_RUN_ID=$RID timeout 20 ./target/release/carrick run-elf --raw \
  --exec-backend hvpatch conformance-probes/target/aarch64-unknown-linux-musl/release/forkcow \
  >/tmp/$RID.out 2>/tmp/$RID.err; echo "exit=$?"; tail -3 /tmp/$RID.err
./scripts/sudo/kill.sh $RID >/dev/null 2>&1
```

Expected red: exit 134, `drop HVPatch MM authority (phase=active …)`, preceded by `authoritative scheduler wake rejected parent=… invalid from Exited`.

- [ ] **Step 2: Determine why the child's terminal does not run**

The child never reaches `retire_detached_address_space_with`. Establish which of these holds, with evidence, before changing code:
(a) `finalize_persistent_process_terminal` is never entered for the child;
(b) it is entered but `owns_final_mm_edge` returns false, so `extent_count` is forced to 0 and no retirement is armed;
(c) it is entered and armed, but `take_address_space_retirement()` returns `None` at the executor terminal;
(d) `retirement.retirement()` is `None`, so the code takes `retire_detached_shared_mm_edge()` — which does NOT drive the authority.

Use `carrick debug lldb-run` or a named fail-closed error, not `eprintln!`. The parent-already-`Exited` signal suggests the child's exit is being processed after the parent's, which points at (a) or (c).

- [ ] **Step 3: Write the failing unit test at the seam that broke**

Not at the symptom. Follow the pattern of `validate_cow_authority_pairing`: assert the invariant the production path violated.

- [ ] **Step 4: Run it and watch it fail**

```bash
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib <test_name> 2>&1 | tail -5
```

- [ ] **Step 5: Fix the root cause, rebuild, verify green**

```bash
just build -p carrick-cli
P=conformance-probes/target/aarch64-unknown-linux-musl/release
for p in clonebasic forkcow forkfiletable forkshared waitexitstorm waitidsiuid \
         mqnotifycrossproc futexpingpong cloneexitsig sigchld xsignal \
         forkexecpthread execpipe clone3args cloneexithandled; do
  RID="t9-$p"; CARRICK_RUN_ID=$RID timeout 20 ./target/release/carrick run-elf --raw \
    --exec-backend hvpatch $P/$p >/tmp/$RID.out 2>/tmp/$RID.err
  printf '%-20s exit=%-4s lines=%s\n' "$p" "$?" "$(wc -l </tmp/$RID.out | tr -d ' ')"
  ./scripts/sudo/kill.sh $RID >/dev/null 2>&1
done
```

Expected: exit 0 with non-zero output lines for all 15.

- [ ] **Step 6: Commit**

```bash
just fmt && git add -u crates/
git commit -m "fix(hvpatch): run a forked child's terminal to completion"
```

### Task 10: Close both vfork+exec shutdown shapes

**Files:**
- Modify: `crates/carrick-runtime/src/vcpu_loop/executor.rs:2458-2500` (`shutdown`, `cancel_dormant`)
- Modify: `crates/carrick-aarch64/src/engine.rs:1047-1086` (`invalidate_asid_on_vcpu`)

**Interfaces:**
- Consumes: Task 9.
- Produces: the `/bin/sh -c` reducer exits 0.

- [ ] **Step 1: Reproduce both shapes and get their frequency**

```bash
for i in 1 2 3 4 5 6; do
  RID=t10-$i; CARRICK_RUN_ID=$RID timeout 25 ./target/release/carrick run ubuntu:24.04 \
    --raw --fs host /bin/sh -c '/bin/echo hi' >/tmp/$RID.out 2>/tmp/$RID.err
  rc=$?
  if grep -qa "cancel dormant binding" /tmp/$RID.err; then s=STALE_BINDING
  elif grep -qa "ASID maintenance" /tmp/$RID.err; then s=ASID_EL0FAULT
  elif [ -s /tmp/$RID.err ]; then s="OTHER"; else s=clean; fi
  echo "run$i exit=$rc out=[$(cat /tmp/$RID.out)] $s"
  ./scripts/sudo/kill.sh $RID >/dev/null 2>&1
done
```

Baseline observed 2026-08-22: 4/6 `STALE_BINDING`, 2/6 `ASID_EL0FAULT`, 6/6 correct stdout, 6/6 exit 125.

- [ ] **Step 2: Fix the stale dormant binding**

`cancel_dormant` (`executor.rs:1327`) treats `SchedulerError::UnknownThread` as fatal. The binding's Thread was already removed from the kernel graph by the parent's reap while the binding entry survived. Decide with evidence whether the correct invariant is (a) reaping must retire the binding, or (b) an absent Thread at shutdown is a normal terminal state. Do not simply swallow the error.

- [ ] **Step 3: Fix the EL0Fault in scoped ASID maintenance**

`invalidate_asid_on_vcpu` sets PC to `HVPATCH_EL1_ASID_MAINT_BASE` at EL1H and got an EL0 fault, meaning the executor's loaded stage-1 root does not map the maintenance trampoline. Establish which executor/root pairing is live at shutdown before changing the arming order.

- [ ] **Step 4: Verify 10/10 clean**

Re-run Step 1 with ten iterations. Require exit 0 and `hi` on stdout every time, with `/bin/bash -c` still clean as the control.

- [ ] **Step 5: Commit**

```bash
just fmt && git add -u crates/
git commit -m "fix(hvpatch): close the vfork+exec pool shutdown races"
```

### Task 11: Reconcile the host-authority census

**Files:**
- Modify: `scripts/migrate/host-authority-transition-inventory.json`

**Interfaces:**
- Consumes: Phase 1 (deleting the transitional runner removes at least one host-thread use).
- Produces: `just lint-domains` green.

- [ ] **Step 1: Re-run the census AFTER deletion**

```bash
python3 scripts/migrate/check-host-authority-transitions.py --refresh-candidate /tmp/authority-candidate.json > /tmp/authority.log 2>&1
```

- [ ] **Step 2: Compare position-insensitively to separate churn from substance**

```bash
python3 - <<'PY'
import json, collections
cand = json.load(open('/tmp/authority-candidate.json'))
inv  = json.load(open('scripts/migrate/host-authority-transition-inventory.json'))
rows = cand.get('rows', cand)
key = lambda r: ((r.get('source') or {}).get('file'), r.get('catalog_id'), r.get('operation'))
ck, ik = collections.Counter(map(key, rows)), collections.Counter(map(key, inv))
print("only in candidate:", sum((ck-ik).values()))
for k, c in (ck-ik).items(): print("   +", c, k)
print("only in inventory:", sum((ik-ck).values()))
for k, c in (ik-ck).items(): print("   -", c, k)
PY
```

Baseline before deletion: 4 new (`Builder::new` ×2 in `continuation.rs`, `Builder::new` + `yield_now` in `executor.rs`), 8 gone.

- [ ] **Step 3: Classify only what survives**

For each surviving new row, either eliminate the call or give it a real classification (`forbidden_semantic` / `declared_backing` / `declared_substrate`). Task 7 Step 1 of the kernel-mn-executors plan forbids HVPatch reaching `std::thread::spawn`/`Builder::spawn`, so prefer elimination. **Never bulk re-bless.**

- [ ] **Step 4: Verify and commit**

```bash
just lint-domains && git commit -am "build: reconcile the host-authority census after deletion"
```

### Task 12: Close the goal on one signed artifact

**Files:**
- Create: `docs/perf-results/2026-08-22-fork-closure-receipt.md`
- Modify: `handoff.md`

**Interfaces:**
- Consumes: Tasks 0-11.
- Produces: the goal's completion evidence.

- [ ] **Step 1: Build and record the exact artifact**

```bash
git status --porcelain | wc -l   # MUST be 0
just build -p carrick-cli
BIN=target/release/carrick
echo "HEAD: $(git rev-parse HEAD)"; shasum -a 256 $BIN
codesign -dvvv --entitlements :- $BIN 2>&1 | grep -E "Identifier=|CDHash=|hypervisor"
otool -l $BIN | grep -A2 LC_UUID | grep uuid
otool -l $BIN | grep -c __dof_carrick
```

- [ ] **Step 2: Run `just ci` and read the status from a FILE**

```bash
RUST_TEST_THREADS=1 just ci > target/perf/ci-final.log 2>&1
echo "JUST_CI_EXIT=$?"
```

Required: `JUST_CI_EXIT=0`.

- [ ] **Step 3: Run the probe gate in CLOSURE mode**

```bash
just conformance-probes-closure > target/perf/probes-closure.log 2>&1
echo "CLOSURE_EXIT=$?"
grep -ac "SKIP" target/perf/probes-closure.log
```

Required: exit 0 and zero skips. Ordinary probe mode is NOT acceptable as the closing gate.

- [ ] **Step 4: Re-run both reducers and the fork battery on the final artifact**

Required: `/bin/sh -c` exits 0; all 15 fork probes exit 0 with output.

- [ ] **Step 5: Prove scoped cleanup**

```bash
ps -eo pid,args | grep -i carrick | grep -v grep | grep -v com.docker
```

Required: empty.

- [ ] **Step 6: Write the receipt, update `handoff.md`, commit**

```bash
git add docs/perf-results/2026-08-22-fork-closure-receipt.md handoff.md
git commit -m "docs: close the HVPatch fork lifecycle goal"
```

---

## Execution record — Phase 1 (appended during execution, 2026-08-22)

The plan is the controller, so where execution contradicted it the contradiction
is recorded here rather than silently absorbed. Phase 1 was written as a pure
deletion; it was not. Collapsing `ExecutionBackend` turned unreachable branches
into build failures exactly as intended, and three of those failures were live
responsibilities, not redundancy.

### Corrections to the task lists

- **Task 2 Step 3 is wrong to delete `prepare_initial_runner_handoff`.** It and
  `PreparedInitialRunnerTask` / `PreparedInitialHandoff` /
  `InitialRunnerStartGate` are called by `launch_persistent_hvpatch_job` to
  publish the initial task state and claim its start gate. They were deleted,
  the compiler rejected the tree, and they were restored. The gate that used to
  bound the launch entry between `launch_vcpu_until_exit` and
  `PreparedInitialRunnerTask` now asserts the first is ABSENT and the second is
  PRESENT.
- **Task 3's "Do NOT delete `RunnerTask`" is inverted.** `RunnerTask` is
  constructed only inside `TransitionalDedicatedRunner::try_spawn_dormant` and
  polled only by the pool worker, so it dies with the pool. `LogicalJobCompletion`
  is the symbol that must survive — `executor.rs` builds one with
  `LogicalJobCompletion::pending()` in five places.
- **The pool's ambient state was already inert.** `CURRENT_RUNNER_JOB` and
  `CURRENT_RUNNER_WORKER` are written only inside the transitional pool's worker
  loop. The persistent executor registers its own `ExecutorRegistration` through
  `scheduler.register_executor` and never publishes those thread-locals, so
  `current_job()`, `current_executor_registration()` and
  `publish_current_hardware_kick()` already answered `None`/`false` on the only
  live path. Every read site must therefore collapse to its `None`/`false`
  branch, not merely lose the symbol.

### The live responsibility Phase 1 exposed: guest fault delivery

`launch_vcpu_until_exit` returned unconditionally at its first statement, so
`run_vcpu_until_exit_inner` never ran — and it was the ONLY implementation of:

- synchronous EL0 fault classification (`lower_el0_fault`) and delivery of
  SIGSEGV / SIGBUS / SIGTRAP to the guest via `deliver_fault_signal`;
- lazy stack growdown (`mmap_growdown_fault_plan` / `commit_mmap_growdown`) and
  resident fault commit (`resident_fault_plan` / `commit_resident_fault`);
- `Stage1CowFault` resolution at the guest boundary;
- forced-exit signal service (`next_syscall()` returning `Ok(None)`);
- the unclassified-fault SIGSEGV default action.

The persistent poll turned every one of these into `RuntimeError::Trap` and
killed the process. Proven red first on the pre-change signed binary:

    carrick run-elf --raw --exec-backend hvpatch .../faultaddr
    -> exit 1, no guest output,
       "trap engine failed: EL0 fault not handled by trap path: esr=0x92000007"

This was already true at HEAD; the deletion did not cause it, it revealed it.
Per Task 1 Step 3's own rule the responsibility was ported into
`ProductionHvpatchLoopJob::poll_with_engine` before the deletion continued, with
`ExecutorExit::Syscall` standing in for the welded loop's `continue` and a new
`enter_terminal_with_outcome` routing a fatal outcome into the persistent
terminal. After the port, on a freshly signed binary:

    faultaddr      -> exit 0, "si_addr_match=true fault_addr_match=true DONE"
    recursionguard -> now also reports "deep_c_recursion_fits=true"

### Baseline shape table: one legitimate change

Phase 1 deletion left all 22 fork-battery shapes byte-identical. The fault port
then changed exactly one: `clonebasic` goes from 0 to 1 stdout lines, because it
now gets further before hitting the Phase 3 teardown defect. That is progress,
not drift, and every other row is unchanged.

### The compatibility wait arms went with the loop

`service_threaded_syscall` escapes every blocking outcome to the executor's
continuation BEFORE its `match`, and `is_blocking_dispatch_outcome` covers
exactly the eleven arms that followed. Those 866 lines were unreachable and are
replaced by one arm that fails closed if the escape and the classifier ever
drift apart. `CompatibilityThreadWaiter` and the per-syscall parked-slice /
sleep-deadline / poll-deadline state went with them.

### Gates: `just test` had never run

`just ci` is sequential and has been dying at clippy — and since `4acd8cc9f` at
`lint-domains` — so `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib`
had not executed in a long time and was RED with five failures on unmodified
HEAD `862bcb9af` (verified in a separate worktree). A stale
`threaded_independent_dispatch_supports` expectation and four cross-process
signal tests order-dependent on the never-cleared carrier-global `HVPATCH_LANE`.
Both repaired; the suite is green for the first time.

### Task 7 was done in the primary tree, not a worktree

The dispatched worktree was created 1,884 commits behind `main`, predating
HVPatch entirely, so its result was not mergeable. Task 7 was redone in place.
Treat `isolation: worktree` in this repo as requiring an explicit base check.

---

## Self-Review

**Spec coverage.** Goal criterion 1 → Tasks 1-4; criterion 2 → Task 9; criterion 3 → Task 10; criterion 4 → Tasks 11, 12 Step 2; criterion 5 → Task 12 Step 3. Phase 2 sweep → Tasks 5-8. Out-of-scope items appear in no task. Baseline → Task 0.

**Placeholders.** None: every step carries an exact command or an exact edit target. Task 9 Step 2 and Task 10 Steps 2-3 deliberately state the hypotheses to discriminate rather than prescribing a fix, because the root cause is not yet established — the plan requires evidence first, which is the systematic-debugging contract, not a placeholder.

**Type consistency.** `retire_detached_address_space_with`, `apply_detached_address_space_retirement_with_receipt`, `validate_cow_authority_pairing`, `carrier_stage2_leases` and `exec_retires_old_mm` are named consistently with the code landed in `f96aabdd4`, `8709213ce`, `84e385655` and `d0ed04105`.
