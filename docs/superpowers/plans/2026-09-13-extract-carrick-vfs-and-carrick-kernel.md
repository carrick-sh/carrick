# Extract `carrick-vfs` and `carrick-kernel` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `carrick-runtime` (377k lines, one crate) along its existing architectural layers into `carrick-vfs` (filesystem model and backends), `carrick-kernel` (the Carrick kernel: kernel graph + syscall dispatch + every in-zone subsystem, a **public bring-your-own-execution-backend crate**) and a slimmed `carrick-runtime` (the HVPatch carrier), with a machine-checked rule that no lower layer names a VMM type and an in-tree example backend that proves the public surface without a VM.

**Architecture:** Bottom-up, cycle-first. Every extraction is preceded by tasks that cut the measured back-edges (lower module naming a higher one) so the eventual `git mv` is a rename with no semantic change. The execution seam is the one that already exists and already has three non-HVF implementations (KVM, bhyve, NVMM): `carrick-hal` traits implemented by the carrier and injected at construction. Three traits are added to that family for the leaks dispatch has today (`Stage1MmProjection`, `HostSignalBridge`, `GuestTimerBridge`). There is no new "transport" or "authority" trait; the kernel graph stays the single authority for process identity, waits and cross-process signals, exactly as AGENTS.md rules.

**Tech Stack:** Rust workspace (`crates/*`, edition 2024, `-D warnings`), `cargo tree` layering assertions, the `just` gate ladder, the Python line-pinned inventory reconciler under `scripts/migrate/`.

**Spec:** the proposal the owner supplied on 2026-09-13 ("Decouple Emulation Logic: `carrick-vfs`, `carrick-dispatch`, and Pluggable Execution Seams"), as corrected by the vetting section below and fixed by the owner's scope decisions of the same day (next section). Where this plan and the proposal disagree, the vetting table states the measured fact and the disposition; the plan follows the fact.

---

## Scope decisions (owner, 2026-09-13)

| Question | Decision | Effect on the plan |
|---|---|---|
| Primary outcome | **Public reuse**: an external project implements the execution seam and drives the kernel crate itself. | The kernel crate's `pub` surface is a deliverable: README, crate docs, and an in-tree example backend that uses only `pub` items (Task 2.12). |
| First consumer shape | **Bring-your-own execution backend**: implements the hal traits and interprets `DispatchOutcome` itself. | Public surface = `SyscallDispatcher` + `SyscallRequest` + `DispatchOutcome` (every variant documented) + kernel bootstrap/fork/wait operations + `GuestMemory`/`CurrentMmMemory` + the three hal bridges. |
| Proof of the surface | **In-tree example crate** `crates/carrick-kernel-example`, workspace member, compiled by `just check`, run by `just test`; fork + pipe + wait with no VM. | Task 2.12. Replaces the proposal's Phase 6 runner honestly: it drives the dispatcher, it does not `fork(2)` host processes. |
| Crate names | New kernel crate is **`carrick-kernel`**; today's `carrick-kernel` (the shared-memory arena) becomes **`carrick-kernel-arena`**, renamed **first**. | Task 0.0. Every later import is written once with final names. |
| Scope | **Both phases plus Task 0.3** (delete the retired native lane's `cfg(test)` bodies). | As written. |
| Phase acceptance | **`just ci` + full `just conformance` + `just conformance-probes` + `just test-embed`**, signed two-process smoke, layering gate, binary identity recorded. | Tasks 1.5 and 2.13. |
| Stability | **Experimental, no semver**: `publish = false` stays; README says the API changes without notice; consumers pin a git rev. | Task 2.12 README text. No CHANGELOG, no crates.io tasks. |

---

## Vetting: what the proposal got right, what the tree says, and what this plan does

Every count below is a grep on `main` at `acbddc406` (2026-09-15; rebased from the 2026-09-13 measurement at `7a3818034`, 82 commits earlier — the shape did not move, the numbers did). Re-run the commands in the tasks before starting; the numbers drift, the shape does not.

| Proposal claim | Measured fact | Disposition |
|---|---|---|
| `carrick-dispatch` = "move `crates/carrick-runtime/src/dispatch/`" with deps `abi, hal, guest-mem, vfs, signal-core, timer-core, thread, host, mem, observability`. | `dispatch/` is **147,793 lines** and names `crate::kernel` **1,467** times (the 60k-line in-carrier kernel graph, not the 1.3k-line shared-memory arena crate). It also names 45 other runtime modules (`namespace` 180, `event_ring` 116, `network` 85, `observe` 74, `hvpatch` 59, `file_authority` 56, `host_signal` 51, …). | The kernel graph and every in-zone subsystem move **with** dispatch. The crate is `carrick-kernel`, and `crates/README.md` says so. |
| `KernelAuthority` trait (10 methods) lets dispatch borrow `&dyn KernelAuthority` instead of `KernelContext`. | Dispatch uses concrete kernel types everywhere: `TaskKey`, `ExactSignalTargetAuthorization`, `ClonePlan`, `WaitResult`, `LinuxSignal`, `Kernel::authorize_*`. A 10-method trait cannot carry 1,467 sites, and would be a second description of the same state. | **Dropped.** Kernel graph and dispatch share a crate; no abstraction between them. |
| `kill(2)` "hardcodes `DispatchOutcome::errno(LINUX_ESRCH)`" and needs a `SignalTransport` seam. | `dispatch/signal.rs:1380-1560` (`authorize_namespace_process_group_signal_targets_exact` at 1391, `hvpatch_exact_process_signal` at 1480): `kill` resolves targets through `Kernel::authorize_namespace_process_group_signal_targets_exact` / `authorize_signal_target_exact` and delivers through `post_signal_to_authorized_target`; `ESRCH` is the `Missing` arm of a typed authorization. The kernel graph **is** the cross-process signal authority. | **Dropped** (`SignalTransport`, `InCarrierSignalTransport`, `HostProcessSignalTransport`, `MockSignalTransport`). A transport trait beside the kernel graph violates "Authority follows the execution lane" and "no second path". An external backend that wants signals across **its** process boundary implements `HostSignalBridge` (Task 2.5). |
| `wait4`/`waitid`/`set_tid_address` have "HVPatch-only dead ends" at `#[cfg(not(test))] return ENOSYS` that a 1:1 runner should fall through. | `proc.rs:3085,3520,3998,4741` gate the **retired 1:1 native lane's host-pid code** (`libc::waitid`, host `kill`) behind `#[cfg(test)]`. Retired in `e1fbfd32e`; survives only for tests of the retired lane. | Un-gating it re-ships the retired lane. **Task 0.3 deletes it** (git remembers). |
| `carrick-vfs` deps: `carrick-abi, carrick-spec, camino, cap-std, parking_lot, thiserror`; contents include `InMemoryFileVfs`, `LayeredVfs`, `FilterVfs`, `RecordingVfs`, `ProcVfs`, `SysVfs`, `DevVfs`, `DevPts`. | `cap-std` has **zero** manifest references (retired; owner ruling 2026-09-05). `InMemoryFileVfs`/`LayeredVfs`/`FilterVfs`/`RecordingVfs` do not exist. `vfs/proc.rs` (6,397 lines) has **85** edges into `kernel`/`namespace`/`network`; `vfs/sys.rs` has 11. Procfs and sysfs are views **of** the kernel graph and cannot live below it. | `carrick-vfs` holds the `Vfs` trait, mounts, dentry cache, backends and rootfs (Phase 1). `ProcVfs`, `SysVfs`, `DevVfs`, `DevptsVfs` stay with the kernel and move in Phase 2. No `cap-std`. |
| `Stage1Authority: Send + Sync` trait replaces `Arc<crate::hvpatch::Stage1MmLease>` in `mm_mutation.rs`/`mm_authority.rs`. | Correct: three sites (`mm_authority.rs:180`, `mm_mutation.rs:212,222`) plus `vcpu_loop::quiesce::{SoleMmStage, PtPauseGuard, FrameCowExactMmGuard}`, `with_sole_mm_stage`, `stamp_identity_page` are the real VM seam inside dispatch. | **Kept**, as a `carrick-hal` trait (Tasks 2.3/2.4). `Stage1Authority` already names the owning type in the runtime; the trait is `Stage1MmProjection`. |
| `ExecBackendRequest` gains `HostProcess` / `Extensible(String)`. | `carrick-spec/src/lib.rs:268` is `HvPatch` only; `parse_value` rejects `native`/`vmm`/`hvf` with "backends were retired". | **Dropped.** A variant no backend implements is a dark launch. An external backend is not selected by the CLI; it constructs the kernel itself. |
| Phase 6: `crates/carrick-dispatch/tests/reference_1to1_runner.rs` runs a real ELF with OS `fork()`/`waitpid`. | That is the retired native lane rebuilt inside a test target no gate runs. The alternate-backend proof that exists is `carrick-kvm`/`carrick-nvmm` running the full dispatcher off-macOS through `carrick-hal`. `carrick debug dispatch-syscall` (`carrick-cli/src/commands.rs:735-770`) already drives the dispatcher with a `LinearMemory` and `capture_one_task_context()` and no VM. | **Replaced** by `carrick-kernel-example` (Task 2.12): the same no-VM shape as `dispatch-syscall`, extended to multiple scripted tasks with fork, pipe and wait, using only `pub` items. Plus the VMM-less cross-compile in `ci` (Task 2.10). |
| Zero regressions on HVPatch; no re-export shims; consumers import the new crates directly. | Consumers today: `carrick-cli` (`fs_setup.rs`, `commands.rs`), `carrick-embed` (`lib.rs`, `error.rs`, `builder.rs`, `vfs.rs`), `carrick-host/src/host_proc.rs` (doc link). Embed imports `carrick_runtime::{container, kernel::control, observe, network::interposer, kernel::TimeControl, kernel::LaunchContext, carrier, Runtime, runtime::RuntimeError, trap::TrapError, host_process, dtrace_consumer}`. | **Kept.** Tasks 1.4 and 2.9 re-point every import; `carrick-runtime` re-exports nothing it no longer owns. |
| Build-time motivation. | `docs/archive/build-decomposition-design.md` mapped this split (A4 `carrick-dispatch`) on 2026-05-26 and stopped at "must be checked for dispatch↔runtime/thread cycles before lifting". | This plan is A4, executed; the cycles are inventoried below. Build time is measured single-variable in Task 2.13, not asserted. |

### Cycles that must be cut before any `git mv` (measured)

| Edge (lower → higher) | Count | Items | Cut in |
|---|---|---|---|
| `vfs/rootfs.rs` → `dispatch` | 9 | `rootfs_errno` ×5 (L1145-1469), `HostSyscallResult` ×4 (L508-705) | Task 1.1 |
| `fs_backend` → `dispatch` | 1 | `HostSyscallResult` | Task 1.1 |
| `vfs/{dev,devpts}` → `kernel::tty` | 4 | `tty::detach` ×2, `TtyKey::Pty` ×2 | Task 1.2 (dev/devpts stay with the kernel) |
| `vfs/mod.rs` → `namespace::process`, `network::model` | 4 | `OpenContext` lazy fields `creds_ns: LazyField<Option<ProcessCredsNs>>` (L728, L791) and `network_model: LazyField<Option<LinuxNetworkModel>>` (L724, L767) | Task 1.3 |
| `kernel` → `vcpu_loop` | 62 | `continuation::{CancellationCause, BlockedContinuation, ContinuationEvent, ContinuationRegistration, ContinuationId, ContinuationDiagnostic, CancellationReceipt}`, `KernelForeignCowProof`, 7 `*_for_test` helpers | Task 2.2 |
| `kernel` → `hvpatch` | 7 | `Stage` ×4, `ForeignMmInstallPermit` ×2, `identity_operation_errno` ×1 | Task 2.1 |
| `dispatch` → `hvpatch` | 59 | `process_context_for_tests` ×26 and `ProcessContext` ×14 (carrier handle → Task 2.15 `CarrierProcess` trait), `WaitResult` ×9, `ProcessThreadExit` ×3, `identity_operation_errno` ×2, `ChildExit` ×1 (Task 2.1); `Stage` ×4 was a census prefix match on `Stage1MmLease` (5 sites, Task 2.3) | Tasks 2.1, 2.15, 2.3 |
| `dispatch` → `vcpu_loop` | 17 | `with_sole_mm_stage` ×4, `stamp_identity_page` ×2, `quiesce::FrameCowExactMmGuard` ×2, `ns_visible_guest_tid` ×2, `is_default_ignore_signal` ×2, `with_foreign_mm_mutation_guard`, `upgrade_protection_si_code`, `quiesce::SoleMmStage`, `quiesce::PtPauseGuard`, `with_real_pt_pause_for_test` | Task 2.4 |
| `dispatch` → `trap::HVF_PAGE_SIZE` | 37 | one constant | Task 2.6 |
| `dispatch` → `host_signal` / `itimer` / `posix_timer` / `io_wait` / `timer_delivery` (macOS arm re-exports **`carrick_vmm_hvf`**) | 51 + 8 + 10 + 2 + 2 | full item list in Task 2.5 | Task 2.5 |
| `kernel/mm_access.rs` tests → `carrick_vmm_hvf::trap::foreign_cow_test_support` | 9 (L2622-3255, all `#[cfg(test)]`) | `ProductionCarrierForeignCowHarness`, `TEST_VA` | Task 2.2 (tests move to the carrier) |
| `kernel` → `container` / `carrier` / `pty_relay` | 40 / 4 / 5 | `ContainerState`, `ContainerStatus`, `CarrierControlState`, `is_safe_id`, `mark_control_owner_exited`, `RunConfig`; `carrier::ContainerTeardown`; `pty_relay::PtyPair` | Task 2.7 |
| `kernel` → `dispatch` | 87 | `MmMutationGuard`, `IoUring*`, `ArchiveFs*`, `SyscallDispatcher::new`, … | **Not cut**: kernel and dispatch land in the same crate. This is why they are extracted together. |

Everything else dispatch names outside `dispatch/` is already a leaf crate re-exported under a `crate::` alias (`linux_abi`=`carrick-abi`, `memory`/`shared_aperture`/`vdso`=`carrick-mem`, `thread`/`fork_quiesce`=`carrick-thread`, `guest_cpu`/`host_proc`=`carrick-host`, `probes`/`compat`=`carrick-observability`, `host_to_linux_errno`=`carrick-host-bsd`/`-linux`) and moves by editing the `use` path.

---

## Global Constraints

- Rule 0: guests run only from `just build` binaries; `just test` is the lib-test recipe, never bare `cargo test --workspace --lib`. `carrick-kernel` forks from its test harness (it inherits `dispatch/tests.rs`), so it joins the serial `RUST_TEST_THREADS=1` list in the `test` recipe (Task 2.9).
- Never `git stash`, never `--no-verify`. Conventional Commits with Why/What/Verified body. Commits carry the `Co-Authored-By:` trailer of the agent that did the work.
- **No re-export shims, no transitional paths.** When a module moves, `carrick-runtime` stops exporting it and every consumer imports the new crate. `pub use carrick_kernel::*` in `carrick-runtime/src/lib.rs` is a plan failure.
- **Layering gate is mandatory and runs in `just ci`** (Task 0.1): `carrick-vfs` closure contains no `carrick-kernel`, `carrick-runtime`, `carrick-vmm-*`, `applevisor*`; `carrick-kernel` and `carrick-kernel-example` closures contain no `carrick-runtime`, `carrick-vmm-*`, `applevisor*`; no `carrick-vmm-*` closure contains `carrick-kernel` (the existing HAL rule).
- **Behaviour is unchanged.** A task in this plan changes no guest-visible result. If cutting an edge would require a behaviour change, stop and report; do not "fix while here". Any errno, ordering or wait-semantics change needs its own oracle line and its own commit outside this plan.
- **The example crate uses only `pub` items of `carrick-kernel`, `carrick-vfs`, `carrick-hal`, `carrick-guest-mem`, `carrick-abi`.** If it needs a `pub(crate)` item, the item becomes `pub` with a doc comment in the same commit; that is how the surface is discovered honestly.
- **Stability statement** in `crates/carrick-kernel/README.md`: experimental, no semver, API changes without notice, pin a git rev. `publish = false` is inherited from the workspace and stays.
- Line-pinned inventories (`scripts/migrate/*.json`, ~3,520 rows under the moved paths) are reconciled on a **clean tree after each move, before lint**, with the path-remap added in Task 0.2. A row that truly retired (Task 0.3 deletions) is dropped by hand with the reason in the commit.
- Every `git mv` task ends with the full ladder on the exact resulting tree: `just fmt-check && just clippy && just lint-domains && just check && just doc && just test && just test-integration`, then `just build` and the two-process signed smoke in Task 0.4. **Phase ends add `just conformance` (tier `full`), `just conformance-probes` and `just test-embed`**, with source HEAD, binary SHA-256, CDHash, LC_UUID, entitlement and `__dof_carrick` recorded against the verdict. Never run the Docker oracle concurrently with carrick.
- **BSD `sed -E` does not support `\b`** and exits 0 having changed nothing (Task 2.1 proved it); re-point symbols with `perl -pi -e 's/…\b/…/g'` or a Python regex, and verify every re-point with a `grep` that uses the same anchoring — never trust a sed exit code.
- `cargo fmt` may re-flow moved files; that is expected and committed with the move. If it touches files the move did not, that is toolchain skew: `git checkout` them.
- Do the work in a worktree under `carrick/.worktrees/` (the only path with sudo NOPASSWD for the signed smoke).

---

## Target crate graph

```text
carrick-abi   carrick-guest-mem   carrick-mem   carrick-hal   carrick-thread
carrick-host  carrick-host-{bsd,linux}   carrick-kernel-arena   carrick-observability
carrick-signal-core   carrick-timer-core   carrick-spec
        │
        ▼
carrick-vfs           Vfs trait, OpenContext/OpenFlags/Metadata/DirEnt/EntryKind,
                      VfsMounts/mount/bind, DentryCache, SparseBuffer, EtcServicesVfs,
                      ResolvConfVfs, FsBackend + HostFsBackend + MemoryBackend,
                      fs_resolve_cache, RootFs/RootFsVfs, pathcodec, overlay,
                      layer_cache, apfs, darwin_fs, FsCaller
        │
        ▼
carrick-kernel        THE CARRICK KERNEL (public): kernel/ (graph, control, tty,
                      scheduler, debug, continuation, process_lifecycle), dispatch/
                      (SyscallDispatcher, SyscallRequest, DispatchOutcome, handlers),
                      namespace/, network/, file_authority/, ProcVfs/SysVfs/DevVfs/
                      DevptsVfs, seccomp, inotify, fanotify, keyring, cred_ipc,
                      event_ring, observe, core_dump, host_tty, pty_relay, page_profile,
                      eventfd_shm, container_policy, container (state record),
                      run_result, run_state, syslog, exec_stamps, exec_helpers,
                      deadlock_watchdog. Consumes the carrier through carrick-hal:
                      Stage1MmProjection, HostSignalBridge, GuestTimerBridge.
        │
        ├──────────────────────────────┐
        ▼                              ▼
carrick-runtime                 carrick-kernel-example
THE HVPATCH CARRIER: hvpatch/,  A backend with no VM: scripted tasks on host
vcpu_loop/, carrier, threaded_  threads, LinearMemory, Null bridges; runs
loop, execute, prepare,         fork + pipe + wait through the public
runtime, supervisors, bins;     surface. Compiled by `just check`, run by
implements the hal bridges      `just test`. The template for an external
over carrick-vmm-*.             backend.
        │
        ▼
carrick-engine  →  carrick-cli
carrick-embed   (imports carrick-kernel for container/kernel::control/observe/network,
                 carrick-runtime for Runtime/carrier/prepare)
```

`crates/README.md` rows: `carrick-kernel-arena`: "Per-run `MAP_SHARED` kernel arena: the Linux-visible cross-process delta the host kernel cannot express (identity, leases, robust locks)." `carrick-kernel`: "The Carrick kernel: kernel graph, syscall dispatch, namespaces, credentials, sockets, IPC, procfs/sysfs, file authority. Public bring-your-own-backend crate; names no VMM type; consumes the carrier through `carrick-hal` traits. Experimental, no semver." `carrick-kernel-example`: "Reference execution backend with no VM; the template for embedding `carrick-kernel` behind another execution strategy." `carrick-runtime`: "The HVPatch carrier: guest-code patching, stage-1/stage-2 projection, vCPU executors, run lifecycle, platform-selected execution loops."

---

## Phase 0 — Preconditions (no extraction yet)

### Task 0.0: Rename the arena crate to `carrick-kernel-arena`

**Files:**
- Move: `crates/carrick-kernel/` → `crates/carrick-kernel-arena/`
- Modify: `crates/{carrick-host,carrick-runtime,carrick-vmm-hvf}/Cargo.toml` (dependency name), the `.rs` files `grep -rl "carrick_kernel::" crates` names (17 on 2026-09-15: `carrick-host/src/guest_cpu.rs`, `carrick-runtime/src/{carrier,prepare,run_state,runtime}.rs`, `dispatch/{creds,mqueue,proc,signal,sysv}.rs`, `dispatch/fs/tests.rs`, `file_authority/{root,tests,types}.rs`, `kernel/{container,tests}.rs`, `kernel/debug/{endpoint,server}.rs`, `namespace/pid.rs`, `carrick-vmm-hvf/src/trap/vcpu_admission.rs` — re-run the grep), `crates/README.md`, `AGENTS.md` (none today; verify), `docs/*.md` that name the crate as a live pointer (30 files; historical diaries and archived plans keep the old name with no edit — they describe the past)
- Modify: `scripts/migrate/*.py` and `scripts/*.sh` that name the path (`grep -rn "carrick-kernel" scripts .semgrep .github`)

**Interfaces:**
- Produces: crate `carrick-kernel-arena`, lib `carrick_kernel_arena`, identical contents. The name `carrick-kernel` is free.

- [ ] **Step 1: Move and rename**

```bash
git mv crates/carrick-kernel crates/carrick-kernel-arena
sed -i '' 's/^name = "carrick-kernel"$/name = "carrick-kernel-arena"/; s/^name = "carrick_kernel"$/name = "carrick_kernel_arena"/' crates/carrick-kernel-arena/Cargo.toml
grep -rl 'carrick-kernel = { path = "../carrick-kernel" }' crates/*/Cargo.toml | xargs sed -i '' 's|carrick-kernel = { path = "../carrick-kernel" }|carrick-kernel-arena = { path = "../carrick-kernel-arena" }|'
grep -rl "carrick_kernel::" crates --include='*.rs' | xargs sed -i '' 's/carrick_kernel::/carrick_kernel_arena::/g'
```

Then edit `crates/carrick-kernel-arena/src/lib.rs`'s first doc line to `//! carrick-kernel-arena: the per-run KERNEL ARENA …` and the `crates/README.md` row. For docs: `grep -rln "carrick-kernel\b" docs AGENTS.md README.md | xargs grep -ln "crates/carrick-kernel/"` finds live path pointers; edit only those, leave dated diaries.

- [ ] **Step 2: Gate**

Run: `just check && just clippy && just lint-domains && just test && just doc`
Expected: clean. `cargo metadata --no-deps --format-version 1 | grep -c '"name":"carrick-kernel"'` prints `0`.

- [ ] **Step 3: Reconcile inventories** (rows under `crates/carrick-kernel/` if any: `grep -c "crates/carrick-kernel/" scripts/migrate/*.json`), using the Task 0.2 `--rename` if it has landed, otherwise by hand for the few rows.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: rename the carrick-kernel arena crate to carrick-kernel-arena

Why: the Carrick kernel (kernel graph + syscall dispatch) is being extracted
from carrick-runtime into a public crate, and its right name is
carrick-kernel. Today that name belongs to the 1.3k-line per-run MAP_SHARED
arena, which is one kernel component, not the kernel.

What: git mv crates/carrick-kernel -> crates/carrick-kernel-arena, lib
carrick_kernel_arena; 3 manifests and every carrick_kernel:: import site re-pointed; README row
and live doc pointers updated. Dated diaries keep the historical name. No
behaviour change.

Verified: just check/clippy/lint-domains/test/doc."
```

### Task 0.1: Layering gate script, wired into `just ci`

**Files:**
- Create: `scripts/closure-assert-layering.sh`
- Modify: `justfile` (`ci` recipe and a new `check-layering` recipe)

**Interfaces:**
- Produces: `just check-layering`, exit 0 when every rule holds, exit 1 with the offending `cargo tree` line otherwise. Later tasks run it after every move.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# Layering gate: a lower crate must not have a higher crate in its normal
# dependency closure, and no VMM crate may depend on the kernel. Mirrors
# scripts/closure-assert-no-hvf.sh for the in-tree layering rather than the
# platform closure.
#
# Rules (crate : forbidden in its normal closure):
#   carrick-vfs            : carrick-kernel carrick-runtime carrick-vmm-* applevisor*
#   carrick-kernel         : carrick-runtime carrick-vmm-* applevisor*
#   carrick-kernel-example : carrick-runtime carrick-vmm-* applevisor*
#   carrick-vmm-*          : carrick-kernel
# A crate that does not exist yet is skipped (the gate lands before the
# crates it guards, so Phase 0 passes trivially).
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
members="$(cargo metadata --no-deps --format-version 1 | tr ',' '\n' | sed -nE 's/^"name":"([^"]+)"$/\1/p' | sort -u)"

check() {
  local crate="$1"; shift
  if ! grep -qx "$crate" <<<"$members"; then
    echo "layering: $crate not in workspace yet, skipped"
    return
  fi
  local tree
  tree="$(cargo tree -p "$crate" --edges normal --prefix none 2>/dev/null | awk '{print $1}' | sort -u)"
  for forbidden in "$@"; do
    if grep -Eq "^${forbidden}$" <<<"$tree"; then
      echo "layering FAIL: $crate depends on $forbidden"
      cargo tree -p "$crate" --edges normal --invert "$(grep -E "^${forbidden}$" <<<"$tree" | head -1)" 2>/dev/null | head -20 || true
      fail=1
    fi
  done
  echo "layering: $crate ok"
}

check carrick-vfs            'carrick-kernel' 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
check carrick-kernel         'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
check carrick-kernel-example 'carrick-runtime' 'carrick-vmm-.*' 'applevisor.*'
for vmm in $(grep -E '^carrick-vmm-' <<<"$members"); do check "$vmm" 'carrick-kernel'; done
exit $fail
```

- [ ] **Step 2: Add the recipe and put it in `ci` next to `check-matrix`**

```just
# Layering gate: carrick-vfs / carrick-kernel never depend upward; no VMM
# depends on the kernel
# (docs/superpowers/plans/2026-09-13-extract-carrick-vfs-and-carrick-kernel.md).
check-layering:
    ./scripts/closure-assert-layering.sh
```

and add `check-layering` to the `ci` recipe's dependency list immediately after `check-matrix`.

- [ ] **Step 3: Run it**

Run: `chmod +x scripts/closure-assert-layering.sh && just check-layering; echo exit=$?`
Expected: `skipped` for the three new crates, `ok` for every `carrick-vmm-*` (none depends on a crate named `carrick-kernel` after Task 0.0), `exit=0`.

- [ ] **Step 4: Prove it fails closed**: temporarily add `carrick-runtime = { path = "../carrick-runtime" }` to `crates/carrick-vfs`… (does not exist yet) — instead add it to `crates/carrick-signal-core/Cargo.toml` and a line `check carrick-signal-core 'carrick-runtime'`; run; expect `layering FAIL`; revert both edits.

- [ ] **Step 5: Commit**

```bash
git add scripts/closure-assert-layering.sh justfile
git commit -m "ci: add the crate layering gate ahead of the vfs/kernel extraction

Why: carrick-runtime is being split into carrick-vfs, carrick-kernel and the
HVPatch carrier, and carrick-kernel becomes a public bring-your-own-backend
crate. The split's one invariant -- a lower crate never names a VMM or
carrier type, and no VMM names the kernel -- must be machine-checked from the
first move, or the first upward \`use\` recreates the monolith with extra
manifests.

What: scripts/closure-assert-layering.sh walks \`cargo tree --edges normal\`
for each guarded crate and fails on a forbidden name; crates that do not
exist yet are skipped so the gate lands before the crates it guards. Wired
as \`just check-layering\` inside \`just ci\` after check-matrix.

Verified: exit 0 on main; injected a carrick-signal-core -> carrick-runtime
edge and saw \`layering FAIL\`."
```

### Task 0.2: Teach the line-pinned inventory reconciler to follow a path move

**Files:**
- Modify: `scripts/migrate/reconcile-line-pinned-inventories.py`
- Test: `scripts/migrate/tests/test_reconcile_rename.py` (create)

**Interfaces:**
- Produces: `python3 scripts/migrate/reconcile-line-pinned-inventories.py --rehome --rename OLD_PREFIX=NEW_PREFIX [--rename …]` rewrites every inventory row's `path` (or `file`) field whose value starts with `OLD_PREFIX` to start with `NEW_PREFIX` **before** the existing position reconciliation runs, so fingerprints re-match at the new location.

- [ ] **Step 1: Write the failing test**

```python
# scripts/migrate/tests/test_reconcile_rename.py
import json, subprocess, sys, pathlib

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "reconcile-line-pinned-inventories.py"

def test_rename_prefix_rewrites_paths(tmp_path):
    inv = tmp_path / "inv.json"
    inv.write_text(json.dumps([
        {"path": "crates/carrick-runtime/src/vfs/mount.rs", "line": 10, "fingerprint": "x"},
        {"path": "crates/carrick-runtime/src/kernel/mod.rs", "line": 3, "fingerprint": "y"},
    ]))
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "--rename-only", str(inv),
         "--rename", "crates/carrick-runtime/src/vfs/=crates/carrick-vfs/src/"],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    rows = json.loads(inv.read_text())
    assert rows[0]["path"] == "crates/carrick-vfs/src/mount.rs"
    assert rows[1]["path"] == "crates/carrick-runtime/src/kernel/mod.rs"
```

- [ ] **Step 2: Run it and watch it fail**

Run: `python3 -m pytest scripts/migrate/tests/test_reconcile_rename.py -q`
Expected: FAIL (`unrecognized arguments: --rename-only`).

- [ ] **Step 3: Implement `--rename` and `--rename-only`**

Argument parser additions:

```python
parser.add_argument("--rename", action="append", default=[], metavar="OLD=NEW",
    help="rewrite inventory paths starting with OLD to start with NEW before reconciling")
parser.add_argument("--rename-only", metavar="INVENTORY_JSON",
    help="apply --rename to one inventory file and exit (test hook)")
```

Helper, called on every inventory after load and before the position pass:

```python
PATH_KEYS = ("path", "file")

def apply_renames(rows, renames):
    """Rewrite the path field of each row whose path starts with an OLD prefix."""
    pairs = [r.split("=", 1) for r in renames]
    changed = 0
    for row in rows:
        for key in PATH_KEYS:
            value = row.get(key)
            if not isinstance(value, str):
                continue
            for old, new in pairs:
                if value.startswith(old):
                    row[key] = new + value[len(old):]
                    changed += 1
                    break
    return changed
```

`--rename-only` loads the JSON (a list of rows, or a dict whose values are lists of rows: handle both shapes the inventories use), applies renames, writes back, prints the count, exits 0. In the normal path a rename without `--rehome` is refused ("fingerprints cannot be verified at the old path").

- [ ] **Step 4: Run the test; it passes.** Run: `python3 -m pytest scripts/migrate/tests/test_reconcile_rename.py -q` → `1 passed`.

- [ ] **Step 5: Prove the unrenamed path is a no-op.** Run: `python3 scripts/migrate/reconcile-line-pinned-inventories.py && git status --porcelain scripts/migrate` → clean (the reconciler has no `--check`; the `--check` flag belongs to `check-host-authority-transitions.py`).

- [ ] **Step 6: Commit**

```bash
git add scripts/migrate/reconcile-line-pinned-inventories.py scripts/migrate/tests/test_reconcile_rename.py
git commit -m "chore(migrate): let the inventory reconciler follow a path move

Why: the vfs/kernel extraction git-mv's ~200k lines; the line-pinned
inventories hold ~3,520 rows under the moved paths and the reconciler only
moves positions inside a file, so a rename would read as 3,520 retired sites.

What: --rename OLD=NEW (repeatable, requires --rehome) rewrites row paths
before the position pass; --rename-only is the unit-test hook.

Verified: scripts/migrate/tests/test_reconcile_rename.py; --check on the
unrenamed tree is a no-op."
```

### Task 0.3: Delete the retired native lane's `#[cfg(test)]` host-pid bodies

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/proc.rs` (the four `#[cfg(not(test))] return …; #[cfg(test)] { … }` pairs at ~3085 `ptrace`, ~3520 `waitid`, ~3998 `wait4`, ~4741 `pidfd_send_signal`; re-locate with `grep -n "cfg(not(test))" crates/carrick-runtime/src/dispatch/proc.rs`)
- Modify: `crates/carrick-runtime/src/dispatch/tests.rs`, `crates/carrick-runtime/src/dispatch/fs/tests.rs` (tests that only exercised those bodies)
- Modify: `scripts/migrate/host-authority-transition-inventory.json` (rows for the deleted `libc::waitid`/`libc::kill` sites, dropped by hand)

**Interfaces:**
- Produces: `wait4`, `waitid`, `ptrace`, `pidfd_send_signal` have one body in every build. When `hvpatch_process()` is `None` they return exactly what release builds return today (`ENOSYS` for the wait family and ptrace, `ESRCH` for pidfd).

- [ ] **Step 1: Inventory the tests that reach the `#[cfg(test)]` bodies**

```bash
grep -n "libc::waitid\|libc::waitpid\|libc::kill(" crates/carrick-runtime/src/dispatch/proc.rs | head -40
grep -n "fn .*wait4\|fn .*waitid\|fn .*pidfd_send_signal\|fn .*ptrace" crates/carrick-runtime/src/dispatch/tests.rs crates/carrick-runtime/src/dispatch/fs/tests.rs | head -40
```

For each test: if it drives the dispatcher with a real forked host child and asserts host-pid wait semantics, it tests the retired lane and is deleted with the body. If it constructs an HVPatch process (`process_context_for_tests`) it stays and must still pass.

- [ ] **Step 2: Delete each pair, keeping the `#[cfg(not(test))]` return as the unconditional return**

Before (proc.rs ~3998):

```rust
            #[cfg(not(test))]
            return Ok(DispatchOutcome::errno(LINUX_ENOSYS));
            #[cfg(test)]
            {
            // PID namespace (§5.3): a positive `pid` arg names a child by its
            // ns-pid; translate it to the host pid the kernel knows. …
            …
            }
```

After:

```rust
            // A task with no HVPatch process binding cannot wait: the retired
            // 1:1 native lane's host-pid wait lived here (e1fbfd32e) and was
            // deleted with the kernel extraction plan; git remembers it.
            Ok(DispatchOutcome::errno(LINUX_ENOSYS))
```

Same for ~3085 (`ptrace`), ~3520 (`waitid`), and ~4741 (`pidfd_send_signal`, unconditional `ESRCH`; the `let _ = host_pid;` goes too; if `PidfdTarget::Host` then has no reader, delete the variant and its constructor and follow the compiler through the match arms).

- [ ] **Step 3: Delete the retired-lane tests from Step 1; remove unused imports.** Run: `just check && RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib --no-run` → clean, no `unused` warnings.

- [ ] **Step 4: Run the serial runtime tests.** Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib` → pass.

- [ ] **Step 5: Reconcile inventories on the clean tree, dropping retired host-authority rows by hand.** Run: `python3 scripts/migrate/reconcile-line-pinned-inventories.py --rehome && python3 scripts/migrate/check-host-authority-transitions.py --check`; delete each row the checker reports as gone and name it in the commit.

- [ ] **Step 6: Full gate and signed smoke**

Run: `just ci && just build && CARRICK_RUN_ID=t03 target/release/carrick run --rm ubuntu:24.04 sh -c 'sleep 0.2 & wait $!; echo waited=$?'`
Expected: ci green; guest prints `waited=0`.

- [ ] **Step 7: Commit**

```bash
git add -A crates/carrick-runtime scripts/migrate
git commit -m "refactor(runtime): delete the retired native lane's cfg(test) wait/ptrace/pidfd bodies

Why: wait4, waitid, ptrace and pidfd_send_signal each carried two bodies: the
HVPatch kernel-graph path, and behind #[cfg(test)] the retired 1:1 host-pid
path (libc::waitid / host kill) from before e1fbfd32e. Release binaries never
ran the second body; only tests of the retired lane did. Two bodies for one
syscall is a second path, and the public carrick-kernel crate must not carry
a host-pid wait into a crate that names no host process.

What: keep the release return (ENOSYS / ESRCH) unconditionally; delete the
cfg(test) bodies, the PidfdTarget::Host variant, and the N tests that only
asserted host-pid semantics: <list them>. Host-authority inventory rows
HA-xxxx.. dropped as retired sites.

Verified: just ci; signed ubuntu:24.04 guest \`sleep & wait\` returns 0
through the HVPatch wait4 path."
```

### Task 0.4: Record the two-process signed smoke used by every later task

**Files:**
- Create: `scripts/conformance/smoke-two-process.sh`

- [ ] **Step 1: Write it**

```bash
#!/usr/bin/env bash
# Two-process signed smoke for the crate-extraction plan. A single-process
# guest cannot see a scope bug; this runs fork + pipe + kill + wait + procfs
# under the signed binary and fails on any deviation. Not an oracle gate.
set -euo pipefail
cd "$(dirname "$0")/../.."
bin=target/release/carrick
[ -x "$bin" ] || { echo "build with just build first"; exit 2; }
export CARRICK_RUN_ID="${CARRICK_RUN_ID:-smoke2p-$$}"
out="$("$bin" run --rm ubuntu:24.04 sh -c '
  set -e
  ( sleep 5 ) & child=$!
  kill -TERM $child; wait $child && rc=0 || rc=$?
  echo child_rc=$rc
  echo hello | ( read -r x; echo pipe=$x )
  head -1 /proc/self/status | cut -f1
  ls /proc | grep -c "^[0-9]" | sed "s/^/procs=/"
  mkdir -p /tmp/x && echo data > /tmp/x/f && cat /tmp/x/f
' 2>&1)"
echo "$out"
grep -q '^child_rc=143$' <<<"$out"
grep -q '^pipe=hello$' <<<"$out"
grep -q '^Name:' <<<"$out"
grep -Eq '^procs=[1-9]' <<<"$out"
grep -q '^data$' <<<"$out"
echo "smoke-two-process: ok"
```

- [ ] **Step 2: Run it on the Task 0.3 binary.** Run: `chmod +x scripts/conformance/smoke-two-process.sh && scripts/conformance/smoke-two-process.sh` → ends `smoke-two-process: ok`. Reap with `scripts/sudo/kill.sh "$CARRICK_RUN_ID"` if it wedges.

- [ ] **Step 3: Commit** `test(conformance): two-process signed smoke for the crate extraction` with a Why/Verified body as in Task 0.1.

---

## Phase 1 — Extract `carrick-vfs`

### Task 1.1: Move `HostSyscallResult` and `rootfs_errno` below the VFS

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs` (definitions)
- Create: `crates/carrick-runtime/src/vfs/errno.rs`
- Modify: `crates/carrick-runtime/src/vfs/rootfs.rs` (9 sites: L508, 612, 654, 705 `use crate::dispatch::HostSyscallResult as _`; L1145, 1230, 1256, 1401, 1469 `rootfs_errno`), `fs_backend/host.rs` (1 site, `HostSyscallResult`)

**Interfaces:**
- Produces: `crate::vfs::errno::{HostSyscallResult, rootfs_errno}` with identical signatures. `dispatch/mod.rs` imports them from there (an intra-crate import, removed in Task 2.9 when the dispatch sites are re-pointed to `carrick_vfs::errno`).

- [ ] **Step 1:** `grep -n "pub.*enum HostSyscallResult\|pub.*trait HostSyscallResult\|pub.*fn rootfs_errno" crates/carrick-runtime/src/dispatch/mod.rs` (`HostSyscallResult` is used as a trait — `use … as _` — so the definition is a trait with an impl for `Result`/`i32`; move the impls with it)
- [ ] **Step 2:** Cut the two definitions (with impls and docs) verbatim into `vfs/errno.rs`. If `HostSyscallResult` names any dispatch type other than `carrick_abi::LinuxErrno`, stop and report: that is an unmeasured upward edge.
- [ ] **Step 3: Re-point**

```bash
grep -rln "crate::dispatch::\(HostSyscallResult\|rootfs_errno\)" crates/carrick-runtime/src/vfs crates/carrick-runtime/src/fs_backend \
  | xargs sed -i '' 's/crate::dispatch::HostSyscallResult/crate::vfs::errno::HostSyscallResult/g; s/crate::dispatch::rootfs_errno/crate::vfs::errno::rootfs_errno/g'
```

- [ ] **Step 4: Verify.** Run: `grep -rn "crate::dispatch::" crates/carrick-runtime/src/vfs/{mod,rootfs,bind,dentry,mount,sparse_buffer,etc_services,resolvconf,namespace_mutation}.rs crates/carrick-runtime/src/fs_backend crates/carrick-runtime/src/fs_backend.rs crates/carrick-runtime/src/{rootfs,fs_resolve_cache,pathcodec,overlay,layer_cache,apfs,darwin_fs}.rs` → no output.
- [ ] **Step 5: Gate.** Run: `just check && just clippy && RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib vfs` → clean.
- [ ] **Step 6: Commit** `refactor(runtime): move HostSyscallResult and rootfs_errno below the VFS` (Why: the only upward edges from rootfs.rs and fs_backend into dispatch, 10 sites; What: verbatim move; Verified: check/clippy/vfs tests).

### Task 1.2: `dev.rs`/`devpts.rs` stay with the kernel (decision record)

`vfs/dev.rs` and `vfs/devpts.rs` name `kernel::tty::{detach, TtyKey::Pty}` (4 sites). Devices and ptys are kernel objects (the pty line discipline is in-zone by owner ruling). They move with `proc.rs`/`sys.rs` in Phase 2 and implement the `Vfs` trait from `carrick-vfs`, which is the right direction.

- [ ] **Step 1:** `grep -n "crate::\(kernel\|namespace\|network\|dispatch\)" crates/carrick-runtime/src/vfs/dev.rs crates/carrick-runtime/src/vfs/devpts.rs` → exactly the four `kernel::tty` items (new ones change nothing: they still stay).

### Task 1.3: Break the remaining non-leaf edges from the moving set

Moving set: `vfs/{mod,bind,dentry,mount,sparse_buffer,etc_services,resolvconf,rootfs,namespace_mutation,errno}.rs` (`namespace_mutation.rs` landed 2026-09-14, 409 lines, 0 upward edges), `fs_backend.rs`, `fs_backend/*`, `rootfs.rs`, `fs_resolve_cache.rs`, `pathcodec.rs`, `overlay.rs`, `layer_cache.rs`, `apfs.rs`, `darwin_fs.rs`.

- [ ] **Step 1: Measure the residue**

```bash
cd crates/carrick-runtime/src
grep -rhoE "crate::[a-z_]+" vfs/{mod,bind,dentry,mount,sparse_buffer,etc_services,resolvconf,rootfs,namespace_mutation,errno}.rs fs_backend.rs fs_backend rootfs.rs fs_resolve_cache.rs pathcodec.rs overlay.rs layer_cache.rs apfs.rs darwin_fs.rs \
 | sort | uniq -c | sort -rn \
 | grep -vE "crate::(vfs|fs_backend|rootfs|fs_resolve_cache|pathcodec|overlay|layer_cache|apfs|darwin_fs|linux_abi|memory|thread|host_proc|guest_cpu|probes|compat|host_to_linux_errno|shared_aperture)$"
```

Measured residue on 2026-09-15 (after Task 1.1): exactly four sites, all in `vfs/mod.rs` — `OpenContext`'s lazily captured `creds_ns: LazyField<'a, Option<crate::namespace::process::ProcessCredsNs>>` (L728, accessor L791) and `network_model: LazyField<'a, Option<crate::network::model::LinuxNetworkModel>>` (L724, accessor L767). The earlier `run_state`/`execute`/`container_thread_states` residue belonged to `proc.rs`, which is not in the moving set.

- [ ] **Step 2: Replace the two `OpenContext` fields with VFS-defined traits**

First enumerate what readers call on them: `grep -rn "\.creds_ns()\|\.network_model()" crates/carrick-runtime/src | grep -v "fn creds_ns\|fn network_model"` and, for each hit, the method chain that follows (e.g. `.creds_ns().map(|c| c.fsuid())`). The method set of each trait is exactly that list.

1. **Credentials** — `creds_ns` becomes `LazyField<'a, Option<Arc<dyn FsCaller>>>` where `FsCaller` is defined in `vfs/mod.rs`:

```rust
/// What the filesystem needs to know about the caller for permission checks.
/// Implemented by the kernel's credential snapshot; the VFS never names the
/// kernel type.
pub trait FsCaller {
    fn fsuid(&self) -> carrick_abi::NsUid;
    fn fsgid(&self) -> carrick_abi::NsGid;
    fn supplementary_groups(&self) -> &[carrick_abi::NsGid];
    fn has_dac_override(&self) -> bool;
    fn has_dac_read_search(&self) -> bool;
}
```

The method names above are illustrative; the real set is the Step 2 enumeration. `impl FsCaller for ProcessCredsNs` lives in `namespace/process.rs`; every producer that fills the lazy field wraps the same value it does today.
2. **Network model** — `network_model` becomes `LazyField<'a, Option<Arc<dyn FsNetworkView>>>` with `FsNetworkView` defined the same way from the `.network_model()` reader enumeration (today: `/etc/resolv.conf` and `/etc/hosts` rendering in `resolvconf.rs`/`etc_services.rs` read the nameserver list and host entries). `impl FsNetworkView for LinuxNetworkModel` lives in `network/model.rs`.

If a reader turns out to be in `proc.rs` only (a kernel-view file that is not moving), the field may instead stay concrete and move with `proc.rs` — decide per reader from the enumeration, and record the decision in the commit body.

- [ ] **Step 3:** Re-run Step 1 until it prints nothing.
- [ ] **Step 4: Gate.** `just check && just clippy && just lint-domains && RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib`.
- [ ] **Step 5: Commit** `refactor(runtime): make the filesystem layer name no kernel or namespace type` (Why: `OpenContext` carried the kernel's `ProcessCredsNs` and `LinuxNetworkModel` as lazy fields, the last two upward edges from the VFS; What: `FsCaller` and `FsNetworkView` traits defined in the VFS, implemented by the kernel types; Verified: gates).

### Task 1.4: Create `crates/carrick-vfs` and `git mv` the moving set

**Files:**
- Create: `crates/carrick-vfs/Cargo.toml`, `crates/carrick-vfs/src/lib.rs`, `crates/carrick-vfs/README.md`
- Move: the Task 1.3 moving set into `crates/carrick-vfs/src/`
- Modify: `crates/carrick-runtime/Cargo.toml`, `crates/carrick-runtime/src/lib.rs`, every `crate::vfs::`/`crate::fs_backend::`/`crate::rootfs::`… site in the runtime, `carrick-cli`/`carrick-embed` imports and manifests

**Interfaces:**
- Produces: `carrick_vfs::{Vfs, VfsHandle, VfsMounts, MountRef, OpenContext, OpenFlags, Metadata, DirEnt, DirEntry, EntryKind, InodeIdentity, DentryCache, BindVfs, RootFsVfs, WatchFd, EtcServicesVfs, ResolvConfVfs, SparseBuffer, FsCaller, FsNetworkView, namespace_mutation, errno::{HostSyscallResult, rootfs_errno}}`, `carrick_vfs::fs_backend::{FsBackend, HostFsBackend, MemoryBackend, BackendError, …}`, `carrick_vfs::{rootfs, fs_resolve_cache, pathcodec, overlay, layer_cache, apfs, darwin_fs}`.

- [ ] **Step 1: Manifest**

```toml
[package]
name = "carrick-vfs"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "carrick_vfs"
path = "src/lib.rs"

[lints]
workspace = true

[features]
# In-memory fs backend selection (default OFF; control point is carrick-cli,
# forwarded through carrick-runtime exactly as before).
fs-memory = ["carrick-spec/fs-memory"]

[dependencies]
carrick-fatal.workspace = true
carrick-abi = { path = "../carrick-abi" }
carrick-spec = { path = "../carrick-spec" }
carrick-guest-mem = { path = "../carrick-guest-mem" }
carrick-host = { path = "../carrick-host" }
carrick-observability = { path = "../carrick-observability" }
carrick-portable = { path = "../carrick-portable" }
carrick-thread = { path = "../carrick-thread" }
carrick-mem = { path = "../carrick-mem" }
anyhow.workspace = true
bitflags.workspace = true
camino.workspace = true
flate2.workspace = true
libc.workspace = true
parking_lot.workspace = true
sha2.workspace = true
tar.workspace = true
tempfile.workspace = true
thiserror.workspace = true
tracing.workspace = true

[target.'cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))'.dependencies]
carrick-host-bsd = { path = "../carrick-host-bsd" }
[target.'cfg(target_os = "linux")'.dependencies]
carrick-host-linux = { path = "../carrick-host-linux" }

[dev-dependencies]
carrick-test-support = { path = "../carrick-test-support" }
tempfile.workspace = true
proptest.workspace = true
```

Trim any dependency the compiler reports unused; add none the moving set does not name.

- [ ] **Step 2: Move**

```bash
mkdir -p crates/carrick-vfs/src/vfs
cd crates/carrick-runtime/src
for f in mod bind dentry mount sparse_buffer etc_services resolvconf rootfs namespace_mutation errno; do git mv vfs/$f.rs ../../carrick-vfs/src/vfs/$f.rs; done
git mv fs_backend.rs ../../carrick-vfs/src/fs_backend.rs
git mv fs_backend ../../carrick-vfs/src/fs_backend
for f in rootfs fs_resolve_cache pathcodec overlay layer_cache apfs darwin_fs; do git mv $f.rs ../../carrick-vfs/src/$f.rs; done
```

`crates/carrick-vfs/src/lib.rs`:

```rust
//! carrick-vfs: the Carrick filesystem model. The `Vfs` trait and its mount
//! table, the dentry cache, the host and in-memory backends, the root
//! filesystem and the layer cache. Names no kernel, carrier or VMM type; the
//! kernel-view filesystems (procfs, sysfs, devpts, /dev) live in
//! carrick-kernel because they render kernel state.

pub mod apfs;
pub mod darwin_fs;
pub mod fs_backend;
pub mod fs_resolve_cache;
pub mod layer_cache;
pub mod overlay;
pub mod pathcodec;
pub mod rootfs;
pub mod vfs;

pub use vfs::*;
```

In `carrick-vfs/src/vfs/mod.rs` delete the `mod proc; mod sys; mod dev; mod devpts;` lines and their re-exports. `proc.rs`, `sys.rs`, `dev.rs`, `devpts.rs` stay in `carrick-runtime/src/vfs/` under a new four-line `crates/carrick-runtime/src/vfs/mod.rs`.

- [ ] **Step 3: Re-point the runtime.** In `carrick-runtime/Cargo.toml` add `carrick-vfs = { path = "../carrick-vfs" }` and make `fs-memory = ["carrick-vfs/fs-memory", "carrick-spec/fs-memory"]`. In `lib.rs` delete `pub mod fs_backend; fs_resolve_cache; layer_cache; overlay; pathcodec; rootfs; apfs; darwin_fs;` and the inline `pub mod apfs { … }` at ~103. Then:

```bash
cd crates/carrick-runtime/src
grep -rl "crate::\(fs_backend\|fs_resolve_cache\|layer_cache\|overlay\|pathcodec\|rootfs\|apfs\|darwin_fs\)::" . | xargs sed -i '' \
  's/crate::fs_backend::/carrick_vfs::fs_backend::/g; s/crate::fs_resolve_cache::/carrick_vfs::fs_resolve_cache::/g; s/crate::layer_cache::/carrick_vfs::layer_cache::/g; s/crate::overlay::/carrick_vfs::overlay::/g; s/crate::pathcodec::/carrick_vfs::pathcodec::/g; s/crate::rootfs::/carrick_vfs::rootfs::/g; s/crate::apfs::/carrick_vfs::apfs::/g; s/crate::darwin_fs::/carrick_vfs::darwin_fs::/g'
```

For `crate::vfs::X`: `X ∈ {proc, sys, dev, devpts, ProcVfs, SysVfs, DevVfs, DevptsVfs, SyntheticProc*, PtyTable, PtyRole, VirtualConsole, ProcMaps*, ProcMapSharing, GuestReportedArch}` stays `crate::vfs::X`; everything else becomes `carrick_vfs::X`. Drive the residue by compiler error; no blanket `pub use carrick_vfs::*` in the runtime.

- [ ] **Step 4: Consumers.** `carrick-cli/src/{fs_setup,commands}.rs`, `carrick-embed/src/{vfs,builder,prepared,lib}.rs`: add `carrick-vfs = { path = "../carrick-vfs" }`; replace `carrick_runtime::{vfs,fs_backend,rootfs}::` with `carrick_vfs::…` for moved items.

- [ ] **Step 5: Inventories and lint paths**

```bash
python3 scripts/migrate/reconcile-line-pinned-inventories.py --rehome \
  --rename crates/carrick-runtime/src/vfs/mod.rs=crates/carrick-vfs/src/vfs/mod.rs \
  $(for f in bind dentry mount sparse_buffer etc_services resolvconf rootfs namespace_mutation errno; do printf -- "--rename crates/carrick-runtime/src/vfs/%s.rs=crates/carrick-vfs/src/vfs/%s.rs " $f $f; done) \
  --rename crates/carrick-runtime/src/fs_backend=crates/carrick-vfs/src/fs_backend \
  $(for f in rootfs fs_resolve_cache pathcodec overlay layer_cache apfs darwin_fs; do printf -- "--rename crates/carrick-runtime/src/%s.rs=crates/carrick-vfs/src/%s.rs " $f $f; done)
```

Then widen every `paths:` glob in `.semgrep/typed-domains.yml` and every `PurePosixPath("crates/carrick-runtime/…")` in `scripts/migrate/check-*.py` that pointed at a moved file; add `crates/carrick-vfs/**` wherever `crates/carrick-runtime/**` is a scope.

- [ ] **Step 6: README** `crates/carrick-vfs/README.md`: what it is (one paragraph), what it deliberately excludes (procfs/sysfs/devpts), the `FsCaller` seam, "experimental, no semver, pin a git rev".

- [ ] **Step 7: Gate ladder + layering + signed smoke.** Run: `just check-layering && just ci && just build && scripts/conformance/smoke-two-process.sh` → `layering: carrick-vfs ok`, ci green, smoke ok.

- [ ] **Step 8: `crates/README.md`**: add the `carrick-vfs` row; shorten the `carrick-runtime` row; product path gains `carrick-vfs`.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "refactor: extract carrick-vfs from carrick-runtime

Why: the filesystem model (Vfs trait, mounts, dentry cache, host and memory
backends, rootfs, overlay, layer cache) named nothing above itself after the
edge cuts in the two preceding commits, and carrick-runtime at 377k lines
recompiles all of it for every kernel edit. This is the A4 split mapped in
docs/archive/build-decomposition-design.md.

What: git mv of vfs/{mod,bind,dentry,mount,sparse_buffer,etc_services,
resolvconf,rootfs,namespace_mutation,errno}, fs_backend, rootfs, fs_resolve_cache, pathcodec,
overlay, layer_cache, apfs, darwin_fs into crates/carrick-vfs. procfs, sysfs,
/dev and devpts stay in the runtime: they render kernel state. Consumers
(carrick-cli, carrick-embed) import carrick_vfs directly; the runtime
re-exports nothing it no longer owns. Inventories rehomed with --rename.

Verified: just check-layering (carrick-vfs closure has no kernel/runtime/
vmm crate), just ci, signed two-process smoke."
```

### Task 1.5: Phase 1 acceptance

- [ ] **Step 1:** Record binary identity: `git rev-parse HEAD; shasum -a 256 target/release/carrick; codesign -dvvv target/release/carrick 2>&1 | grep -E 'CDHash|Identifier'; otool -l target/release/carrick | grep -A2 LC_UUID | tail -1; otool -l target/release/carrick | grep -c dof; codesign -d --entitlements - target/release/carrick 2>/dev/null | grep -c hypervisor`.
- [ ] **Step 2:** `just conformance full` (carrick phase, then Docker phase; never concurrent). Expected: verdict set equals the blessed baseline. Any DIFF is attributed per AGENTS.md (Docker too? pre-change binary too? blessed baseline?) **before** any code change; a load-probabilistic flip is sampled ≥2×.
- [ ] **Step 3:** `just conformance-probes` from the repo root (from any other cwd it SKIPs every lane and reports green). Expected: all MATCH.
- [ ] **Step 4:** `just test-embed`. Expected: green.
- [ ] **Step 5:** Append the identity block and verdict counts to `docs/conformance-campaigns/2026-09-13-crate-extraction.md` (create) as "Phase 1 receipt". Commit `docs(conformance): phase 1 receipt for the carrick-vfs extraction`.

---

## Phase 2 — Extract `carrick-kernel`

### Task 2.1: Move process-lifecycle types out of `hvpatch/` into `kernel/`

**Files:**
- Modify: wherever `grep -rn "pub.*\(enum Stage\b\|struct ProcessContext\|enum WaitResult\|struct ProcessThreadExit\|struct ChildExit\|struct ForeignMmInstallPermit\|fn identity_operation_errno\|fn process_context_for_tests\)" crates/carrick-runtime/src/hvpatch` lands
- Create: `crates/carrick-runtime/src/kernel/process_lifecycle.rs`
- Modify: 66 sites in `dispatch/` (59) and `kernel/` (7)

**Interfaces:**
- Produces: `crate::kernel::process_lifecycle::{ProcessContext, WaitResult, Stage, ProcessThreadExit, ChildExit, ForeignMmInstallPermit, identity_operation_errno, process_context_for_tests}`, re-exported from `crate::kernel`.

- [ ] **Step 1: Confirm each type names no VMM or stage-1 type.** Run: `grep -n "carrick_vmm_hvf\|applevisor\|Stage1MmLease\|stage1_mm::" $(grep -rl "enum Stage\b\|struct ProcessContext\|enum WaitResult" crates/carrick-runtime/src/hvpatch)`. Expected: `ProcessContext`/`WaitResult`/`Stage`/`ProcessThreadExit`/`ChildExit` hold `TaskKey`s, generations and exit codes only. If `ForeignMmInstallPermit` holds a stage-1 handle it is **not** moved: it becomes `Stage1MmProjection::InstallPermit` in Task 2.3.
- [ ] **Step 2:** Cut the definitions (impls, tests) into `kernel/process_lifecycle.rs`; `pub mod process_lifecycle; pub use process_lifecycle::{…};` in `kernel/mod.rs`.
- [ ] **Step 3: Re-point**

```bash
cd crates/carrick-runtime/src
grep -rl "crate::hvpatch::\(ProcessContext\|WaitResult\|Stage\b\|ProcessThreadExit\|ChildExit\|identity_operation_errno\|process_context_for_tests\)" dispatch kernel vcpu_loop hvpatch | xargs sed -i '' -E 's/crate::hvpatch::(ProcessContext|WaitResult|Stage|ProcessThreadExit|ChildExit|identity_operation_errno|process_context_for_tests)\b/crate::kernel::\1/g'
```

- [ ] **Step 4: Verify.** `grep -rn "crate::hvpatch::" crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/kernel` → only `Stage1MmLease` (3 sites) and possibly `ForeignMmInstallPermit`.
- [ ] **Step 5: Gate + commit** `refactor(runtime): move process-lifecycle types from hvpatch into the kernel graph` (Why: kernel facts keyed by TaskKey lived in the carrier's module; What: verbatim move; Verified: check/clippy/serial lib tests).

**Landed 2026-09-16 (`84d59e62f`, `fe5f1afae`) — corrections from execution:** `Stage` does not exist (the census row was a prefix match on `Stage1MmLease`; there are 5 `Stage1MmLease` sites, not 3). `ChildExit`, `WaitResult`, `ProcessThreadExit`, `identity_operation_errno` and `RetiredThreadResources` (the `ProcessThreadExit::Retired` payload, pure kernel state) moved. **`ProcessContext` did not move and must not**: it is a carrier handle (holds `Arc<MmResources>` and `Arc<RwLock<Arc<Stage1MmBackend>>>`, 903-line impl naming 15 hvpatch-private types); moving it relocates the back-edge instead of cutting it. It and `process_context_for_tests` (which builds a real `Stage1MmBackend`) are cut by **Task 2.15** through a kernel-level trait. `ForeignMmInstallPermit` stays in hvpatch for Task 2.3 — it holds no stage-1 handle, but its private `new()` is a carrier-minted capability (only the HVPatch lifecycle may install a foreign-mm endpoint) and moving it would widen who can mint one. The three `Stage1MmPool::new_root_for_tests` sites in `kernel/mm_access.rs` tests (L2453, L2554, L2639) are a kernel→hvpatch back-edge the census missed; Task 2.2 moves those tests to the carrier with the other foreign-COW tests.


### Task 2.15: `CarrierProcess` — dispatch reaches the HVPatch process through a kernel-level trait

**Files:**
- Create: `crates/carrick-runtime/src/kernel/carrier_process.rs` (trait + test double)
- Modify: `crates/carrick-runtime/src/hvpatch/mod.rs` (`impl CarrierProcess for ProcessContext`), `dispatch/kernel_context.rs:85,113,355` (`bind_hvpatch_process`, `hvpatch_process`), `dispatch/dispatcher.rs:1482,1532,1628`, `dispatch/proc.rs:511,635,812,978,4585`, `dispatch/mod.rs:2597`, `dispatch/fs.rs:781,821`, every `hvpatch_process()` consumer, the 26 `process_context_for_tests` call sites (`dispatch/mqueue.rs` ×20, `core_publication.rs` ×3, `ioring.rs`, `proc.rs`, `sysv.rs`)

**Interfaces:**
- Consumes: the kernel's existing seam shape — `kernel::address::MmBackend` (3 methods, `Arc<dyn MmBackend>` taken by `RootBootstrap::with_mm_backend`, with test impls in `kernel/exec.rs` `TestMmBackend`, `kernel/snapshot.rs` `TestBackend`, `kernel/mm_access.rs` fixtures) and `hvpatch::ProcessContext` as it is today.
- Produces: `pub trait CarrierProcess: Send + Sync` in `crate::kernel::carrier_process`, re-exported from `crate::kernel`; `SyscallDispatcher`/`ProcView`/`KernelContext` bindings store and return `Option<Arc<dyn CarrierProcess>>` where they held `Option<crate::hvpatch::ProcessContext>`; `hvpatch::ProcessContext` implements it; `kernel::carrier_process::TestCarrierProcess` (behind `#[cfg(any(test, feature = "test-support"))]`) replaces `process_context_for_tests` for dispatch tests.

- [ ] **Step 1: Enumerate the surface compiler-driven.** Change `hvpatch_process()`'s return type (dispatcher.rs:1482/1532/1628, kernel_context.rs:355, proc.rs:812, fs.rs:781) to `Option<Arc<dyn CarrierProcess>>` with an empty trait, run `just check`, and add one trait method per error, copying the signature from `impl ProcessContext` verbatim. Measured on 2026-09-16 the set is about: `pid`, `task_id`, `task_key`, `task_binding`, `kernel_graph`, `context_for_linux_tid`, `process_group`, `process_is_live`, `live_process_key`, `wait_child_with_job_control`, `wait_child_key`, `wait_child_in_process_group_with_job_control`, `register_pidfd_watch`, `stop_for_ptrace_signal`, `mm_access_authority`, `old_file_table`, `process_timer_delivery`, `bind_vma_source`, `bind_mm_mutation_authority`, `stage1_mm_lease`, `prepare_exec`, `commit_exec`, `exit_thread`, `is_forked_guest_process`, `enable_mm_access_for_tests`. The compiler's list wins over this one.
- [ ] **Step 2: Return-type rule.** A method whose signature names only kernel/abi/hal types is copied as is. A method that names an hvpatch-private type is handled by the gate: (a) `stage1_mm_lease() -> Result<Arc<crate::hvpatch::Stage1MmLease>, RuntimeError>` keeps that return type in THIS task — it is the one hvpatch name allowed to survive in dispatch, and Task 2.3 replaces it with `Arc<dyn Stage1MmProjection>`; (b) the exec wrappers `PreparedProcessExec`, `CommittedProcessExec`, `PublishedProcessExec`, `CompleteExecError` (hvpatch/mod.rs:464-547) either move into `kernel/exec.rs` if, after `RetiredThreadResources`' precedent, they hold only kernel exec-transition state plus receipts, or become opaque `Box<dyn PreparedExec>`-style trait objects whose traits carry exactly the methods dispatch calls on them (`complete`, `into_parts`, `context`, `thread`, `shared`, …); decide per type by the same gate (names a stage-1 or `MmResources` field → opaque) and record the decision per type in the commit body. No `pub(crate) use crate::hvpatch::…` may appear in `kernel/` or `dispatch/`.
- [ ] **Step 3: `impl CarrierProcess for ProcessContext`** in hvpatch/mod.rs, forwarding. `bind_hvpatch_process(process: ProcessContext)` becomes `bind_hvpatch_process(process: Arc<dyn CarrierProcess>)`; the carrier wraps at its single call site (`grep -rn "bind_hvpatch_process\|bind_hvpatch_process_exact" crates/carrick-runtime/src` outside dispatch/).
- [ ] **Step 4: `TestCarrierProcess`.** Build it from `RootBootstrap::with_mm_backend(pid, ThreadId::synthetic_for_tests(pid), Arc<dyn MmBackend>, name)` + `Kernel::bootstrap_root`, using the kernel's existing `TestMmBackend` (promote it from `kernel/exec.rs`'s test module to `kernel/carrier_process.rs` under the same cfg), publishing the root task exactly as `process_context_for_tests` does minus `MmResources`/`Stage1MmBackend`; implement every trait method with the same kernel-graph semantics `ProcessContext` has (waits, identities, pidfd watches, ptrace stop, exec transitions through `crate::kernel::exec`); `stage1_mm_lease` returns `Err` (no stage-1), `bind_vma_source`/`bind_mm_mutation_authority` record into the test backend. Switch the 26 `process_context_for_tests` callers to it. A dispatch test that turns out to need a real stage-1 backend (it fails only for that reason) moves to the carrier's test module unchanged, with the list in the commit body — expected: few or none, since dispatch tests exercise syscalls, not page tables.
- [ ] **Step 5: Verify the seam is total.** `grep -rn "crate::hvpatch" crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/kernel` → exactly: `Stage1MmLease` (Task 2.3), `ForeignMmInstallPermit` (Task 2.3), `Stage1MmPool::new_root_for_tests` ×3 in `kernel/mm_access.rs` tests (Task 2.2). `process_context_for_tests` is deleted from hvpatch when it has no caller left; otherwise it stays for the carrier's own tests only.
- [ ] **Step 6: Gate + signed smoke + commit.** `just check && just clippy && just lint-domains && RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib && just build && scripts/conformance/smoke-two-process.sh`. Commit `refactor(runtime): dispatch reaches the HVPatch process through the CarrierProcess trait` with Why (the carrier handle was the largest hvpatch→dispatch edge, 14 type sites + 26 test-helper sites; the public kernel crate cannot name it), What (the trait's exact method list, the per-type exec-wrapper decisions, the test double), Verified (gates, smoke, the Step 5 grep output).

### Task 2.2: Move the continuation model from `vcpu_loop/` into `kernel/`

**Files:**
- Move: `vcpu_loop/continuation.rs` (2,419 lines; 0 `hvpatch`/`trap`/VMM refs) → `kernel/continuation.rs`; `vcpu_loop/continuation/wait_service.rs` (1,783 lines; 0 such refs) → `kernel/continuation/wait_service.rs`
- Stay in the carrier: `vcpu_loop/continuation/quantum.rs` (1,587 lines; `crate::hvpatch` ×19, `crate::trap` ×42 — executor quantum accounting). Deferred to Task 2.5: `vcpu_loop/continuation/readiness.rs` (877 lines; `crate::host_signal` ×4 — moves once `host_signal` is a bridge). `vcpu_loop/continuation/tests.rs` (6,555 lines) is split by the same rule: tests of moved code move, tests naming `hvpatch`/`host_signal`/executor internals stay.
- Move: the `#[cfg(test)]` modules in `kernel/mm_access.rs` (L2622-3255) that name `carrick_vmm_hvf::trap::foreign_cow_test_support::{ProductionCarrierForeignCowHarness, TEST_VA}`, and the three tests naming `crate::hvpatch::Stage1MmPool::new_root_for_tests` (L2453, L2554, L2639 on 2026-09-16) → `vcpu_loop/memory.rs` tests (they test the carrier's foreign-COW projection; a kernel test module may not name a VMM crate even as a dev-dependency)
- Modify: `vcpu_loop/mod.rs`, `vcpu_loop/memory.rs:156` (`KernelForeignCowProof`, `pub(crate)`), `kernel/mod.rs`, 62 kernel sites

**Interfaces:**
- Produces: `crate::kernel::continuation::{CancellationCause, BlockedContinuation, ContinuationEvent, ContinuationRegistration, ContinuationId, ContinuationDiagnostic, CancellationReceipt}` and `crate::kernel::KernelForeignCowProof`. `vcpu_loop` imports downward.

- [ ] **Step 1:** Re-measure per file: `for f in vcpu_loop/continuation.rs vcpu_loop/continuation/*.rs; do printf "%-40s hvpatch=%s trap=%s host_signal=%s vmm=%s\n" $f $(grep -c crate::hvpatch $f) $(grep -c crate::trap $f) $(grep -c crate::host_signal $f) $(grep -c 'carrick_vmm_hvf\|applevisor\|hv_' $f); done`. Expected (2026-09-15): `continuation.rs` 0/0/0/0, `wait_service.rs` 0/0/0/0, `readiness.rs` 0/0/4/0, `quantum.rs` 19/42/0/0. Read how `continuation.rs` declares its submodules (`grep -n "^mod \|^pub mod " vcpu_loop/continuation.rs`); `quantum` and `readiness` must be re-declared from `vcpu_loop/mod.rs` after the move.
- [ ] **Step 2: Move and re-point**

```bash
cd crates/carrick-runtime/src
mkdir -p kernel/continuation
git mv vcpu_loop/continuation.rs kernel/continuation.rs
git mv vcpu_loop/continuation/wait_service.rs kernel/continuation/wait_service.rs
# quantum.rs and readiness.rs stay under vcpu_loop/continuation/ for now;
# tests.rs is split in Step 3.
grep -rl "crate::vcpu_loop::continuation" . | xargs sed -i '' 's/crate::vcpu_loop::continuation/crate::kernel::continuation/g'
```

Then fix the `mod` declarations so `crate::vcpu_loop::continuation::{quantum, readiness}` still resolve from the carrier side (declare them in `vcpu_loop/mod.rs` as `pub mod continuation { pub mod quantum; pub mod readiness; }` with `#[path]` attributes pointing at the existing files) and `crate::kernel::continuation::wait_service` resolves from the kernel side. Any `super::` reference inside `quantum.rs`/`readiness.rs` that reached the moved types becomes `crate::kernel::continuation::…`.

- [ ] **Step 3:** For every `crate::vcpu_loop::X` still named inside `kernel/continuation.rs` or `kernel/continuation/wait_service.rs` (`grep -n "vcpu_loop::" kernel/continuation.rs kernel/continuation/wait_service.rs`): X is executor-side. Replace with a trait `ContinuationExecutor` defined in `continuation.rs` whose methods are exactly the calls made, implemented in `vcpu_loop/`. The seven `*_for_test` helpers the kernel names from `vcpu_loop` (`kernel_frame_cow_authority_for_test`, `foreign_cow_task_binding_for_test`, `foreign_cow_handshake_test_lock`, `enter_hvpatch_guest_or_service_invalidation_for_test`, `fixed_frame_cow_owner_inventory_for_test`, `with_real_pt_pause_for_test`) are called from `kernel/tests.rs`; those tests move, body unchanged, to the `vcpu_loop` test module (they test the carrier's projection). The same applies to the nine `kernel/mm_access.rs` test sites naming `carrick_vmm_hvf::trap::foreign_cow_test_support`: they move to `vcpu_loop/memory.rs`'s test module. Split `vcpu_loop/continuation/tests.rs`: tests that exercise only moved types go to `kernel/continuation/tests.rs`; tests naming `hvpatch`, `host_signal` or executor internals stay.
- [ ] **Step 4:** `KernelForeignCowProof` (`vcpu_loop/memory.rs:156`, `pub(crate) struct`): if it holds only kernel identities (mm id, owner generation) it moves to `kernel/mm_proof.rs`; if it holds a stage-1 handle it becomes `Stage1MmProjection::CowProof` in Task 2.3.
- [ ] **Step 5: Verify.** `grep -rn "crate::vcpu_loop\|carrick_vmm_hvf" crates/carrick-runtime/src/kernel` → no output.
- [ ] **Step 6: Gate + commit** `refactor(runtime): the continuation model and wait service are kernel state, not executor state`.

### Task 2.3: `Stage1MmProjection` — the stage-1 mm seam as a `carrick-hal` trait

**Files:**
- Create: `crates/carrick-hal/src/stage1_mm.rs`
- Modify: `crates/carrick-hal/src/lib.rs`, the five `Stage1MmLease` sites in `dispatch/` (`mm_authority.rs:180`, `mm_mutation.rs:212,222` and two more — re-measure with `grep -rn Stage1MmLease crates/carrick-runtime/src/dispatch`), `CarrierProcess::stage1_mm_lease`'s return type (Task 2.15), `hvpatch/stage1_mm.rs` (impl)

**Interfaces:**
- Produces: `carrick_hal::stage1_mm::Stage1MmProjection` (object-safe, `Send + Sync`). `DispatchMmAuthority` and `MmMutationCoordinator` hold `Arc<dyn Stage1MmProjection>`; `hvpatch::Stage1MmLease` implements it. **Public surface item**: an external backend implements this trait.

- [ ] **Step 1: Enumerate the exact surface dispatch uses**

```bash
cd crates/carrick-runtime/src/dispatch
grep -nE "stage1[A-Za-z_]*\.[a-z_]+\(|Stage1MmLease::" mm_authority.rs mm_mutation.rs mem/*.rs | sed -E 's/.*(stage1[A-Za-z_]*\.[a-z_]+|Stage1MmLease::[a-z_]+).*/\1/' | sort | uniq -c
```

Write the trait with exactly those methods, same names, same argument and return types, one doc line each copied from the lease. A method whose signature names an HVF type (`hv_vm_t`, an `applevisor` handle, a `carrick_vmm_hvf` struct) is not part of the seam: dispatch must be calling it through a kernel-level notion (`Ipa`, `GuestVa` range, owner generation). If it isn't, **stop and report**: that is the load-bearing finding and the owner decides.

```rust
//! The stage-1 mm projection a kernel-level mm mutation consumes. Implemented
//! by the carrier's `Stage1MmLease` (HVPatch on HVF today; any execution
//! backend tomorrow). The kernel never names the implementation.
pub trait Stage1MmProjection: Send + Sync {
    /// Exact owner generation this projection was authenticated against.
    fn owner_generation(&self) -> OwnerGeneration;
    // … one method per line of the Step 1 enumeration, verbatim signatures …
}
```

- [ ] **Step 2:** Replace every `Arc<crate::hvpatch::Stage1MmLease>` in dispatch (five sites + the `CarrierProcess::stage1_mm_lease` return type) with `Arc<dyn Stage1MmProjection>`; `impl Stage1MmProjection for Stage1MmLease` in `hvpatch/stage1_mm.rs`, forwarding.
- [ ] **Step 3:** If Task 2.1/2.2 deferred `ForeignMmInstallPermit`/`KernelForeignCowProof`, make them associated types here.
- [ ] **Step 4: Verify.** `grep -rn "crate::hvpatch" crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/kernel` → no output.
- [ ] **Step 5: Gate + commit** `refactor(hal): dispatch consumes the stage-1 mm through Stage1MmProjection` (also `python3 scripts/migrate/check-mm-authority.py --check`).

### Task 2.4: Quiesce and identity-page helpers dispatch takes from `vcpu_loop`

**Files:**
- Modify: 12 dispatch sites naming `crate::vcpu_loop::{with_sole_mm_stage, stamp_identity_page, quiesce::{FrameCowExactMmGuard, SoleMmStage, PtPauseGuard}, with_foreign_mm_mutation_guard, with_real_pt_pause_for_test}` and 5 naming `{ns_visible_guest_tid, is_default_ignore_signal, upgrade_protection_si_code}`
- Modify: `crates/carrick-hal/src/stage1_mm.rs`, `kernel/`

- [ ] **Step 1:** The three pure helpers (`ns_visible_guest_tid`, `is_default_ignore_signal`, `upgrade_protection_si_code`) compute from kernel state and ABI tables: move each into the kernel module owning its input; re-point `vcpu_loop` and `dispatch`.
- [ ] **Step 2:** The quiesce entry points become `Stage1MmProjection` methods:

```rust
    /// Run `f` with this mm as the sole runnable stage (page-table pause).
    fn with_sole_mm_stage(&self, f: &mut dyn FnMut(&dyn SoleMmStage)) ;
    /// Pause page-table mutation on this mm for the guard's lifetime.
    fn pause_pt(&self) -> Box<dyn PtPause + '_>;
    /// Stamp the identity page for a task after exec/clone publication.
    fn stamp_identity_page(&self, task: TaskKey, page: IdentityPageContents) -> Result<(), Stage1Error>;
```

`SoleMmStage`, `PtPause`, `FrameCowExactMm` become hal traits with the methods the 12 sites call on the guards (read them). A generic-over-`R` closure becomes `&mut dyn FnMut` with the result written through a captured `Option<R>` at the call site, to keep the trait object-safe.
- [ ] **Step 3: Verify.** `grep -rn "crate::vcpu_loop" crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/kernel` → no output.
- [ ] **Step 4: Gate + commit** `refactor(runtime): dispatch reaches page-table quiesce only through Stage1MmProjection`.

### Task 2.5: `HostSignalBridge` and `GuestTimerBridge` — the host-signal and timer seams

On macOS `crate::host_signal`, `crate::io_wait`, `crate::itimer`, `crate::posix_timer` are `pub use carrick_vmm_hvf::{…}` (`lib.rs:179`); on Linux they are inline modules in `lib.rs:431-1787`. Dispatch calls **73** functions on them: the largest hidden VMM dependency in dispatch, and the reason `lib.rs` is 1,809 lines. For an external backend these two traits are where it plugs in its own signal delivery and timers — the honest form of the proposal's `SignalTransport`.

**Files:**
- Create: `crates/carrick-hal/src/host_signal_bridge.rs`, `crates/carrick-hal/src/guest_timer_bridge.rs`
- Modify: `crates/carrick-runtime/src/lib.rs`, `crates/carrick-vmm-hvf/src/{host_signal,io_wait,itimer,posix_timer}.rs` (impls), `carrick-vmm-kvm` (impls over the Linux bodies moved out of `lib.rs`), `dispatch/` (73 sites), `SyscallDispatcher` (two `Arc<dyn …>` fields)

**Interfaces:**
- Produces (argument and return types are **the types the free functions take today**; copy each from `grep -n "pub fn <name>" crates/carrick-vmm-hvf/src/{host_signal,io_wait,itimer,posix_timer}.rs`; a bare `i32` stays bare here, typing is a follow-up):

```rust
// carrick_hal::host_signal_bridge
pub trait HostSignalBridge: Send + Sync {
    fn has_unblocked_pending_for(&self, task: TaskKey, blocked: SigBlockMask) -> bool;
    fn has_process_pending(&self, task: TaskKey) -> bool;
    fn take_pending_for(&self, task: TaskKey) -> Option<PendingSignal>;
    fn take_pending_in_for(&self, task: TaskKey, set: SigSet) -> Option<PendingSignal>;
    fn publish_pending_for(&self, task: TaskKey, signal: PendingSignal);
    fn publish_process_signal(&self, process: TaskKey, signal: PendingSignal);
    fn last_sender_for(&self, task: TaskKey) -> Option<SenderIdentity>;
    fn raise_for_self(&self, signal: Signal) -> Result<(), LinuxErrno>;
    fn wake_all_waiters(&self, process: TaskKey);
    fn ensure_host_handler(&self, signal: Signal);
    fn set_host_ignore(&self, signal: Signal);
    fn set_host_default(&self, signal: Signal);
    fn reset_routed_handlers_after_execve(&self, task: TaskKey);
    fn relocate_internal_fd(&self, from: HostFd, to: HostFd);
    fn xsig_enqueue(&self, target: TaskKey, signal: PendingSignal) -> Result<(), LinuxErrno>;
    fn xsig_nudge(&self, target: TaskKey);
    fn xsig_drain_for_self(&self) -> Vec<PendingSignal>;
    fn host_to_linux_signum(&self, host: i32) -> Option<Signal>;
    fn linux_to_host_signum(&self, signal: Signal) -> Option<i32>;
    fn is_internal_kick_signal(&self, host: i32) -> bool;
}
pub const NO_PENDING_SIGNAL: … ; // moved from host_signal

// carrick_hal::guest_timer_bridge
pub trait GuestTimerBridge: Send + Sync {
    fn itimer_arm(&self, task: TaskKey, which: ItimerWhich, value: ItimerSpec) -> Result<ItimerSpec, LinuxErrno>;
    fn itimer_disarm(&self, task: TaskKey, which: ItimerWhich) -> ItimerSpec;
    fn itimer_signum_for(&self, which: ItimerWhich) -> Signal;
    fn itimer_spawn_fallback_timer(&self, task: TaskKey);
    fn posix_create_with_target_and_value(&self, spec: PosixTimerSpec) -> Result<TimerId, LinuxErrno>;
    fn posix_arm(&self, id: TimerId, value: ItimerSpec, flags: TimerFlags) -> Result<ItimerSpec, LinuxErrno>;
    fn posix_remaining(&self, id: TimerId) -> Option<ItimerSpec>;
    fn posix_getoverrun(&self, id: TimerId) -> Option<u32>;
    fn posix_seed_overrun(&self, id: TimerId, count: u32);
    fn posix_exists(&self, id: TimerId) -> bool;
    fn posix_clock_id(&self, id: TimerId) -> Option<GuestClockId>;
    fn posix_delete(&self, id: TimerId) -> Result<(), LinuxErrno>;
    fn deliver(&self, task: TaskKey, event: TimerEvent);
    fn delivery(&self) -> &dyn TimerDelivery;
}
```

Also in `carrick-hal`, behind `feature = "test-support"`: `NullHostSignalBridge` and `NullGuestTimerBridge` (every method a no-op / `None` / `Ok(default)`), used by `SyscallDispatcher::new()` in tests and by the example backend.

- [ ] **Step 1:** Write both traits with the copied signatures. `io_wait::WaitFd` is a type: move its definition to `carrick-hal` if it names no HVF type; else it becomes an associated type.
- [ ] **Step 2:** `impl HostSignalBridge for HvfHostSignal` (unit struct in `carrick-vmm-hvf/src/host_signal.rs`) forwarding to the existing free functions; the Linux bodies leave `lib.rs` for `carrick-vmm-kvm/src/host_signal.rs` etc. and get the same impls. Same for `GuestTimerBridge`.
- [ ] **Step 3:** `SyscallDispatcher` gains `host_signal: Arc<dyn HostSignalBridge>` and `timers: Arc<dyn GuestTimerBridge>`; production construction passes the real bridges where the dispatcher is built today (`grep -rn "SyscallDispatcher::new\|SyscallDispatcher::with" crates/carrick-runtime/src/{carrier,vcpu_loop,runtime,prepare}*`); `SyscallDispatcher::new()` becomes the test/test-support constructor with the Null bridges and changes no test assertion.
- [ ] **Step 4:** Re-point the 73 dispatch sites to `self.host_signal.…` / `self.timers.…` by compiler error.
- [ ] **Step 5:** Delete the inline modules and the `pub use carrick_vmm_hvf::{…}` from `lib.rs`; `lib.rs` is now under ~400 lines.
- [ ] **Step 5b:** `git mv vcpu_loop/continuation/readiness.rs kernel/continuation/readiness.rs` (its 4 `crate::host_signal` calls now go through the bridge); re-declare the module on the kernel side; move its tests from `vcpu_loop/continuation/tests.rs` with it.
- [ ] **Step 6: Verify.** `grep -rn "crate::\(host_signal\|io_wait\|itimer\|posix_timer\|timer_delivery\)" crates/carrick-runtime/src/dispatch crates/carrick-runtime/src/kernel` → none; `grep -rn "carrick_vmm_hvf" crates/carrick-runtime/src/{dispatch,kernel,namespace,network,file_authority}` → none.
- [ ] **Step 7: Gate, signal smoke, commit**

Run: `just ci && just build && scripts/conformance/smoke-two-process.sh && CARRICK_RUN_ID=t25 target/release/carrick run --rm ubuntu:24.04 sh -c 'trap "echo alarm" ALRM; (sleep 0.3; kill -ALRM $$) & sleep 1; echo done'` → `alarm` then `done`.

```bash
git add -A
git commit -m "refactor(hal): dispatch reaches host signals and guest timers through hal bridges

Why: on macOS crate::host_signal / io_wait / itimer / posix_timer were
re-exports of carrick-vmm-hvf, so 73 dispatch call sites named the HVF
crate through an alias, and on Linux the same names were 1,400 lines of
inline modules in lib.rs. The public carrick-kernel crate must consume
these through traits an external backend can implement -- the shape
TimerDelivery already has.

What: HostSignalBridge and GuestTimerBridge in carrick-hal with the exact
function set dispatch calls; HVF and KVM lanes implement them over their
existing bodies; SyscallDispatcher holds Arc<dyn ..> set by the carrier,
Null bridges under test-support. lib.rs loses its inline modules. No
behaviour change.

Verified: just ci; signed two-process smoke; SIGALRM delivery smoke."
```

### Task 2.6: `HVF_PAGE_SIZE` becomes `carrick_guest_mem::HOST_PAGE_GRANULE`

- [ ] **Step 1:** In `crates/carrick-guest-mem/src/lib.rs`: `pub const HOST_PAGE_GRANULE: u64 = 0x4000; // 16 KiB: the host page granule every lane shares today.` If any lane actually differs, this is not a constant; stop and report.
- [ ] **Step 2:** `grep -rl "crate::trap::HVF_PAGE_SIZE" crates/carrick-runtime/src/dispatch | xargs sed -i '' 's/crate::trap::HVF_PAGE_SIZE/carrick_guest_mem::HOST_PAGE_GRANULE/g'`; define the carrier's `HVF_PAGE_SIZE` as `carrick_guest_mem::HOST_PAGE_GRANULE` in both arms.
- [ ] **Step 3:** Remaining `crate::trap::*` in dispatch/kernel (`RawSyscall`, `SyscallTrap`, `TrapError`, `host_clock_uptime_ns`, `shared_file_key_base`, `shared_futex_waiter_key`) are `carrick_hal`/`carrick_host` re-exports: re-point to the leaf crate. `grep -rn "crate::trap" crates/carrick-runtime/src/{dispatch,kernel}` → none.
- [ ] **Step 4:** `just check && just clippy`; commit `refactor(runtime): dispatch names the host page granule, not HVF_PAGE_SIZE`.

### Task 2.7: `container.rs`, `carrier::ContainerTeardown`, `pty_relay::PtyPair`, `runtime::DEFAULT_MAX_TRAPS`

- [ ] **Step 1:** `DEFAULT_MAX_TRAPS` moves from `runtime.rs` to `run_state.rs`; `runtime.rs` imports it.
- [ ] **Step 2:** `pty_relay.rs` (L31, L81) and `exec_helpers.rs` (L11) mention `applevisor`/`carrick_vmm_hvf` in **comments only** (verified 2026-09-15: `grep -n "carrick_vmm_hvf\|applevisor" pty_relay.rs exec_helpers.rs` shows `//` lines). Reword the comments so a grep for VMM names in the kernel crate stays clean; no code change.
- [ ] **Step 3:** `carrier::ContainerTeardown` (4 kernel sites): if a receipt/state record, move to `kernel/control/teardown.rs`; if it holds carrier handles, invert via `trait ContainerTeardownSink` defined in the kernel, implemented by the carrier.
- [ ] **Step 4:** (folded into Step 2.)
- [ ] **Step 5: Verify the whole moving set names no carrier module**

```bash
cd crates/carrick-runtime/src
grep -rn "crate::\(hvpatch\|vcpu_loop\|carrier\|threaded_loop\|execute\|prepare\|runtime\|interactive_supervisor\|host_process\|dtrace_consumer\|dtrace_symbols\|debug_state\|binfmt\|trap\|host_signal\|io_wait\|itimer\|posix_timer\|timer_delivery\)\b" \
  kernel dispatch namespace network file_authority vfs container.rs container_policy.rs event_ring.rs observe seccomp.rs inotify.rs fanotify.rs keyring.rs cred_ipc.rs core_dump.rs host_tty.rs pty_relay.rs page_profile.rs eventfd_shm.rs run_result.rs run_state.rs syslog.rs exec_stamps.rs exec_helpers.rs deadlock_watchdog.rs
grep -rln "carrick_vmm_hvf\|applevisor" kernel dispatch namespace network file_authority vfs container.rs pty_relay.rs exec_helpers.rs
```

Both empty. `crate::execute`/`crate::runtime` residue is a constant or error type that belongs in `run_result.rs`/`run_state.rs`: move it down.
- [ ] **Step 6:** Gate + commit `refactor(runtime): the kernel moving set names no carrier module`.

### Task 2.8: `SyscallDispatcher` construction takes the carrier's bridges explicitly

- [ ] **Step 1:** Production constructor becomes `SyscallDispatcher::with_bridges(bridges: CarrierBridges)`:

```rust
/// Everything the execution backend supplies to the kernel at construction.
pub struct CarrierBridges {
    pub host_signal: Arc<dyn HostSignalBridge>,
    pub timers: Arc<dyn GuestTimerBridge>,
}
```

`SyscallDispatcher::new()` stays **only** under `#[cfg(any(test, feature = "test-support"))]` with the Null bridges (59 test modules call it). The carrier is the only production caller.
- [ ] **Step 2:** `just check && just clippy && RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib`; commit `refactor(runtime): the execution backend hands the dispatcher its bridges at construction`.

### Task 2.9: Create `crates/carrick-kernel` and `git mv` the kernel moving set

**Files:**
- Create: `crates/carrick-kernel/Cargo.toml`, `crates/carrick-kernel/src/lib.rs`
- Move: `kernel/`, `dispatch/`, `namespace/`, `network/`, `file_authority/`, `observe/`, `vfs/{mod,proc,sys,dev,devpts}.rs`, `container.rs`, `container_policy.rs`, `event_ring.rs`, `seccomp.rs`, `inotify.rs`, `fanotify.rs`, `keyring.rs`, `cred_ipc.rs`, `core_dump.rs`, `host_tty.rs`, `pty_relay.rs`, `page_profile.rs`, `eventfd_shm.rs`, `run_result.rs`, `run_state.rs`, `syslog.rs`, `exec_stamps.rs`, `exec_helpers.rs`, `deadlock_watchdog.rs`
- Modify: `crates/carrick-runtime/Cargo.toml`, `crates/carrick-runtime/src/lib.rs`, every `crate::<moved>::` in the carrier, `carrick-embed`/`carrick-cli` manifests and imports, `justfile`, `.semgrep/typed-domains.yml`, `scripts/migrate/check-*.py`, `scripts/conformance/check-next-strategy.py`

**Interfaces:**
- Produces: `carrick_kernel::{kernel, dispatch, namespace, network, file_authority, observe, vfs, container, container_policy, event_ring, seccomp, inotify, fanotify, keyring, cred_ipc, core_dump, host_tty, pty_relay, page_profile, eventfd_shm, run_result, run_state, syslog, exec_stamps, exec_helpers, deadlock_watchdog}` at the same relative paths (`carrick_runtime::kernel::control::send` → `carrick_kernel::kernel::control::send`; the `kernel::kernel` doubling is accepted for path stability and may be flattened later as its own change).

- [ ] **Step 1: Manifest**: copy `carrick-runtime/Cargo.toml`'s `[dependencies]` **minus** `carrick-vmm-*`, the optional VMM edges, `applevisor*`, `mach2`, `carrick-aarch64`, **plus** `carrick-vfs`, `carrick-kernel-arena`. Features: `syscall-shim`, `fs-memory` (forwards to `carrick-vfs`), the `trace-*` gates the moved code names (`grep -rhoE 'feature = "[a-z-]+"' <moving set> | sort -u`), `test-support` (enables `carrick-hal/test-support`, the Null bridges, `SyscallDispatcher::new`, `process_context_for_tests`). No `platform-*` features: host-OS glue arrives through `carrick-host-bsd`/`-linux` by `cfg(target_os)` tables as in the `carrick-vfs` manifest.
- [ ] **Step 2: Move**

```bash
mkdir -p crates/carrick-kernel/src
cd crates/carrick-runtime/src
for d in kernel dispatch namespace network file_authority observe vfs; do git mv $d ../../carrick-kernel/src/$d; done
for f in container container_policy event_ring seccomp inotify fanotify keyring cred_ipc core_dump host_tty pty_relay page_profile eventfd_shm run_result run_state syslog exec_stamps exec_helpers deadlock_watchdog; do git mv $f.rs ../../carrick-kernel/src/$f.rs; done
```

`carrick-kernel/src/lib.rs` declares each `pub mod`, plus the leaf-crate aliases the moved code relies on (`pub use carrick_abi as linux_abi; pub use carrick_mem::{elf, memory, page_table, vdso, shared_aperture}; pub use carrick_thread::{fork_quiesce, thread}; pub use carrick_host::{guest_cpu, host_facts, host_mapping, host_proc, ulock}; pub use carrick_observability::{compat, probes, vm_lifecycle}; pub use carrick_abi::syscall;` and the `host_to_linux_errno` cfg pair). Those are aliases of leaf crates inside the new crate, not shims of the old one. Its crate doc is written in Task 2.12.
- [ ] **Step 3: Re-point the carrier**: replace `crate::<moved>::` with `carrick_kernel::<moved>::` for every moved module name (one `sed` over the list); delete the `pub mod` lines from `lib.rs`; add `carrick-kernel = { path = "../carrick-kernel" }`. `lib.rs` keeps only what the carrier owns.
- [ ] **Step 4: Bridges**: the traits are in `carrick-hal`, so `carrick-vmm-*` depend only on `carrick-hal`. `just check-layering` verifies both directions.
- [ ] **Step 5: Consumers**: `carrick-embed`, `carrick-cli` add `carrick-kernel`; re-point `carrick_runtime::{container, kernel, observe, network, run_result, run_state, event_ring}` → `carrick_kernel::…` (`dtrace_consumer`, `Runtime`, `carrier`, `prepare`, `host_process` stay in the runtime). `RuntimeError`: if defined in `run_result.rs` it is `carrick_kernel::run_result::RuntimeError`.
- [ ] **Step 6: Inventories, lint paths, justfile**

```bash
python3 scripts/migrate/reconcile-line-pinned-inventories.py --rehome \
  $(for d in kernel dispatch namespace network file_authority observe vfs; do printf -- "--rename crates/carrick-runtime/src/%s=crates/carrick-kernel/src/%s " $d $d; done) \
  $(for f in container container_policy event_ring seccomp inotify fanotify keyring cred_ipc core_dump host_tty pty_relay page_profile eventfd_shm run_result run_state syslog exec_stamps exec_helpers deadlock_watchdog; do printf -- "--rename crates/carrick-runtime/src/%s.rs=crates/carrick-kernel/src/%s.rs " $f $f; done)
```

`.semgrep/typed-domains.yml`: `crates/carrick-runtime/src/dispatch/**` → `crates/carrick-kernel/src/dispatch/**` (and `retval.rs`). Every `PurePosixPath("crates/carrick-runtime/src/(dispatch|kernel|file_authority)/…")` in `scripts/migrate/check-*.py`. `justfile` `test`: add `--exclude carrick-kernel` to the parallel line and `env RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib --features test-support {{ARGS}}` beside the runtime line with the same fork-from-harness comment. `test-integration`: `carrick-runtime/tests/integration/*` that test only kernel/dispatch behaviour move to `carrick-kernel/tests/`.
- [ ] **Step 7: Gate ladder + layering + signed smoke.** `just check-layering && just ci && just build && scripts/conformance/smoke-two-process.sh` → `carrick-vfs ok`, `carrick-kernel ok`, every `carrick-vmm-* ok`, ci green, smoke ok; `strings target/release/carrick | grep -c carrick_kernel` > 0; `otool -l target/release/carrick | grep -c dof` > 0.
- [ ] **Step 8: Docs**: `crates/README.md` rows and product path (`carrick-cli -> carrick-engine -> { carrick-image, carrick-runtime -> carrick-kernel -> carrick-vfs } -> carrick-spec`); AGENTS.md "Where key subsystems live" paths (`crates/carrick-kernel/src/dispatch/mod.rs`, `…/fs.rs`, `…/signal.rs`, `…/net.rs`, `…/event_ring.rs`, `…/pty_relay.rs`, `crates/carrick-kernel/src/vfs/devpts.rs`, `crates/carrick-vfs/src/…`); `docs/hal.md` gains the three traits.
- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "refactor: extract carrick-kernel, the Carrick kernel, from the HVPatch carrier

Why: after the seam commits (process-lifecycle types, continuation model,
Stage1MmProjection, HostSignalBridge/GuestTimerBridge, page granule,
container/teardown) the kernel graph, syscall dispatch and every in-zone
subsystem named no carrier or VMM module. Keeping them in one crate with the
HVF carrier meant every kernel edit relinked the carrier, every alternate
lane compiled HVF-adjacent code, and no external execution backend could
reuse the kernel at all.

What: git mv of kernel/, dispatch/, namespace/, network/, file_authority/,
observe/, the kernel-view vfs (proc/sys/dev/devpts) and <N> single-file
subsystems into crates/carrick-kernel. carrick-runtime keeps hvpatch/,
vcpu_loop/, carrier, threaded_loop, execute, prepare, runtime, the
supervisors and the bins, and implements the hal bridges. Consumers import
carrick_kernel directly; nothing is re-exported from the runtime.
Inventories rehomed with --rename; semgrep and migrate checkers re-scoped;
just test runs carrick-kernel serially (it forks from the harness).

Verified: just check-layering (no runtime/vmm crate in the kernel closure;
no kernel in any vmm closure), just ci, signed two-process smoke, USDT
section present."
```

### Task 2.10: Off-macOS compile of the kernel

- [ ] **Step 1:** `rustup target add aarch64-unknown-linux-gnu && cargo check -p carrick-kernel --features test-support --target aarch64-unknown-linux-gnu` → clean. The whole emulation core builds with no VMM in its closure on a host that has none.
- [ ] **Step 2:** `cargo check -p carrick-cli --no-default-features --features platform-linux --target aarch64-unknown-linux-gnu && scripts/closure-assert-no-hvf.sh` → clean, unchanged from before the plan.
- [ ] **Step 3:** Add Step 1 as `just check-kernel-portable`, in `ci` after `check-layering`. Commit `ci: compile the kernel crate for a VMM-less target in just ci`.

### Task 2.11: Public surface — README and crate docs for `carrick-kernel`

**Files:**
- Create: `crates/carrick-kernel/README.md`
- Modify: `crates/carrick-kernel/src/lib.rs` (crate doc), `crates/carrick-kernel/src/dispatch/outcome.rs` (every `DispatchOutcome` variant has a doc line saying what the backend must do)

- [ ] **Step 1: README** with these sections, in this order: *What this is* (the Carrick kernel; no guest Linux kernel; experimental, partial coverage, not a trust boundary); *Stability* ("Experimental. No semver. The API changes without notice; pin a git rev. `publish = false`."); *What a backend supplies* (implement `carrick_hal::{Stage1MmProjection, HostSignalBridge, GuestTimerBridge}`, a `GuestMemory + CurrentMmMemory` over your guest's address space, a trap source producing `SyscallRequest`); *What a backend interprets* (the `DispatchOutcome` table: variant → backend obligation, generated from the enum docs; `Fork`, `Execve`, `CloneThread`, `ThreadExit`, `Exit`, `SignalThread`, `WaitOnHvpatchChild`, `WaitOnFds`, `WaitOnSignals`, `WaitOnSleep`, `WaitOnSharedWord`, `FutexWait*`, `SigReturn`, `SetMemoryModel`, `MapHostAlias` — the retired-lane `WaitOnProcExit`/`WaitOnProcState` no longer exist after Task 0.3); *Bootstrap* (`Kernel::bootstrap_root(RootBootstrap)` → `KernelContext`; `SyscallDispatcher::with_bridges(CarrierBridges)`; `dispatcher.dispatch(&ctx, request, &mut memory, &reporter)`); *The example* (`crates/carrick-kernel-example`, "start here"); *What is deliberately not public* (the HVPatch carrier, vCPU executors, stage-1 tables: `carrick-runtime`).
- [ ] **Step 2: Crate doc** in `lib.rs`: the README's first two sections verbatim as `//!`, plus "Modules a backend uses: `dispatch`, `kernel`, `observe`. Modules a backend may ignore: everything else (they are `pub` because dispatch is one crate, not because they are stable)."
- [ ] **Step 3: `DispatchOutcome` docs**: each variant gets `/// Backend: <one sentence obligation>` (e.g. `Fork`: "Backend: publish the prepared fork through `kernel::operations::PreparedFork::commit`, then start executing the child task at the returned frame; see `carrick-kernel-example/src/scripted.rs::on_fork`"). `just doc` (`-D warnings`) gates it.
- [ ] **Step 4:** `just doc && just check`; commit `docs(kernel): README, crate doc and per-outcome backend obligations for carrick-kernel`.

### Task 2.12: `carrick-kernel-example` — a backend with no VM, proving the public surface

**Files:**
- Create: `crates/carrick-kernel-example/Cargo.toml`, `src/lib.rs`, `src/memory.rs`, `src/scripted.rs`, `tests/fork_pipe_wait.rs`
- Modify: `justfile` (`test` runs it in the parallel workspace line, which it joins automatically as a member; `check-layering` already guards it)

**Interfaces:**
- Consumes (all `pub`): `carrick_kernel::dispatch::{SyscallDispatcher, SyscallRequest, SyscallArgs, DispatchOutcome, CarrierBridges}`, `carrick_kernel::kernel::{Kernel, RootBootstrap, KernelContext, TaskKey, operations::PreparedFork}`, `carrick_hal::{NullHostSignalBridge, NullGuestTimerBridge, Stage1MmProjection}`, `carrick_guest_mem::{GuestMemory, CurrentMmMemory, LinearMemory}`, `carrick_abi::syscall` numbers.
- Produces: `carrick_kernel_example::ScriptedBackend` — one host thread per Linux task, each running a `Vec<Step>` of syscalls against the shared dispatcher; interprets `Returned`, `Errno`, `Exit`, `Fork`, `WaitOnHvpatchChild`, `WaitOnFds`, `SchedulerYield` (`WaitOnProcExit`/`WaitOnProcState` were deleted in Task 0.3 as zero-producer retired-lane residue). Anything else → `Err(Unsupported(outcome))`.

- [ ] **Step 1: Write the failing test**

```rust
// crates/carrick-kernel-example/tests/fork_pipe_wait.rs
use carrick_kernel_example::{ScriptedBackend, Step, Sys};

#[test]
fn fork_pipe_wait_through_the_public_surface() {
    // Parent: pipe2 -> fork -> (child: write "hi", exit 7) -> read -> wait4 -> exit.
    let script = vec![
        Step::sys(Sys::Pipe2 { flags: 0 }),                       // returns fds into slot 0/1
        Step::sys(Sys::Fork),                                       // child continues at Step::child_marker
        Step::child_marker(vec![
            Step::sys(Sys::Write { fd: Step::slot(1), data: b"hi".to_vec() }),
            Step::sys(Sys::ExitGroup { code: 7 }),
        ]),
        Step::sys(Sys::Read { fd: Step::slot(0), len: 2 }),        // expect "hi"
        Step::sys(Sys::Wait4 { pid: Step::last_child(), options: 0 }),
        Step::sys(Sys::ExitGroup { code: 0 }),
    ];
    let run = ScriptedBackend::new().run_root(script).expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.read_results(), vec![b"hi".to_vec()]);
    assert_eq!(run.wait_statuses(), vec![7 << 8]);   // WEXITSTATUS(7)
    assert_eq!(run.tasks_started(), 2);
}
```

- [ ] **Step 2: Run it; it fails to compile** (`cargo test -p carrick-kernel-example --test fork_pipe_wait` → no such crate).

- [ ] **Step 3: Manifest**

```toml
[package]
name = "carrick-kernel-example"
version.workspace = true
edition.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
carrick-kernel = { path = "../carrick-kernel", features = ["test-support"] }
carrick-hal = { path = "../carrick-hal", features = ["test-support"] }
carrick-guest-mem = { path = "../carrick-guest-mem" }
carrick-abi = { path = "../carrick-abi" }
anyhow.workspace = true
parking_lot.workspace = true
thiserror.workspace = true
```

`carrick-vfs` is reached through `carrick-kernel`'s public re-exports only if the example needs a rootfs; the pipe test does not.

- [ ] **Step 4: `src/memory.rs`**: a `GuestMemory + CurrentMmMemory` over a `Vec<u8>` per task, mirroring the `LinearMemory` shape `carrick debug dispatch-syscall` uses (`crates/carrick-cli/src/commands.rs:~750`, inside the `Commands::DispatchSyscall` arm at L735). If `LinearMemory` is already `pub` in `carrick-guest-mem`, use it and delete this file.

- [ ] **Step 5: `src/scripted.rs`**: the backend.

```rust
pub struct ScriptedBackend {
    dispatcher: Arc<SyscallDispatcher>,
}

impl ScriptedBackend {
    pub fn new() -> Self {
        let bridges = CarrierBridges {
            host_signal: Arc::new(NullHostSignalBridge),
            timers: Arc::new(NullGuestTimerBridge),
        };
        Self { dispatcher: Arc::new(SyscallDispatcher::with_bridges(bridges)) }
    }

    /// Bootstrap the root task exactly as `capture_one_task_context` does for
    /// `carrick debug dispatch-syscall`, then run `script` on the calling thread.
    pub fn run_root(self, script: Vec<Step>) -> Result<RunReport, ExampleError> { … }

    fn run_task(&self, ctx: KernelContext, memory: &mut ExampleMemory, script: &[Step], report: &Report) -> Result<(), ExampleError> {
        for step in script {
            let request = step.to_request(memory, report)?;
            let outcome = self.dispatcher.dispatch(&ctx, request, memory, &NoopReporter)?;
            match outcome {
                DispatchOutcome::Returned { value } => step.record(value, memory, report),
                DispatchOutcome::Errno(e) => return Err(ExampleError::Errno(step.name(), e)),
                DispatchOutcome::Exit { code, .. } => { report.exited(ctx.task().key(), code); return Ok(()); }
                DispatchOutcome::Fork { .. } => self.on_fork(&ctx, outcome, memory, step.child_script(), report)?,
                DispatchOutcome::WaitOnHvpatchChild { .. } => self.on_wait(&ctx, outcome, step, memory, report)?,
                DispatchOutcome::WaitOnFds { .. } => self.on_wait_fds(&ctx, outcome, step, memory, report)?,
                DispatchOutcome::SchedulerYield => std::thread::yield_now(),
                other => return Err(ExampleError::Unsupported(format!("{other:?}"))),
            }
        }
        Ok(())
    }
}
```

`on_fork` mirrors the carrier's `Fork` arm at `crates/carrick-runtime/src/vcpu_loop/exec.rs:2756` **using only `pub` kernel operations** (`kernel::operations::PreparedFork::commit` → `PublishedFork`, then the child's `KernelContext`); it clones the parent's `ExampleMemory`, spawns a thread running `run_task` on the child script, and records the child's pid for `Step::last_child()`. Every kernel item `exec.rs` uses that is `pub(crate)` today becomes `pub` with a doc line in this task's commit: that is the surface being discovered. `on_wait` re-dispatches the wait syscall after the child thread's exit is observed (the kernel's own wait continuation completes it; the example polls with `yield_now` bounded at 5 s so a lost wake is a test failure, not a hang). `on_wait_fds` likewise re-dispatches `read` once the writer thread has run.

- [ ] **Step 6: Run the test; it passes.** `cargo test -p carrick-kernel-example` → 1 passed.

- [ ] **Step 7: Gate**: `just check-layering` (`carrick-kernel-example ok`), `just ci` (it runs in the parallel `--workspace` line), `just doc`.

- [ ] **Step 8: README** for the example: "This is the template for a bring-your-own execution backend. It has no VM: tasks are host threads and guest memory is a `Vec<u8>`. What it implements is exactly what your backend must: construct the kernel with your bridges, translate your trap source into `SyscallRequest`, interpret every `DispatchOutcome` you meet. What it deliberately does not do: run real guest code, fork host processes, or emulate a CPU."

- [ ] **Step 9: Commit**

```bash
git add -A crates/carrick-kernel-example crates/carrick-kernel justfile
git commit -m "feat(kernel): carrick-kernel-example, a VM-less backend proving the public surface

Why: carrick-kernel is a public bring-your-own-execution-backend crate. A
crate whose pub items are whatever leaked from the monolith is not an API;
the only honest proof is a second backend built from pub items alone.

What: crates/carrick-kernel-example runs scripted Linux tasks on host
threads with Vec-backed guest memory and Null hal bridges, interpreting
Returned/Errno/Exit/Fork/WaitOnHvpatchChild/WaitOnFds/SchedulerYield. The
fork_pipe_wait test runs pipe2 -> fork -> child write+exit -> read -> wait4
through SyscallDispatcher with no VM. <N> kernel items became pub with docs
to make that possible: <list>. It does not fork host processes or run guest
code; that is what the retired 1:1 lane was and it is not coming back.

Verified: cargo test -p carrick-kernel-example; just check-layering shows
no runtime/vmm crate in its closure; just ci."
```

### Task 2.13: Phase 2 acceptance

- [ ] **Step 1:** Record binary identity exactly as in Task 1.5 Step 1.
- [ ] **Step 2:** `just conformance full`, then `just conformance-probes` from the repo root, serially with the Docker phase; attribute any DIFF before touching code.
- [ ] **Step 3:** `just test-embed` → green.
- [ ] **Step 4:** If the lima/KVM box is reachable: `just kvm-smoke-lima` → unchanged. (The KVM lane is the in-tree alternate backend; it now consumes `carrick-kernel` through the same hal traits an external backend would.)
- [ ] **Step 5:** Build-time receipt, single variable, quiet host: `touch crates/carrick-kernel/src/dispatch/fs.rs && time cargo build -p carrick-cli --release` twice, versus the same touch of `crates/carrick-runtime/src/dispatch/fs.rs` on the pre-plan commit twice. Write both to `docs/perf-results/2026-09-xx-crate-extraction-build-time.md` as "suggests".
- [ ] **Step 6:** Append the Phase 2 receipt to `docs/conformance-campaigns/2026-09-13-crate-extraction.md`; commit `docs(conformance): phase 2 receipt for the carrick-kernel extraction`.

---

## Phase 3 — Documentation and memory

### Task 3.1: Docs

- [ ] `docs/architecture-overview.md`: the three-crate layering, the three hal seams, the rule "the kernel names no VMM type; `just check-layering` enforces it", and the sentence "an execution backend is a `carrick-hal` implementor driving `carrick-kernel`; `carrick-kernel-example` is the template".
- [ ] `docs/hal.md`: `Stage1MmProjection`, `HostSignalBridge`, `GuestTimerBridge` in the trait table with implementors (HVF, KVM, example).
- [ ] `docs/archive/build-decomposition-design.md`: dated note that A4 landed via this plan, under the new names.
- [ ] `docs/host-facility-boundary.md`: one line that `HostSignalBridge` is the seam where a backend's host-crossing signal delivery lives.
- [ ] Commit `docs: record the carrick-vfs / carrick-kernel layering, the hal bridge seams and the example backend`.

---

## Self-review against the proposal and the scope decisions

| Proposal section | Plan coverage |
|---|---|
| Phase 1 `carrick-vfs` | Tasks 1.1–1.5, corrected contents (no procfs/sysfs, no cap-std), `FsCaller` seam. |
| Phase 2 `KernelAuthority` / `SignalTransport` | Dropped with measured reasons. The backend's signal seam is `HostSignalBridge` (Task 2.5). |
| Phase 3 `carrick-dispatch` | Tasks 2.1–2.9 as `carrick-kernel`; contents corrected to include the kernel graph and in-zone subsystems; arena renamed first (Task 0.0). |
| Phase 4 fallbacks; `Stage1Authority` | Fallbacks replaced by deletion (Task 0.3); `set_tid_address`/`kill` unchanged; stage-1 seam kept as `Stage1MmProjection` (Tasks 2.3–2.4). |
| Phase 5 consumers, no shims, `ExecBackendRequest` | Tasks 1.4/2.9 re-point consumers with no shims; `ExecBackendRequest` unchanged. |
| Phase 6 reference runner | `carrick-kernel-example` (Task 2.12), VMM-less compile in `ci` (Task 2.10), KVM lane (Task 2.13). |
| Verification plan | Every move task: `just ci` + layering + signed two-process smoke. Phase ends: full `just conformance`, `just conformance-probes`, `just test-embed`, binary identity recorded, build time measured single-variable. |
| Scope decisions | Public reuse → Tasks 2.11/2.12; names → Task 0.0 and all paths; both phases + 0.3 → Phases 0–2; full gate → Tasks 1.5/2.13; experimental/no semver → Task 2.11 README. |

**Placeholder scan:** the "enumerate at execution" steps (trait method lists in 2.3, the guard traits in 2.4, residue greps in 1.3/2.7, the `pub`-promotions in 2.12) each give the exact command whose output is the list; 2.5's list is written out from today's measurement. **Type consistency:** `Stage1MmProjection`, `HostSignalBridge`, `GuestTimerBridge`, `NullHostSignalBridge`, `NullGuestTimerBridge`, `CarrierBridges`, `SyscallDispatcher::with_bridges`, `FsCaller`, `ContinuationExecutor`, `HOST_PAGE_GRANULE`, `carrick_vfs::errno::{HostSyscallResult, rootfs_errno}`, `FsNetworkView`, `kernel::process_lifecycle::*`, `kernel::continuation::*`, `ScriptedBackend`, `Step`, `Sys` are the names introduced and are spelled identically throughout.

## Out of scope, deliberately

- Any errno, ordering, or wait-semantics change (needs its own oracle line).
- Typing bare `i32` signums/fds in the bridge signatures (follow-up; behaviour-neutral here).
- Flattening `carrick_kernel::kernel::…` to `carrick_kernel::…` (path-stability first; a separate rename later if wanted).
- Semver, CHANGELOG, crates.io publication (owner: experimental, pin a git rev).
- A 1:1 host-process runner, microVM runner or ptrace runner. Each is a `carrick-hal` implementor driving `carrick-kernel`, modelled on `carrick-kernel-example`, with its own design doc.
