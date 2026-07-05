# Conformance Direction Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the four direction drifts found in the 76-commit LTP re-bless campaign (`47a8bb10..HEAD`) — replace deny-to-match-the-container denials with honest capability, revert the capability-capping / test-shaping fakes and fix the latent `wait4(-1)` bug, gate-test then simplify the HVF vcpu-admission machinery, and finish the shared-mmap SysV IPC arena — so carrick's conformance reflects **real Linux behavior, not a constrained oracle**.

**Architecture:** Five independently-executable phases, sequenced by risk and dependency. Phase 0 (hygiene) and Phases 1–2 (small, high-value dispatch reverts) land first; Phase 3 (HVF admission) gate-tests before any redesign; Phase 4 (SysV arena) is the honest home of the `msgmni` fix. Each phase produces working, independently-testable software and could be pulled out as its own plan.

**Tech Stack:** Rust 2024 workspace; `just` recipes (`just build`, `just test`, `just fmt-check`, `just conformance`, `just lint-domains`, `just ci`); `cargo test -p <crate>`, `cargo clippy`; the differential Docker oracle (`cargo run -p carrick-conformance -- --tier full ...`); `bitflags`, `libc`, `zerocopy`, mmap-backed shared state, the carrick shared-futex abstraction (`carrick_host::ulock`); `carrick trace` (in-process dtrace) and `carrick-lldb` for diagnosis.

## Global Constraints

- Use `just` entrypoints; any guest run or conformance gate must use a **signed** binary from `just build` (`scripts/build-signed.sh` codesigns the HVF entitlement; unsigned runs `HV_DENIED`).
- **Never run carrick and the Docker oracle concurrently** (LinuxKit VM + HVF starve each other; verdicts corrupt). The harness two-phases them; do not background a carrick guest during a `--generate-suites` (it shells `docker run` to enumerate images).
- **Do not read Linux kernel source.** Derive ABI from man pages, ABI docs, and Docker oracle traces (bpftrace/dtrace).
- **Honesty over metric.** No syscall returns `EPERM`/`ENOSYS` *solely* to match a container-constrained oracle where real Linux succeeds. Container-only-blocked syscalls are compared under `seccomp=unconfined` (± `--cap-add`) so **both** engines run the real syscall.
- **`known_gaps` / `baseline.jsonl` discipline:** never edit them to *excuse a fixable DIFF* or paper a divergence without the oracle. An honest **gating DIFF is acceptable**. Re-blessing the baseline to record a genuinely-shifted verdict *measured against the oracle* is legitimate bless mechanics, not an excuse. A `known_gap` is permissible **only** to mark a genuinely-unimplemented *subsystem* (e.g. no kernel keyring backend) as report-only while tracked — never for an edge case that should be fixed. When in doubt, prefer the honest gating DIFF and flag for maintainer decision.
- **No `git commit --no-verify`** — all commits run `cargo fmt`; formatting is enforced. Pin `rust-toolchain`.
- Typed domain values required at service boundaries (`just lint-domains`); raw `u32`/`u64`/`i32`/`i64` only at syscall-wire, procfs-text, libc, atomic, and shared-memory-layout boundaries. New flag domains use `bitflags!`.
- **Red-first TDD:** every behavior change gets a failing probe/test that fails *for the right reason* on the pre-fix binary, verified DIFF, before the fix.
- Prefer the differential oracle with `--flake-retries 0 --workers 1` for focused verification. `scripts/run-probe.sh`'s oracle is a hardcoded `docker run --platform linux/arm64` with **no** seccomp/cap flags, so it **cannot** faithfully test the unconfined keyring/pidfd/rlimit contracts — use the conformance harness suites (which read `generate.rs` `docker_flags`) as the authoritative test for those.
- Commit logically after each independently-passing task with a Conventional Commit subject + body + verification line + the project's `Co-Authored-By`/`Claude-Session` trailers.

---

## Phase Overview & Execution Order

| Phase | Ruling | Objective | Size | Gate before next |
|-------|--------|-----------|------|------------------|
| 0 | hygiene | Restore stripped `seccomp=unconfined`; make regen preserve manual `docker_flags`; land + characterize unreviewed working-tree edits | S | working tree committed |
| 1 | #1 | Deny→unconfine+ENOSYS: keyring, pidfd_getfd; rlimit(cred-gated); establish the unconfine-oracle template | M | — |
| 2 | #3 | Fix `wait4(-1)` hazard (real bug); revert ptrace pid-1 synthetic stop | S | — |
| 3a | #2 | Gate-test admission machinery vs fragile many-thread workloads (CPython/node/Go; apt manual) | S | **must be green before 3b** |
| 3b-mech | #2 | Replace host-wide 4-VM file-lock permit with a shared-memory atomic counter (keep physical-core cap) | M | — |
| 3b-spike | #2 | *Design spike:* measure whether reclaim-on-block alone can drop the cross-process permit | L (spike) | after 3b-mech |
| 4 | #3+#4 | Finish shared-mmap SysV arena (free-list) → run-global queue count → **realistic `msgmni`** (subsumes the `msgmni=8` revert) | L (spike) | — |

**`msgmni` note:** ruling #3 wants `msgmni=8` gone, but the value is coupled to *enforcement* on the still-file-backed hot path and is not even enforced run-globally today (per-process `HashSet`). Raising it standalone makes `msgstress01` TIMEOUT. The honest removal therefore lives in **Phase 4** (Task 4), which builds the run-global counter that makes a realistic `msgmni` affordable. Until Phase 4 lands, `msgmni=8` is an **acknowledged debt**, not a hidden shaping — do not raise it on the file path.

**Whole-goal acceptance:**
- No syscall returns `EPERM`/`ENOSYS` solely to match a container-constrained oracle where real Linux succeeds; such suites are compared under `seccomp=unconfined`.
- No capability value or wait status exists solely to make one LTP suite pass.
- `wait4(-1)` never consumes a synthetic ptrace stop.
- The fragile many-thread workloads (CPython `test_many_threads`, node `worker_threads`, Go `TestConcurrentExec`) stay MATCH on the post-Phase-3 branch; apt install stays exit-0 (manual).
- `msgmni` reports a Linux-realistic value backed by real, run-global capacity.
- Full conformance gate: no *new* gating regressions vs the pre-remediation baseline; MATCH deltas from honest reversals are documented, not hidden.

---

## Phase 0 — Working-tree triage + oracle-fidelity durability

**Root cause:** `scripts/conformance/suites.toml` is machine-generated by `generate.rs` (`--generate-suites`), and its header says "Do NOT edit by hand." Commit `bafdf249` hand-added `docker_flags = ["--security-opt","seccomp=unconfined"]` to `ltp-clone301/302` *directly in the generated file*; a later regen silently dropped them (clone3 is presently running under default Docker seccomp again — a live regression). The durable fix is a `DOCKER_FLAG_OVERRIDES` table in `generate.rs` so any manual per-suite oracle-fidelity edit survives regen. This table is also the home Phases 1 uses for its unconfine flags.

**Files:**
- Modify: `crates/carrick-conformance/src/generate.rs` (const near :70; final pass at :431; tests at `mod tests` :451-468)
- Modify: `scripts/conformance/suites.toml` (clone301 block ~:8363, clone302 block ~:8375)
- Keep+commit (separate): `crates/carrick-runtime/src/dispatch/fs/fd_helpers.rs:74-149`, `fs.rs` (`note_fd_closed` calls :4756/:6455/:6463/:6515, test :10544), `net.rs:3950`, `ioring.rs:620`, `dispatch/mod.rs:2189` — the fd-allocator fix
- Keep (characterize): `scripts/conformance/oracle-cache.jsonl:2265-2298` (dup ulimit rows)

**Interfaces:**
- Produces: `const DOCKER_FLAG_OVERRIDES: &[(&str, &[&str])]` and `fn docker_flag_overrides(name: &str) -> Option<Vec<String>>` in `generate.rs`, consumed by Phase 1 Task 1.

### Task 0.1: RED tests — prove regen silently drops manual docker_flags

- [ ] **Step 1: Write two failing tests** in `generate.rs` `mod tests` (:451-468). Do **not** call `build()` (it shells to docker; hangs offline).
```rust
#[test]
fn manual_docker_flag_overrides_survive_regen() {
    assert_eq!(
        docker_flag_overrides("ltp-clone301"),
        Some(vec!["--security-opt".into(), "seccomp=unconfined".into()])
    );
    assert_eq!(docker_flag_overrides("ltp-clone302"),
        Some(vec!["--security-opt".into(), "seccomp=unconfined".into()]));
    assert_eq!(docker_flag_overrides("ltp-clone303"), None);
}

#[test]
fn committed_suites_preserve_manual_docker_flags() {
    let text = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/conformance/suites.toml")
    ).unwrap();
    let m = Manifest::from_toml(&text).unwrap();
    for name in ["ltp-clone301", "ltp-clone302"] {
        let s = m.suites.iter().find(|s| s.name == name).unwrap();
        assert!(s.docker_flags.iter().any(|f| f == "seccomp=unconfined"),
            "{name} lost seccomp=unconfined");
    }
}
```
- [ ] **Step 2: Run — expect the right failures.** `cargo test -p carrick-conformance committed_suites_preserve_manual_docker_flags` → FAIL (clone301 lost seccomp=unconfined); the pure-fn test fails to *compile* (fn/const don't exist yet). Both are the red state.
- [ ] **Step 3: Commit.** `test(conformance): assert manual docker_flags survive suite regen`

### Task 0.2: Add `DOCKER_FLAG_OVERRIDES` table + apply as final pass in `build()`

- [ ] **Step 1: Add the table + lookup** near `generate.rs:70`:
```rust
/// Oracle-fidelity docker_flags that must survive `--generate-suites`.
/// clone3 template: lift the container seccomp default so BOTH engines run the
/// real syscall; carrick then returns ENOSYS for unimplemented (ruling 1).
const DOCKER_FLAG_OVERRIDES: &[(&str, &[&str])] = &[
    ("ltp-clone301", &["--security-opt", "seccomp=unconfined"]),
    ("ltp-clone302", &["--security-opt", "seccomp=unconfined"]),
];
fn docker_flag_overrides(name: &str) -> Option<Vec<String>> {
    DOCKER_FLAG_OVERRIDES.iter().find(|(n, _)| *n == name)
        .map(|(_, f)| f.iter().map(|s| s.to_string()).collect())
}
```
- [ ] **Step 2: Apply as a final pass** immediately before `(suites, (cpy.len(), go.len(), ltp.len()))` at `generate.rs:431`:
```rust
for s in &mut suites {
    if let Some(f) = docker_flag_overrides(&s.name) { s.docker_flags = f; }
}
```
(Overwrite, not append — no current override needs to combine with an inline flag.)
- [ ] **Step 3: Run** `cargo test -p carrick-conformance manual_docker_flag_overrides_survive_regen` → PASS; `cargo fmt --check && cargo clippy -p carrick-conformance` clean.
- [ ] **Step 4: Commit.** `fix(conformance): preserve manual docker_flags across suite regen`

### Task 0.3: Restore the stripped flags in the committed file (do NOT `git checkout` the whole file)

- [ ] **Step 1: Insert** `docker_flags = ["--security-opt", "seccomp=unconfined"]` after the `carrick_flags = [...]` line of the `ltp-clone301` block (~:8363) and `ltp-clone302` block (~:8375). Keep all other working-tree additions (new suites `chdir02`, `clone10/11/304`, `clock_settime04`, `fanotify24/25`, and the dup `ulimit -n 4096;` cmds) — those are legit regen output.
- [ ] **Step 2: Run** `cargo test -p carrick-conformance committed_suites_preserve_manual_docker_flags` → PASS; `grep -c 'seccomp=unconfined' scripts/conformance/suites.toml` → `2`.
- [ ] **Step 3: Commit.** `fix(conformance): restore clone301/302 seccomp=unconfined oracle flags`
- **Gotcha:** a full `--generate-suites` regen is deferred (needs live docker, must not run alongside carrick); Task 0.2's table makes the next regen reproduce these lines.

### Task 0.4: Land the fd-allocator working-tree change as its own commit

Decision: **KEEP, commit separately** — it is the long-standing libuv `dup` floor bug (Linux lowest-free-fd), not any of the 4 rulings.

- [ ] **Step 1: Verify its shipped red-first test** `cargo test -p carrick-runtime fd_allocator_cursor_reuses_closed_hole_then_advances` → PASS (opens fds 4..36 via dup, closes 10, asserts next dup returns 10 then 36). `cargo test -p carrick-runtime` green; `cargo clippy -p carrick-runtime` clean.
- [ ] **Step 2: Review the new lock nesting** in `fd_helpers.rs:80-98,109-138` — `install_fd_at_or_above`/`install_two_fds` now hold `open_files.write()` + `next_fd.lock()` + `closed_stdio.lock()`; `note_fd_closed` takes only `next_fd`. Confirm no path locks `open_files` while holding `next_fd` (would invert order → deadlock). Current close paths call `note_fd_closed` *after* releasing `open_files` — order holds; confirm and note in the commit body.
- [ ] **Step 3: Commit** the 5 files together: `fix(runtime): allocate lowest-free fd with a close-rewound cursor`

### Task 0.5: Characterize the dup `ulimit`/`LTP_NOFILE_4096` change (keep, flag root cause)

- [ ] **Step 1:** Confirm oracle-symmetry: `effective_cmd` (engine.rs:81-86) wraps the cmd as `/bin/sh -c "<cmd>"`, so `["ulimit -n 4096; .../dup03"]` runs the builtin then the binary on **both** engines — bounding, not deny-to-match. `DEFAULT_NOFILE_SOFT=1024*1024` (fs/state.rs:263) is why dup03/06/205 (loop to `RLIMIT_NOFILE`) need it.
- [ ] **Step 2:** No behavior change; fold these already-present edits into the Task 0.4 or a small `chore(conformance): bound dup nofile tests to 4096 on both engines` commit. Flag (no action) the `DEFAULT_NOFILE_SOFT=1M` root cause and the dead `/bin/sh -lc` oracle-cache keys (prunable in a later cache refresh; never hand-edit the cache).

**Phase 0 verification:** `cargo test -p carrick-conformance` green · `cargo test -p carrick-runtime fd_allocator_cursor_reuses_closed_hole_then_advances` green · `grep -c 'seccomp=unconfined' scripts/conformance/suites.toml` = 2 · `cargo fmt --check && cargo clippy -p carrick-conformance -p carrick-runtime` clean.

---

## Phase 1 — Honest capability: deny-to-match → unconfine + ENOSYS (ruling #1)

**CredState fact (verified):** carrick models `CAP_SYS_RESOURCE` as `euid == 0`. `this.cred_snapshot()` → `CredState` (creds.rs:269); `CredState::is_privileged()` = `self.euid == 0` (creds.rs:152); default identity is root (creds.rs:118-131). `LINUX_ENOSYS == 38`, `LINUX_EPERM == 13`; `DispatchOutcome::errno(...)` is the return shape.

**Report-only decision (per global constraint):** keyring and `pidfd_getfd` are genuinely-unimplemented *subsystems*. Returning honest `ENOSYS` will DIFF against the now-unconfined oracle. Prefer letting these DIFF **report-only** as tracked-unimplemented subsystems (not `known_gaps` for a fixable edge case). If the harness's only report-only mechanism for LTP suites is `known_gaps`, use it **as a tracked-subsystem marker** and record the intent in the commit; **flag for maintainer confirmation** at execution. Do not use it to excuse anything Phases could actually fix.

**Files:** `crates/carrick-runtime/src/dispatch/proc.rs` (keyring :2070-2080; pidfd_getfd :2747-2753), `time.rs` (prlimit64 :795-797), `fs.rs` (fanotify :8239-8247), `crates/carrick-conformance/src/generate.rs` (LTP loop :404-428, consts :60-101), probes `keydeny.rs`, `rlimitroundtrip.rs`.

### Task 1.1: Establish the seccomp=unconfined / cap-add oracle template in `generate.rs` (prereq for 1.2–1.4)

- [ ] **Step 1: Prove the fake MATCH (RED).** `just conformance full --workers 1 --suite ltp-add_key02 --suite ltp-keyctl01 --flake-retries 0` currently MATCHes — but both sides return EPERM only because Docker's default seccomp blocks `add_key`/`keyctl`. That MATCH is false.
- [ ] **Step 2: Add the const sets + loop logic.** Alongside the existing const sets (~:60-101) add:
```rust
const LTP_SECCOMP_UNCONFINED: &[&str] = &["add_key", "request_key", "keyctl", "pidfd_getfd"];
const LTP_CAP_SYS_RESOURCE: &[&str] = &["setrlimit"];
```
In the LTP loop (:404-428), after `let mut suite = mk(...)`, extend `suite.docker_flags`: if `b` starts_with any `LTP_SECCOMP_UNCONFINED` stem push `["--security-opt","seccomp=unconfined"]`; `pidfd_getfd` additionally `["--cap-add","SYS_PTRACE"]`; if it starts_with a `LTP_CAP_SYS_RESOURCE` stem push `["--security-opt","seccomp=unconfined","--cap-add","SYS_RESOURCE"]`. Match by **stem prefix** so new numbered cases auto-inherit. Fold `clone301/302` into `DOCKER_FLAG_OVERRIDES` (Phase 0) rather than the loop (they are named suites).
- [ ] **Step 3: Regenerate + assert idempotent.** `cargo run -p carrick-conformance -- --generate-suites` (docker phase only, no concurrent carrick), then `git diff scripts/conformance/suites.toml | grep seccomp` shows the new entries; a second regen is a no-op.
- [ ] **Step 4: Commit.** `test(conformance): unconfine oracle seccomp for real-syscall suites`

### Task 1.2: Keyring `add_key`/`request_key`/`keyctl`: EPERM → honest ENOSYS

- [ ] **Step 1: RED.** With the oracle unconfined (1.1), `just conformance full --workers 1 --suite ltp-add_key02 --suite ltp-keyctl01 --suite ltp-request_key01 --flake-retries 0` DIFFs (real syscall succeeds/`ENOKEY` vs carrick EPERM) — proving the denial was container-mirroring.
- [ ] **Step 2: Change the three one-line handlers** at `proc.rs:2070-2080` from `Ok(DispatchOutcome::errno(LINUX_EPERM))` to `Ok(DispatchOutcome::errno(LINUX_ENOSYS))` (already in scope, used unqualified at :2032). Comment: real Linux supports **unprivileged** user keyrings; carrick has no kernel keyring, so ENOSYS (glibc fallback / LTP TCONF) is honest; EPERM falsely claimed "implemented but denied." (Reverts `980bf69a` intent.)
- [ ] **Step 3: Make the suites report-only** as tracked-unimplemented (see report-only decision above); re-run — non-gating.
- [ ] **Step 4: Commit.** `fix(runtime): report keyring syscalls as unimplemented, not denied`
- **Gotcha:** `keydeny.rs` (from `980bf69a`) is diffed by `run-probe.sh` against default-seccomp docker (also EPERM) — it cannot test the unconfined contract. Repurpose it to assert carrick's ENOSYS(38) contract, or delete it; do not treat a `keydeny` MATCH as validation.

### Task 1.3: `pidfd_getfd`: EPERM → honest ENOSYS

- [ ] **Step 1: RED.** `proc.rs:2747-2753` returns EPERM with a comment stating it mirrors "the conservative denial the Docker oracle reports." With oracle `seccomp=unconfined` + `--cap-add SYS_PTRACE`, `just conformance full --workers 1 --suite ltp-pidfd_getfd01 --suite ltp-pidfd_getfd02 --flake-retries 0` DIFFs (getfd01 happy path succeeds on real Linux).
- [ ] **Step 2: Change** the `pidfd_getfd` body (syscall 438 only) to `Ok(DispatchOutcome::errno(LINUX_ENOSYS))`; rewrite the comment: carrick has no cross-process guest-fd duplication on macOS (a real impl needs a host-side helper); ENOSYS is honest "not implemented," not a fabricated denial. **Leave `pidfd_open` (:2720+) and `pidfd_send_signal` (:2755+) untouched** — genuinely implemented.
- [ ] **Step 3:** Report-only tracked-unimplemented; re-run non-gating. **Commit:** `fix(runtime): report pidfd_getfd as unimplemented, not denied`

### Task 1.4: `rlimit` hard-raise: gate EPERM on unprivileged euid (CAP_SYS_RESOURCE)

- [ ] **Step 1: RED (probe).** Extend `rlimitroundtrip.rs` with a root-raise case asserting SUCCESS (rc==0) when raising a previously-lowered hard limit as default root (euid 0). Drive via `just conformance full --suite ltp-setrlimit03 --flake-retries 0` (needs the `--cap-add SYS_RESOURCE` from 1.1); on the current tree it DIFFs because `time.rs:795` returns EPERM unconditionally.
- [ ] **Step 2: Gate the denial** at `time.rs:795-797`:
```rust
if rlim_max > old.rlim_max && this.cred_snapshot().euid != 0 {
    return Ok(DispatchOutcome::errno(LINUX_EPERM));
}
```
The existing store path (:807-813) writes `LinuxRlimit::new(rlim_cur, rlim_max)` into `rlimit_overrides` so the raised max reads back via `effective_rlimit`. glibc `setrlimit` routes through `prlimit64` on aarch64 — this single site covers both. (Reverts `13873aa3`.)
- [ ] **Step 3: Run** — root raise succeeds and round-trips; the unprivileged (setuid-nobody) case still EPERMs; no regression in `setrlimit01/02/06`.
- [ ] **Step 4:** Update `rlimitroundtrip.rs` `core_raise_hard_eperm` (~:58-64) — its EPERM expectation is valid only unprivileged. **Commit:** `fix(runtime): let privileged guest raise rlimit hard cap`
- **Gotcha:** default carrick identity is root, so the default guest can now raise — correct (matches real Linux root+`CAP_SYS_RESOURCE`). Docker drops `CAP_SYS_RESOURCE` even for container-root, so `--cap-add SYS_RESOURCE` on the oracle is **mandatory** or you re-create the deny-to-match trap.

### Task 1.5: fanotify: keep EPERM, document the CAP_SYS_ADMIN decision (low priority)

- [ ] **Step 1:** No behavior change — fanotify is genuinely `CAP_SYS_ADMIN`-gated and unprivileged Linux returns EPERM, so this MATCHes real Linux without any seccomp trick. Replace the `let _ = (this, cx);` comment at `fs.rs:8239-8247` with an explicit rationale: no fanotify backend; EPERM is the honest CAP-gated answer; **do NOT** add fanotify to `LTP_SECCOMP_UNCONFINED` (no real success path to converge on).
- [ ] **Step 2:** `just conformance full --workers 1 --suite ltp-fanotify02 --flake-retries 0` still MATCHes. **Commit:** `docs(runtime): record fanotify EPERM is the honest CAP-gated answer`

**Phase 1 verification:** `just build && just fmt-check && just lint-domains && just check` · the four `just conformance full ... --suite ltp-{add_key02,keyctl01,request_key01,pidfd_getfd01,setrlimit03,clone301}` runs behave as above · `--generate-suites` idempotent.

---

## Phase 2 — Revert the ptrace fake + fix the latent `wait4(-1)` bug (ruling #3)

**Hazard (precise):** `c25e394b`'s wait4 predicate is `host_target == attached as i32 || host_target == -1` (proc.rs:2358). `-1` is the wait-**any**-child sentinel, so *any* genuine `wait4(-1)`/`waitpid(-1)` by the process that attached to pid 1 drains `ptrace_attach_stop_pending` and returns the fabricated `(SIGSTOP<<8)|0x7f` status with rv=pid 1, instead of reaping the real ready child. This is a correctness bug **independent** of the fake's desirability — fix it regardless.

**Files:** `crates/carrick-runtime/src/dispatch/proc.rs`, `conformance-probes/src/bin/ptraceattachinit.rs` (delete), `docs/2026-07-03-bless-regressions.md`.

### Task 2.1: TDD the `wait4(-1)` hazard, then the minimal one-clause fix

- [ ] **Step 1: Extract for testability.** Pull the inline predicate at `proc.rs:2357-2359` into a free fn near the module's other helpers (pattern: `setpgid_tests` :3108-3181):
```rust
fn synthetic_attach_matches(host_target: i32, attached: Option<u32>) -> bool {
    attached.is_some_and(|a| host_target == a as i32)
}
```
and call it from the wait4 body.
- [ ] **Step 2: RED.** Add `#[cfg(test)] mod ptrace_attach_wait_tests` with:
```rust
#[test] fn wait_any_child_does_not_consume_synthetic_attach_stop() {
    assert!(!synthetic_attach_matches(-1, Some(42))); // the hazard invariant
    assert!(synthetic_attach_matches(42, Some(42)));
    assert!(!synthetic_attach_matches(7, Some(42)));
}
```
Run `cargo test -p carrick-runtime --lib synthetic_attach_matches`. Before the fix the first assert FAILS (current expr `|| host_target == -1` matches any attached pid).
- [ ] **Step 3: GREEN.** Drop the `|| host_target == -1` clause (the extracted fn already omits it). Re-run → PASS. `just fmt-check && just test`.
- [ ] **Step 4: Commit.** `fix(runtime): wait4(-1) must not consume synthetic ptrace attach stop`
- **Note:** on real Linux the synthetic state never exists (attach-to-pid-1 is EPERM), so no Docker-vs-carrick probe can isolate this — the hostless unit test is the honest red-first. This fix is subsumed by Task 2.2; keep it a separate commit to prove the latent bug independently (ruling #3 ordering).

### Task 2.2: Revert `c25e394b` — honest EPERM for PTRACE_ATTACH to pid 1

- [ ] **Step 1:** Prefer `git revert --no-commit c25e394b`; expect a conflict only in the wait4 body (`a21ed31e` + `WaitOnProcExit` park logic rewrote ~:2390-2438 afterward). Resolve by keeping the current park logic and removing exactly the inserted synthetic block. If too tangled, do the four manual edits:
  1. PTRACE_DETACH arm (:1983-2003) → restore plain form (drop the `ptrace_attached_pid` clear).
  2. PTRACE_ATTACH (:2004-2019) → delete the `pid.0 == LINUX_BOOTSTRAP_PID` synthetic arm so attach-to-pid-1 falls through to the existing `EPERM` arm (:2015-2017).
  3. Delete the `synthetic_attach_stop` block + its `return Returned` (:2354-2389) — removes the fabricated status and pid-1 return.
  4. Remove `ProcState` fields `ptrace_attached_pid`/`ptrace_attach_stop_pending` (defs :460-461, init :576-577).
- [ ] **Step 2:** Delete `conformance-probes/src/bin/ptraceattachinit.rs` (auto-discovered; leaving it forces a gate DIFF). Do **not** add it to `KNOWN_PROBE_GAPS`. Prune the `ltp-ptrace11 MATCH after synthetic attach-stop` note in `docs/2026-07-03-bless-regressions.md:~132`.
- [ ] **Step 3: Verify no collateral regression.** `just build`; `scripts/run-probe.sh ptracekillcont` MUST still MATCH (uses TRACEME + real children); `scripts/run-probe.sh ptraceattach` MUST still MATCH (non-dumpable-parent EPERM); PEEK/POKE stay ENOSYS (:2020-2035). Spot-check `cargo run -p carrick-conformance -- --tier full --workers 1 --flake-retries 0 --suite ltp-ptrace11` (and ptrace01/02/06) — `ltp-ptrace11` may DIFF honestly; **do not** excuse it.
- [ ] **Step 4: Commit.** `revert(runtime): drop synthetic pid-1 ptrace attach stop; honest EPERM`
- **Baseline:** current baseline records `ltp-ptrace11` as broken/broken verdict=match, so the verdict likely does not move. If it shifts, re-bless via the oracle (legitimate bless mechanics, per `reference_conformance_oracle_bless`). Do **not** `git revert a21ed31e` — it carries keep-worthy vcpu-reclaim + namespace-PPid work.

**Phase 2 verification:** `just fmt-check && just test` · `test ! -e conformance-probes/src/bin/ptraceattachinit.rs` · the two `run-probe` MATCHes above.

---

## Phase 3 — vcpu-admission: gate-test THEN simplify (ruling #2). **Keep the physical-core cap.**

**Verified facts:** the physical-core cap is `min(hvf_cap~60, physical_cores=10)=10` via `vcpu_gate::budget_from_limits` (trap.rs:1034) — **keep it**. There are TWO independent caps: (1) the in-process M:N `HostCondvarScheduler` (vcpu_sched.rs, bounds sibling threads in one process) and (2) the cross-process file-lock permit (trap.rs:788-844, `CONSERVATIVE_GLOBAL_VM_CAP=4`, bounds one-vCPU VMs across a fork tree). **Only (2) is being replaced.** Reclaim-on-block is **already wired** (hvf_aarch64_engine.rs:518 `save_guest_state`→`reclaim_park`; :526 `save_shared_wait_state`→`shared_wait_park`); the "NOT YET WIRED" doc comments at trap.rs:2828/2867 are stale — correct them.

**Sequencing:** 3a must capture a green baseline **before** any 3b code change (ruling #2 ordering). 3b-mech is the ship-able simplification; 3b-spike is a design decision, deferrable, done only after 3b-mech so there is always a safe shipped state.

### Task 3.1 (3a): Add the vcpu-admission gate-test harness + record the current-branch baseline

**Fixtures already exist** (do not invent suites): `cpython-queue` (suites.toml:3167, `python3 -m test test_queue` incl. 100-thread `test_many_threads`), `node-v8-smoke` (:45) + `node-app-smoke` (:19) (`worker_threads`), `go-os_exec` (:6777, `TestConcurrentExec` fork+exec storm). **apt has no fixture** — manual repro only.

- [ ] **Step 1: Create** `scripts/conformance/vcpu-admission-gate.sh` (model on `scripts/conformance/bhyve-grind.sh`): runs `just build`, then
```bash
cargo run -p carrick-conformance -- --tier full --workers 1 --flake-retries 0 \
  --suite cpython-queue --suite node-v8-smoke --suite node-app-smoke --suite go-os_exec \
  --jsonl /tmp/carrick-vcpu-gate.jsonl
```
parses the `verdict` per suite, prints a table, and **exits 1 if any row is not MATCH**. Echo (do not automate) the manual apt note: `just run run --raw --fs host ubuntu:24.04 apt-get install -y hello` (expect exit 0).
- [ ] **Step 2: Capture the baseline.** Run the script on the current branch → all 4 MATCH. This is the reference 3b must preserve.
- [ ] **Step 3: Commit.** `test(hvf): add vcpu-admission gate for many-thread/fork workloads`
- **Gotchas:** signed binary mandatory (`just build`); never run a second docker alongside carrick; these are heavy suites (minutes each at `--workers 1`); apt is advisory (unfixtured), not a hard gate.

### Task 3.2 (3b-mech): Replace the file-lock permit with a shared-memory atomic counter (keep the cap)

- [ ] **Step 1: RED unit test.** Extract a testable inner `PermitPool { live: usize, cap: usize }` behind the shared-memory backing, and in `trap.rs` `vm_create_admission_tests` (:4522) assert (a) at most `CONSERVATIVE_GLOBAL_VM_CAP=4` Initial/SharedWaitResume permits live at once, (b) a released permit is reclaimable, (c) a simulated fork-child inherit does not double-count parent slots. `cargo test -p carrick-vmm-hvf vm_create_admission_tests --lib` fails until the pool type exists.
- [ ] **Step 2: Implement.** Replace `acquire_global_vcpu_permit`'s flock-on-`/tmp/carrick-hvf-vcpu-slots/slot-N` (:818, `GlobalVcpuPermitBackoff` 1→50ms) with a single process-shared segment created **before any fork** — `mmap(MAP_ANON|MAP_SHARED)` (or `shm_open` keyed on `CARRICK_RUN_ID`) holding an `AtomicUsize live` + `cap`. acquire = CAS-increment while `live < budget` else backoff; release = `fetch_sub`; fork child inherits the authoritative counter (drop `reset_global_vcpu_permits_after_fork_child`'s fd-closing). Delete `ensure_global_vcpu_slot_dir`/`open_global_vcpu_slot`/the fd-per-slot `HashMap`. **KEEP** `global_permit_budget_from_mn` budgets (:726) and `vcpu_gate::budget_from_limits = min(hvf_cap, physical_cores)` (:1034). Correct the stale "NOT YET WIRED" doc at :2828.
- [ ] **Step 3: GREEN end-to-end.** `cargo test -p carrick-vmm-hvf vm_create_admission_tests --lib` PASS; re-run `scripts/conformance/vcpu-admission-gate.sh` — all 4 stay MATCH (proves fork-storm protection preserved). `cargo test -p carrick-mem el1_shim_tests` (note: shim tests live in carrick-mem, not carrick-vmm-hvf). `cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings`.
- [ ] **Step 4: Commit.** `refactor(hvf): replace file-lock vcpu permit with shared-memory counter`
- **Gotchas:** the one property lost vs flock is auto-release-on-process-death; mitigate by preserving the short-held `acquire → register_global_vcpu_permit (:854) → release on vcpu_destroy (:875)` lifecycle so a crash leaks at most one count. Do not change the budget math (ruling #2 keeps the cap). Key the segment on `CARRICK_RUN_ID` to avoid cross-run contamination.

### Task 3.3 (3b-spike, DESIGN SPIKE — not mechanical): can reclaim-on-block alone drop the cross-process permit?

- [ ] **Step 1: Gate behind a flag** `CARRICK_HVF_NO_XPROC_PERMIT=1` around `create_vm_with_admission` (:949-951) so `global_permit_budget_from_mn` returns `None` for all classes when set — leaving only the in-process M:N scheduler + reclaim-on-block. **No deletion.** Keep the flag OFF by default.
- [ ] **Step 2: Stress the pre-block window** (the fork-storm peak the permit was added for, commit `1ef9d63c`): `cargo run -p carrick-conformance -- --tier full --workers 8 --flake-retries 0 --suite ltp-msgstress01 --suite ltp-futex_cmp_requeue01 --jsonl /tmp/carrick-noxproc-spike.jsonl`. PASS = zero CRASH/TIMEOUT/`HV_NO_RESOURCES`/`HV_BUSY` across 3 runs AND the 3a gate stays green.
- [ ] **Step 3: Decide + document.** Write a short findings note in `docs/`. If PASS → delete the shared-memory permit; if FAIL (reclaim doesn't fire fast enough before children park) → keep the counter and close the spike. **Commit:** `spike(hvf): gate cross-process vcpu permit to measure reclaim-only bound`
- **Gotcha:** `reclaim_park` only helps once a thread reaches its block point; a synchronous fork storm's peak is all children *between* fork and first blocking syscall. Do the spike **after** 3b-mech lands.

---

## Phase 4 — Finish the shared-mmap SysV arena → run-global count → realistic `msgmni` (rulings #3 + #4)

**Existing plan status** (`docs/superpowers/plans/2026-07-04-sysv-ipc-service.md`, 7 tasks): Task 1 (threads-max de-shaping) DONE; Task 2 (facade) DONE but as a unit struct forwarding to the file store; Task 3 (wake probe) DONE; Task 6 (explicit wake) PARTIALLY DONE — a **real cross-process futex wake already exists** (`MsgQueueWaitWord` sysv.rs:1471 via `carrick_host::ulock`, `MsgQueueWaitToken`/`WaitOnSharedWord` :1624/:1643; NOT polling). **Tasks 4 & 5 (the shared-mmap arena + moving contents onto it) are SKIPPED** — the hot path is still file-backed (`MsgQueueFile` :756 under `MsgQueueLock` OFD-flock; `msg_queue_try_send` :2788; `msg_queue_receive` :2849). This phase EXTENDS that plan; do not duplicate its 1300 lines.

**Why it matters (not cosmetic):** the `msgmni` cap at `sysv.rs:2745` counts `state.message_queues` — a **per-process** `HashSet` (fresh per forked host process). So `=8` is not even enforced run-globally. A realistic `msgmni` is impossible without a **run-global** counter, which the arena header (`live_queues`) provides. This is why finishing the arena (ruling #4) and removing `msgmni=8` (ruling #3) are one coherent phase.

**Two design spikes before coding:** (A) **arena allocator/reclamation** — the existing plan's arena is a monotonic bump with no free path; `msgstress01` cycles thousands of small messages through long-lived queues and would leak/TIMEOUT. Needs a size-classed free-list. (B) **capacity coordination** — `SYSV_MSG_QUEUE_SLOTS` (plan:512) and `SYSV_MSG_ARENA_BYTES` (plan:8 MiB) must bound the realistic `msgmni`; if the unconfined oracle reports `msgmni ≫ 512`, sizing is a real decision.

### Task 4.1 (extend plan Task 4): Land the run-scoped shared-mmap mapping with a **free-list** allocator

- [ ] **Step 1: Implement the plan's structures verbatim** (`SysvMsgServiceMapping`, `SysvMsgServiceHeader`, `SysvMsgQueueSlot`, `SysvMsgRecordHeader`, typed `MsgQueueSlotIndex`/`MsgArenaOffset`, mmap open/create under `SHM_DIR` keyed by `sysv_run_scope()` sysv.rs:682) — plan lines 593-874.
- [ ] **Step 2: RED test for reuse** (`#[cfg(test)] mod tests`, point `SHM_DIR` at a tempdir via `CARRICK_RUN_ID`): map a `SysvMsgServiceMapping`, allocate one slot, append 3 records, free the middle, append a 4th, assert the freed region is reused (`arena_next` did **not** advance). `cargo test -p carrick-runtime sysv_arena_reuse` fails against the bump-only sketch.
- [ ] **Step 3: Replace bump with a size-classed free-list.** On `consume_head_message` push the record's `[offset,len]` onto a header free-chain; on append pop a fitting free block before advancing `arena_next`. Keep raw integers behind the typed wrappers (`just lint-domains`).
- [ ] **Step 4:** `just fmt-check && just check -p carrick-runtime && just lint-domains`. **Commit:** `feat(runtime): add reclaiming shared sysv message arena`
- **Gotchas:** do NOT ship the bump-only sketch (silent leak → `msgstress01` TIMEOUT). Mapping is per-host-process; child re-opens after fork (`after_fork_child` sets `mapping=None`, sysv.rs:627-630). Header `lock_word` spin lock is acceptable as the correctness cut; the real cross-process wakeup already exists via `MsgQueueWaitWord` — do not reinvent a second futex.

### Task 4.2 (extend plan Task 5): Move msgsnd/msgrcv/msgget/msgctl/msg_table onto the arena; make the count run-global

- [ ] **Step 1: RED via new probe.** Create `conformance-probes/src/bin/sysvmsgcap.rs` proving (a) `msgmni` is enforced **run-globally** — a forked child creating queues counts against the same ceiling the parent sees (fails today: `sysv.rs:2745` counts only the per-process `HashSet`), and (b) a single queue can cycle far more messages than an 8 MiB never-reclaimed arena could hold (guards the free-list). `just build && target/release/carrick run --raw --fs host localhost:5050/ltp:arm64 /opt/carrick-probes/sysvmsgcap` → run-global key FALSE today.
- [ ] **Step 2: Rewrite the facade methods** (`msgsnd` :650 → arena append; `msgrcv` :659 → arena walk; `msgget_open` :2725; `sysvipc_msg_table_from_files` :1892 reads slots) to operate on `SysvMsgQueueSlot` + arena records under `SysvMsgServiceGuard` (plan Task 5 Steps 2-4). **Enforce `msgmni` against `header.live_queues` (run-global), not the per-process `HashSet`.** Preserve every semantic check verbatim: `can_write`→EACCES, payload>`LINUX_MSGMAX`→EINVAL, full→`Ok(false)`/EAGAIN, oversize recv w/o NOERROR→E2BIG, and `selected_msg_index` type-selection (:2811, incl. MSG_COPY/MSG_EXCEPT/negative-min).
- [ ] **Step 3: GREEN.** `sysvmsgcap` run-global key TRUE; `sysvmsgwake` all 4 keys stay TRUE; `cargo run -p carrick-conformance -- --tier full --workers 1 --flake-retries 0 --suite ltp-msgctl04 --suite ltp-msgctl06 --suite ltp-msgrcv03 --suite ltp-msgsnd05 --suite ltp-msgstress01` MATCH.
- [ ] **Step 4: Commit.** `feat(runtime): store sysv messages in shared arena, count queues run-global`
- **Gotchas:** **latent bug to fix in transit** — `msg_queue_try_send` :2802 computes `full_by_count = qnum.saturating_add(1) > qbytes`, comparing message COUNT against the BYTE limit; Linux caps count separately. Fix only if the oracle agrees; flag in the commit. `MSG_STAT`/`MSG_STAT_ANY` index by slot position — map slot index to the Linux `msqid` identity as the current fd-inode scheme does. `msgrcv`'s guest write (`cx.memory.write_bytes`) must stay atomic with slot mutation under the guard. Keep `MsgQueueLock`/`MsgQueueFile` compiling until every caller is migrated, then delete in one sweep.

### Task 4.3 (close plan Task 6): Rewire the existing futex wake onto arena slots; drop the wait-word files

- [ ] **Step 1:** Make the arena store call the `wake_msg_queue_waiters` equivalent keyed by **slot** (not path) on every successful send/recv and on `IPC_RMID` (slot.state→removed, `header.live_queues` decrement). The wake is real (not polling): `MsgQueueWaitWord` :1471 wakes via `carrick_host::ulock::wake` :1532; blocking loops (msgsnd :2444-2489, msgrcv :2520-2568) already retry-then-`WaitOnSharedWord` with EINTR + EIDRM detection.
- [ ] **Step 2:** If the arena header can host the wait word directly (`SysvMsgQueueSlot.wait_epoch`, plan:698), delete the orphaned `MsgQueueWaitWord` file-mmap layer (one fewer per-queue file).
- [ ] **Step 3:** `target/release/carrick run ... /opt/carrick-probes/sysvmsgwake` (all 4 keys true) + the 22-suite `ltp-msg*` cluster (plan:1177) MATCH. **Commit:** `refactor(runtime): key sysv wakeups on arena slots, drop wait-word files`
- **Gotchas:** don't regress the wake into a sleep loop. The wait word must be a stable host VA surviving fork (arena mapping satisfies this only if the child re-mmaps). A waiter that wakes and sees `slot.state==removed` returns `LINUX_EIDRM`.

### Task 4.4 (extend plan Task 7): Restore a Linux-realistic `msgmni` — this is the ruling-#3 `msgmni=8` removal

- [ ] **Step 1: Establish oracle truth** (docker phase, isolated): `docker run --rm --security-opt seccomp=unconfined <ltp-image> cat /proc/sys/kernel/msgmni` — record the real value.
- [ ] **Step 2: Raise all three coupled sites** to the realistic value: `sysv.rs:173 const LINUX_MSGMNI` (drives enforcement :2745 AND MSG_INFO/IPC_INFO :2999/:3001) and `vfs/proc.rs:476` `/proc/sys/kernel/msgmni` `Sysctl::Static`. Fix the comments at `sysv.rs:173` and `vfs/proc.rs:471-473` that call 8 "the service we actually provide." Keep `msgmax`/`msgmnb` unless the oracle disagrees. Enforcement must already be run-global from Task 4.2.
- [ ] **Step 3: RED→GREEN.** `sysvmsgcap`'s global-cap key now enforces at the real ceiling; `cargo run -p carrick-conformance -- --tier full --workers 1 --flake-retries 0 --suite ltp-msgstress01` MATCHes (it sizes off `/proc/sys/kernel/msgmni` and no longer TIMEOUTs with a real arena). `just ci`.
- [ ] **Step 4: Commit.** `fix(runtime): restore linux-realistic msgmni now that arena has capacity`
- **This is the honest completion of ruling #3's `msgmni=8` revert** — deferred here because a realistic ceiling is only affordable once Tasks 4.1-4.2 make that many queues real. Never raise the enforced ceiling before the arena lands.

---

## Self-Review (writing-plans checklist)

**Spec coverage vs the 4 rulings + hygiene:**
- Ruling #1 (deny→unconfine+ENOSYS) → Phase 1 (keyring 1.2, pidfd_getfd 1.3, rlimit 1.4, oracle template 1.1, fanotify decision 1.5). ✅
- Ruling #2 (keep cap, gate-test then simplify) → Phase 3 (3a gate 3.1, 3b-mech 3.2, 3b-spike 3.3); physical-core cap explicitly preserved. ✅
- Ruling #3 (revert fakes + fix `wait4(-1)`) → Phase 2 (2.1 hazard, 2.2 ptrace revert) + `msgmni=8` removal at Phase 4 Task 4.4 (with the debt stated). ✅
- Ruling #4 (finish arena) → Phase 4 (4.1 arena, 4.2 storage+run-global, 4.3 wake, 4.4 msgmni). ✅
- Hygiene (working-tree seccomp strip, regen durability, fd-allocator) → Phase 0. ✅

**Type/name consistency:** `docker_flag_overrides`/`DOCKER_FLAG_OVERRIDES` (Phase 0 → Phase 1.1 reuse); `synthetic_attach_matches` (Phase 2.1, removed by 2.2 — intentional); `LINUX_MSGMNI` single shared const touched only in Phase 4.4 (Phase 2 no longer touches it — the earlier draft's overlap is resolved). `budget_from_limits`/`global_permit_budget_from_mn` preserved in Phase 3.2. Consistent.

**Cross-phase hazards resolved:** `msgmni` consolidated into Phase 4 (was double-owned by Phase 2 + 4). `known_gaps`/baseline tension nuanced in Global Constraints. `a21ed31e` explicitly *not* reverted anywhere. Reclaim "NOT YET WIRED" stale comment corrected in Phase 3.2.

**Open decisions flagged for the maintainer at execution (not placeholders — genuine judgment calls):**
1. Report-only mechanism for keyring/pidfd (honest DIFF vs tracked-subsystem `known_gap`) — Phase 1.
2. `msgmni=8` interim debt: acceptable to leave until Phase 4, or is an earlier honest-but-conservative interim wanted?
3. 3b-spike outcome gates whether the cross-process permit is deleted or kept — genuinely empirical.
4. Arena capacity sizing (`SYSV_MSG_QUEUE_SLOTS`/`SYSV_MSG_ARENA_BYTES`) once the unconfined oracle `msgmni` is known.
