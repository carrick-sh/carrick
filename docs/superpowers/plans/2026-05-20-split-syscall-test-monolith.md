# Split the Syscall Test Monolith — Implementation Plan (Goal #5)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Checkbox steps.
> **CONCURRENCY:** Touches only `tests/`. Safe to run concurrently with `src/`-only plans (e.g. Plan A) in a separate worktree — no file overlap.

**Goal:** Split `tests/syscall_dispatch.rs` (7,930 lines, 109 `#[test]` fns, flat) along the same subsystem seams planned for `src/dispatch.rs` (fs, mem, net, time, signal, creds, process), with shared helpers extracted into one common module, so tests live next to what they test and adding a test is the path of least resistance.

**Architecture:** Cargo treats each file in `tests/` as its own crate. To make a shared module, use a subdirectory module that is NOT itself a test target: `tests/syscall/common.rs` plus per-subsystem files that `#[path]`-include or `mod`-include it. The standard idiom: create `tests/syscall/mod.rs`-style shared code under `tests/common/` and have each `tests/syscall_<subsystem>.rs` declare `#[path = "common/syscall_support.rs"] mod support;`. Verify the chosen idiom compiles before bulk-moving.

**Inventoried facts (read-only survey, 2026-05-20):**
- 109 tests, flat list. Helpers (35+) at lines 7584–7930 (~347 lines). Imports + ~100 constant aliases at lines 1–80.
- Subsystem distribution: FS 49, TIME 14, NET 13, CREDS 12, PROCESS 8, MEM 6, SIGNAL 6.
- Shared helpers (must move to common): primitives `read_i32_le`/`read_u64`/`write_u64`; struct readers `read_stat/statx/statfs/utsname/rlimit/tms/rusage/itimerspec/itimerval/timerfd_expirations/eventfd_value/epoll_event/timespec/timeval/timezone/winsize/termios/fd_pair`; collection helpers `write_iovecs`/`read_pollfds`/`write_pollfds`/`write_fd_set`/`read_fd_set`/`linux_fd_set_len`; capability helpers `write_capability_header`/`write_capability_data`/`read_capability_data`; `linux_c_string`; fixtures `gzip_tar`/`gzip_tar_with_links`; `rw_perms`/`rwx_perms`; `write_open_how`.
- `gzip_tar`/`gzip_tar_with_links`/`SegmentPerms` helpers are ALSO duplicated in `tests/cli.rs` — opportunity to dedupe into common, but out of scope unless trivial.
- No existing `tests/common` module.

**Safety net:** all 109 tests must still run and pass after the split: `cargo test --test 'syscall_*' 2>&1 | tail`. Count tests before and after; the totals must match.

---

### Task 1: Establish the shared support module (proof-of-idiom first)

**Files:** Create `tests/common/syscall_support.rs`; create a throwaway `tests/syscall_smoke.rs` to prove the include idiom compiles.

- [ ] **Step 1:** Create `tests/common/syscall_support.rs` containing the imports (lines 1–20), constant aliases (lines 20–80), and ALL helpers (lines 7584–7930) copied verbatim from `tests/syscall_dispatch.rs`. Make every helper and constant `pub`.
- [ ] **Step 2:** Create `tests/syscall_smoke.rs`:
```rust
#[path = "common/syscall_support.rs"]
mod support;

#[test]
fn support_module_links() {
    // Touch one helper + one constant to prove the include compiles and links.
    let _ = support::rw_perms();
}
```
- [ ] **Step 3:** `cargo test --test syscall_smoke 2>&1 | tail -10` → PASS. If `#[path]` include causes unused-import warnings, add `#![allow(unused_imports, dead_code)]` at the top of `syscall_support.rs` (a shared support file legitimately exposes more than any one consumer uses).
- [ ] **Step 4:** Commit: `git commit -am "tests: add shared syscall_support module + idiom smoke test"`.

---

### Tasks 2–8: Carve out each subsystem (one task per subsystem)

For EACH subsystem in {fs, mem, net, time, signal, creds, process}, do the following (this is the repeated recipe — apply identically per subsystem):

- [ ] **Step 1:** Create `tests/syscall_<subsystem>.rs` starting with:
```rust
#[path = "common/syscall_support.rs"]
mod support;
use support::*;
```
- [ ] **Step 2:** MOVE (cut from `syscall_dispatch.rs`, paste here) the `#[test]` fns for that subsystem per the inventory groupings (FS 49, MEM 6, NET 13, TIME 14, SIGNAL 6, CREDS 12, PROCESS 8). Cross-cutting tests go: `syscall_request_can_be_built_from_aarch64_register_frame` + `linear_memory_bounds_reads` → process; `faccessat2_*` + `utimensat_*` → fs.
- [ ] **Step 3:** `cargo test --test syscall_<subsystem> 2>&1 | tail -10` → all that subsystem's tests PASS.
- [ ] **Step 4:** Commit: `git commit -am "tests: split <subsystem> syscall tests into tests/syscall_<subsystem>.rs"`.

---

### Task 9: Delete the emptied monolith + smoke file; verify totals

- [ ] **Step 1:** After all subsystems are moved, `tests/syscall_dispatch.rs` should contain no `#[test]` fns (only the now-duplicated helper tail, which is dead). Delete `tests/syscall_dispatch.rs` and `tests/syscall_smoke.rs`.
- [ ] **Step 2:** Verify the test count is conserved:
```bash
cargo test --test 'syscall_*' 2>&1 | grep -E 'test result' 
```
Expected: total passed across the syscall_* targets == 109 (plus any subsystem's own count). No test lost.
- [ ] **Step 3:** `cargo test 2>&1 | tail -5` → whole suite green.
- [ ] **Step 4:** Commit: `git commit -am "tests: remove emptied syscall_dispatch monolith; 109 tests now live by subsystem"`.

---

## Self-Review
- Spec coverage: goal #5 fully — monolith split along subsystem seams matching the `src/dispatch.rs` split (Plan D), shared helpers in one module, per-subsystem files. "Adding a test is path of least resistance" → a contributor adds to the matching subsystem file.
- Risk: low — pure test reorganization; the conserved-count check (Task 9) catches any dropped test. The `#[path]` idiom is proven in Task 1 before any bulk move.
- Open item to verify at execution: confirm `#[path]`-included shared module is the cleanest idiom for this repo vs. a `tests/common/mod.rs`; Task 1 is the gate for that decision.
