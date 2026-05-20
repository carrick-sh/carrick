# Lift ABI Constants into `linux_abi.rs` — Implementation Plan (Goal #3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.
> **PRECONDITION:** Plan A (finish-normalization) must be merged first. This plan edits the same file (`src/dispatch.rs`) — do not run it concurrently with any other `dispatch.rs` plan.

**Goal:** Make `src/linux_abi.rs` the single source of truth for Linux ABI constants. Move all 257 `LINUX_*`/`SYS_*` constants currently declared in `src/dispatch.rs` into `linux_abi.rs`; `dispatch.rs` imports them, never declares them.

**Architecture:** Constants move as `pub const` into `linux_abi.rs` (grouped by family next to the existing ABI groups). `dispatch.rs` gains them in its existing `use crate::linux_abi::{…}` block (src/dispatch.rs:8–20). External modules that referenced `dispatch::LINUX_*` are repointed to `linux_abi::LINUX_*`. Compilation is kept green at each phase.

**Inventoried facts (from read-only survey, 2026-05-20):**
- 257 ABI constants in `dispatch.rs`: 115 `pub`, 142 private. One non-ABI const (`SYSCALL_FLAG_VALIDATORS`, dispatch.rs:9564) STAYS — it's a validator table, not ABI.
- **Zero name collisions** with the 57 constants already in `linux_abi.rs`. No value reconciliation needed.
- 37 external references to `dispatch::LINUX_*` across 7 files: `vfs/mod.rs` (11), `fs_backend.rs` (12), `vfs/rootfs.rs` (7), `vfs/dev.rs` (4), `vfs/sys.rs` (1), `vfs/proc.rs` (1), `runtime.rs` (1). Only the `pub` constants are referenced externally.
- Internal dependency chains that must move together: `LINUX_FALLOC_FL_SUPPORTED` ← the 6 `FALLOC_FL_*` flags; `LINUX_EFD_NONBLOCK/CLOEXEC`, `LINUX_TFD_NONBLOCK/CLOEXEC`, `LINUX_EPOLL_CLOEXEC` ← `LINUX_O_NONBLOCK`/`LINUX_O_CLOEXEC`; `LINUX_SPLICE_SUPPORTED_FLAGS` ← `SPLICE_F_*`; `LINUX_WAITID_*`/`LINUX_WAIT4_SUPPORTED_FLAGS` ← the `W*` flags; `LINUX_OPEN_HOW_SIZE` ← `LinuxOpenHow` (already in linux_abi.rs).
- Existing import style to extend: `use crate::linux_abi::{ KernelAbi, LINUX_S_IFDIR, … };` (dispatch.rs:8). Some sites use fully-qualified `crate::linux_abi::LINUX_SIG_DFL` (dispatch.rs:1151–1165).

**Safety net:** `cargo build` after every phase; full `cargo test` + `cargo test --test conformance` at the end. Constants are compile-time values, so any miswire is a compile error, not a silent ABI drift — but conformance still runs as belt-and-suspenders.

---

### Task 1: Move the `pub` constants (the externally-referenced set)

**Files:** `src/linux_abi.rs` (add), `src/dispatch.rs` (remove decls + import), 7 consumer files (repoint).

- [ ] **Step 1:** Cut the 115 `pub const LINUX_*`/`SYS_*` declarations from `dispatch.rs` (lines ~33–161 plus the scattered socket-family/option blocks at ~11603–11858 and errno at 12126) and paste them into `linux_abi.rs`, grouped next to the existing families (errno, open flags, AT_, fcntl, mmap/mprotect, socket families/types/levels/options/msg-flags, falloc, seek, xattr, misc). Keep the `FALLOC_FL_*` family contiguous so `LINUX_FALLOC_FL_SUPPORTED`'s definition still resolves.
- [ ] **Step 2:** Add the moved names to the `use crate::linux_abi::{…}` block at dispatch.rs:8.
- [ ] **Step 3:** Repoint external references. Run, then verify each diff:
```bash
for f in src/vfs/mod.rs src/fs_backend.rs src/vfs/rootfs.rs src/vfs/dev.rs src/vfs/sys.rs src/vfs/proc.rs src/runtime.rs; do
  perl -pi -e 's/\bdispatch::LINUX_/linux_abi::LINUX_/g' "$f"
done
```
- [ ] **Step 4:** `cargo build 2>&1 | grep -E 'error' | head` → expect no output. Fix any "unresolved import" by adjusting the use block.
- [ ] **Step 5:** Commit: `git commit -am "Move pub ABI constants from dispatch.rs to linux_abi.rs"` (with the Co-Authored-By trailer).

---

### Task 2: Move the private constants

**Files:** `src/linux_abi.rs` (add as `pub const`), `src/dispatch.rs` (remove + import).

- [ ] **Step 1:** Move the ~142 private `const LINUX_*` from dispatch.rs (lines ~162–276, and socket/netlink blocks) into `linux_abi.rs` as `pub const`. Move dependent groups as units (epoll/eventfd/timerfd flags after their `O_*` deps already landed in Task 1; `WAITID_*`/`WAIT4_*` with the `W*` flags; `SPLICE_SUPPORTED_FLAGS` with `SPLICE_F_*`). Leave `SYSCALL_FLAG_VALIDATORS` (dispatch.rs:9564) in place — it is not ABI.
- [ ] **Step 2:** Add them to the dispatch.rs `use crate::linux_abi::{…}` block.
- [ ] **Step 3:** `cargo build 2>&1 | grep -E 'error' | head` → no output. No external repointing needed (these were private).
- [ ] **Step 4:** `cargo test 2>&1 | tail -5` and `cargo test --test conformance 2>&1 | tail -20` → all green / XFAIL only.
- [ ] **Step 5:** Commit: `git commit -am "Move private ABI constants to linux_abi.rs; dispatch.rs now imports all ABI"`.

---

### Task 3: Guardrail — keep ABI declarations out of dispatch.rs

- [ ] **Step 1:** Add a test (in `linux_abi.rs` tests or `tests/syscall_table.rs`) asserting a representative invariant only once, OR add a CI grep gate. Concretely, append to `tests/syscall_table.rs`:
```rust
#[test]
fn dispatch_declares_no_abi_constants() {
    let src = include_str!("../src/dispatch.rs");
    // dispatch.rs must import ABI constants, never declare them.
    for line in src.lines() {
        let t = line.trim_start();
        assert!(
            !(t.starts_with("pub const LINUX_") || t.starts_with("const LINUX_")
              || t.starts_with("pub const SYS_") || t.starts_with("const SYS_")),
            "ABI constant declared in dispatch.rs — move it to linux_abi.rs: {line}",
        );
    }
}
```
- [ ] **Step 2:** `cargo test --test syscall_table dispatch_declares_no_abi_constants` → PASS.
- [ ] **Step 3:** Commit: `git commit -am "Guard: ABI constants must live in linux_abi.rs, not dispatch.rs"`.

---

## Self-Review
- Spec coverage: goal #3 fully — all `LINUX_*`/`SYS_*` move (Tasks 1–2), and a regression guard prevents re-accretion (Task 3). The throughline ("stop the god-file silently re-accreting") is served by Task 3.
- Risk: low — zero collisions confirmed; constants are compile-time so miswires are build errors. Dependency-chain groups are enumerated above so they move atomically.
