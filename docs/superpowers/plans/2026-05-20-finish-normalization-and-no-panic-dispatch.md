# Finish Syscall Normalization + No-Panic Dispatch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate every remaining legacy-arm syscall onto the uniform `SyscallCtx<M>` handler contract, delete the legacy `match` in `dispatch()` so the macro table is the single authoritative registry, and replace the `_ => panic!("unimplemented syscall")` fallback with a structured `ENOSYS` return plus a logged compat event so guest input can never crash the supervisor.

**Architecture:** Each remaining legacy handler stays exactly as written (already tested) and gains a thin `sys_*` wrapper with the uniform signature `fn(&mut self, &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>`. The wrapper forwards `ctx.request` (it is `Copy`) and `ctx.memory` to the inner fn. Every wrapper is registered in the `normalized_dispatch!` macro table. The legacy `match request.number { … }` block in `dispatch()` is then deleted; when `dispatch_normalized` returns `None`, `dispatch()` records `CompatEvent::unhandled_syscall` and returns `DispatchOutcome::Errno { errno: LINUX_ENOSYS }` instead of panicking.

**Tech Stack:** Rust, existing `normalized_dispatch!` macro (src/dispatch.rs:797), `SyscallCtx`/`SyscallRequest` (both `#[derive(Copy)]`), differential conformance harness (tests/conformance.rs, Docker-backed), 313 unit tests.

**Safety net:** `cargo test` (313 unit + integration tests) after every task; the differential conformance suite (`cargo test --test conformance`) is the ground-truth guard against ABI regressions.

---

## Legacy arms being migrated (from src/dispatch.rs:1267–1331)

| Syscall #(s) | Current arm | Inner fn / value | New wrapper |
|---|---|---|---|
| 5 \| 6 | `setxattr(Path)` | `setxattr(req, mem, XattrTarget::Path)` | `sys_setxattr_path` |
| 7 | `setxattr(Fd)` | `setxattr(.., Fd)` | `sys_setxattr_fd` |
| 8 \| 9 | `getxattr(Path)` | `getxattr(.., Path)` | `sys_getxattr_path` |
| 10 | `getxattr(Fd)` | `getxattr(.., Fd)` | `sys_getxattr_fd` |
| 11 \| 12 | `listxattr(Path)` | `listxattr(.., Path)` | `sys_listxattr_path` |
| 13 | `listxattr(Fd)` | `listxattr(.., Fd)` | `sys_listxattr_fd` |
| 14..=16 | `xattr_unsupported()` | `xattr_unsupported()` | `sys_xattr_unsupported` |
| 43 | `statfs` | `statfs(req, mem)` | `sys_statfs` |
| 44 | `fstatfs` | `fstatfs(req, mem)` | `sys_fstatfs` |
| 45 | `truncate` | `truncate(req, &mem)` | `sys_truncate` |
| 74, 75, 77 | `bootstrap_enosys()` | `bootstrap_enosys()` | `sys_bootstrap_enosys` |
| 93, 94 | `exit(req)` | `exit(req)` | `sys_exit` |
| 151 | `Returned{cred_euid}` (setfsuid) | inline | `sys_setfsuid` |
| 152 | `Returned{cred_egid}` (setfsgid) | inline | `sys_setfsgid` |
| 159 | `Returned{0}` (setgroups) | inline | `sys_setgroups` |
| 172, 178 | `getpid()` | `getpid()` | `sys_getpid` |
| 173 | `Returned{1}` (getppid) | inline | `sys_getppid` |
| 174 | `Returned{cred_ruid}` (getuid) | inline | `sys_getuid` |
| 175 | `Returned{cred_euid}` (geteuid) | inline | `sys_geteuid` |
| 176 | `Returned{cred_rgid}` (getgid) | inline | `sys_getgid` |
| 177 | `Returned{cred_egid}` (getegid) | inline | `sys_getegid` |
| 243 | `recvmmsg` | `recvmmsg(req, mem)` | `sys_recvmmsg` |
| 269 | `sendmmsg` | `sendmmsg(req, mem)` | `sys_sendmmsg` |
| 435 | `clone3` | `clone3(req, &mem)` | `sys_clone3` |
| 283 | `membarrier` | `membarrier(req)` | `sys_membarrier` |
| 293 | `rseq` | `rseq()` | `sys_rseq` |

---

### Task 1: Add the normalized shim-wrappers

**Files:**
- Modify: `src/dispatch.rs` — add a new `impl SyscallDispatcher` block holding the wrappers (place it immediately after the existing `xattr_unsupported`/`bootstrap_enosys` helpers, near line 8175, so the wrappers sit next to the inner fns they call).

- [ ] **Step 1: Add the wrapper block**

Insert this block inside `impl SyscallDispatcher` (a fresh `impl` block is fine — Rust allows multiple):

```rust
// === Normalized shim-wrappers ===
// Thin adapters giving each remaining legacy handler the uniform
// SyscallCtx<M> contract so it can live in the `normalized_dispatch!`
// table. The inner fns are unchanged (already tested); these forward
// `ctx.request` (Copy) and `ctx.memory`. Once every syscall has a
// wrapper the legacy match in `dispatch()` is deleted and the macro
// table becomes the single authoritative syscall registry.
impl SyscallDispatcher {
    fn sys_setxattr_path<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.setxattr(ctx.request, ctx.memory, XattrTarget::Path)
    }
    fn sys_setxattr_fd<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.setxattr(ctx.request, ctx.memory, XattrTarget::Fd)
    }
    fn sys_getxattr_path<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.getxattr(ctx.request, ctx.memory, XattrTarget::Path)
    }
    fn sys_getxattr_fd<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.getxattr(ctx.request, ctx.memory, XattrTarget::Fd)
    }
    fn sys_listxattr_path<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.listxattr(ctx.request, ctx.memory, XattrTarget::Path)
    }
    fn sys_listxattr_fd<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.listxattr(ctx.request, ctx.memory, XattrTarget::Fd)
    }
    fn sys_xattr_unsupported<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.xattr_unsupported())
    }
    fn sys_statfs<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.statfs(ctx.request, ctx.memory)
    }
    fn sys_fstatfs<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.fstatfs(ctx.request, ctx.memory))
    }
    fn sys_truncate<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        self.truncate(ctx.request, &*ctx.memory)
    }
    fn sys_bootstrap_enosys<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.bootstrap_enosys())
    }
    fn sys_exit<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.exit(ctx.request))
    }
    fn sys_setfsuid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: i64::from(self.cred_euid) })
    }
    fn sys_setfsgid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: i64::from(self.cred_egid) })
    }
    fn sys_setgroups<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 0 })
    }
    fn sys_getpid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.getpid())
    }
    fn sys_getppid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: 1 })
    }
    fn sys_getuid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: i64::from(self.cred_ruid) })
    }
    fn sys_geteuid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: i64::from(self.cred_euid) })
    }
    fn sys_getgid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: i64::from(self.cred_rgid) })
    }
    fn sys_getegid<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(DispatchOutcome::Returned { value: i64::from(self.cred_egid) })
    }
    fn sys_recvmmsg<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.recvmmsg(ctx.request, ctx.memory))
    }
    fn sys_sendmmsg<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.sendmmsg(ctx.request, ctx.memory))
    }
    fn sys_clone3<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.clone3(ctx.request, &*ctx.memory))
    }
    fn sys_membarrier<M: GuestMemory>(&mut self, ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.membarrier(ctx.request))
    }
    fn sys_rseq<M: GuestMemory>(&mut self, _ctx: &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError> {
        Ok(self.rseq())
    }
}
```

- [ ] **Step 2: Build to verify wrappers compile (they are not yet referenced — `dead_code` warnings expected)**

Run: `cargo build 2>&1 | grep -E 'error|warning: .*never used' | head`
Expected: no `error` lines. `never used` warnings for the new `sys_*` fns are expected and acceptable at this step.

- [ ] **Step 3: Commit**

```bash
git add src/dispatch.rs
git commit -m "Add normalized shim-wrappers for remaining legacy syscall handlers

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Register the wrappers in the macro table

**Files:**
- Modify: `src/dispatch.rs:819–970` — the `normalized_dispatch! { … }` invocation.

- [ ] **Step 1: Append the new entries to the macro table**

Add these lines inside the `normalized_dispatch! { … }` block (after the last existing entry `439 => faccessat2,` at line 969, before the closing `}`). The macro's `$num:pat` accepts or-patterns and ranges:

```rust
        5 | 6 => sys_setxattr_path,
        7 => sys_setxattr_fd,
        8 | 9 => sys_getxattr_path,
        10 => sys_getxattr_fd,
        11 | 12 => sys_listxattr_path,
        13 => sys_listxattr_fd,
        14..=16 => sys_xattr_unsupported,
        43 => sys_statfs,
        44 => sys_fstatfs,
        45 => sys_truncate,
        74 | 75 | 77 => sys_bootstrap_enosys,
        93 | 94 => sys_exit,
        151 => sys_setfsuid,
        152 => sys_setfsgid,
        159 => sys_setgroups,
        172 | 178 => sys_getpid,
        173 => sys_getppid,
        174 => sys_getuid,
        175 => sys_geteuid,
        176 => sys_getgid,
        177 => sys_getegid,
        243 => sys_recvmmsg,
        269 => sys_sendmmsg,
        435 => sys_clone3,
        283 => sys_membarrier,
        293 => sys_rseq,
```

- [ ] **Step 2: Build to verify no duplicate/unreachable-pattern errors**

Run: `cargo build 2>&1 | grep -E 'error|unreachable pattern' | head`
Expected: no output. (The macro expands to a `match`; an accidental duplicate syscall number would produce `unreachable pattern` — that is the compiler enforcing the registry is conflict-free.)

- [ ] **Step 3: Commit**

```bash
git add src/dispatch.rs
git commit -m "Register all remaining syscalls in the normalized dispatch table

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Delete the legacy match; replace panic with ENOSYS + logged event

**Files:**
- Modify: `src/dispatch.rs:1267–1331` (the `let outcome = match request.number { … };` block inside `dispatch()`).

- [ ] **Step 1: Replace the legacy match block**

Replace the entire `let outcome = match request.number { … };` block (lines ~1267–1331, from `let outcome = match request.number {` through its closing `};`) with:

```rust
        // The normalized macro table is the single authoritative syscall
        // registry. Any number it does not claim is genuinely unimplemented:
        // record a structured compat event and return ENOSYS. The supervisor
        // must never panic on guest input — an unknown syscall is the guest's
        // problem to handle (it gets -ENOSYS), not ours to crash on.
        reporter.record(CompatEvent::unhandled_syscall(
            request.number,
            name,
            request.args,
        ));
        let outcome = DispatchOutcome::Errno {
            errno: LINUX_ENOSYS,
        };
```

This leaves the existing trailing block intact:

```rust
        let (retval, errno) = outcome.retval_errno();
        reporter.record(CompatEvent::SyscallReturn {
            number: request.number,
            name: name.to_owned(),
            retval,
            errno,
        });

        Ok(outcome)
```

- [ ] **Step 2: Build**

Run: `cargo build 2>&1 | grep -E 'error' | head`
Expected: no output. The inner fns (`setxattr`, `statfs`, `exit`, `recvmmsg`, etc.) are now reached only via their `sys_*` wrappers; they must NOT warn as unused. If any inner fn warns "never used", it means a wrapper or table entry is missing — fix it.

- [ ] **Step 3: Run the full unit + integration suite**

Run: `cargo test 2>&1 | tail -30`
Expected: all tests pass (313 lib tests + integration). Pay attention to `tests/syscall_dispatch.rs` (exit/getpid/xattr/statfs/truncate/mmsg/clone3 coverage) — these now route through the normalized path and must still pass unchanged.

- [ ] **Step 4: Run the differential conformance suite (ground truth vs. real Linux)**

Run: `cargo test --test conformance 2>&1 | tail -40`
Expected: every probe `PASS` or `XFAIL` (known gap); zero `FAIL`, zero `UNEXPECTED PASS`. Note: requires Docker (see [[reference-docker-cross-check]]).

- [ ] **Step 5: Commit**

```bash
git add src/dispatch.rs
git commit -m "Delete legacy dispatch match; macro table is now the sole registry

Unimplemented syscalls return -ENOSYS with a logged compat event instead
of panicking the supervisor. Every syscall now uses the uniform
SyscallCtx<M> handler contract; there is one recipe for adding a syscall.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Regression test — the registry is complete and panic-free

**Files:**
- Modify: `src/dispatch.rs` (the `#[cfg(test)] mod tests` block, near the existing `errno_translation_covers_every_divergent_code` test ~line 12465).

- [ ] **Step 1: Write the failing test**

Add this test. It pins the contract: a representative set of previously-legacy syscalls must be claimed by `dispatch_normalized` (not fall through to ENOSYS), and a guaranteed-unknown syscall returns ENOSYS rather than panicking.

```rust
#[test]
fn every_migrated_syscall_is_claimed_by_the_normalized_table() {
    let mut d = SyscallDispatcher::new();
    let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
    let mut reporter = CompatReporter::default();
    // Numbers that used to live in the deleted legacy match. Each must now
    // be claimed by the normalized table (Some), never None.
    for nr in [5u64, 7, 8, 10, 11, 13, 14, 43, 44, 45, 74, 93, 151, 152,
               159, 172, 173, 174, 175, 176, 177, 178, 243, 269, 283, 293, 435] {
        let req = SyscallRequest::new(nr, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
        assert!(
            d.dispatch_normalized(req, &mut mem, &mut reporter).is_some(),
            "syscall {nr} fell through the normalized table",
        );
    }
}

#[test]
fn unknown_syscall_returns_enosys_without_panicking() {
    let mut d = SyscallDispatcher::new();
    let mut mem = LinearMemory::new(0, vec![0u8; 4096]);
    let mut reporter = CompatReporter::default();
    // 999 is not a real aarch64 syscall and is not in the table.
    let req = SyscallRequest::new(999, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
    let outcome = d.dispatch(req, &mut mem, &mut reporter).expect("must not error");
    assert_eq!(outcome, DispatchOutcome::Errno { errno: LINUX_ENOSYS });
}
```

- [ ] **Step 2: Run to verify both pass** (they should pass immediately — they pin behavior just implemented)

Run: `cargo test --lib every_migrated_syscall_is_claimed_by_the_normalized_table unknown_syscall_returns_enosys_without_panicking 2>&1 | tail -15`
Expected: both PASS. If `CompatReporter::default()` or `SyscallArgs::from([..])` don't exist with these names, adjust to the constructors used by the neighbouring tests in the same module (grep the test module for how it builds a reporter and args).

- [ ] **Step 3: Commit**

```bash
git add src/dispatch.rs
git commit -m "Pin the normalized registry: migrated syscalls claimed, unknown -> ENOSYS

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Self-Review notes

- **Spec coverage:** Goal #1 (finish migration, delete legacy arm, macro table = registry) — Tasks 1–3. Goal #4 behavioral half (panic → ENOSYS + logged event) — Task 3. Regression guard — Task 4. Goal #4 enforcement half (clippy gate over `unwrap`/`panic` in dispatch) is deferred to a follow-up plan because enabling a crate-wide lint first requires auditing the 128 existing `.unwrap()` and 15 `panic!` sites; it is tracked as the next plan, not silently dropped.
- **Borrow safety:** `ctx.request` is `Copy` so forwarding it does not conflict with the `&mut *ctx.memory` reborrow (request is copied before memory is borrowed; args evaluate left-to-right). `truncate`/`clone3` take `&impl GuestMemory`, so the wrappers pass `&*ctx.memory`.
- **Type consistency:** every wrapper has the exact signature the `normalized_dispatch!` macro expects: `fn(&mut self, &mut SyscallCtx<M>) -> Result<DispatchOutcome, DispatchError>`. Inner fns returning bare `DispatchOutcome` (`fstatfs`, `xattr_unsupported`, `bootstrap_enosys`, `exit`, `getpid`, `recvmmsg`, `sendmmsg`, `clone3`, `membarrier`, `rseq`) are wrapped in `Ok(...)`.

---

## Roadmap (subsequent plans, after this lands)

These deliver the remaining goal items and each gets its own executable plan once this one is merged and green:

- **Plan B — Goal #4 enforcement:** audit the 128 `.unwrap()` / 15 `panic!` sites; introduce a clippy gate (`[lints.clippy] unwrap_used / panic = "deny"` crate-wide, or a `disallowed-macros` clippy.toml) once the code passes it.
- **Plan C — Goal #3:** lift every `LINUX_*` / `SYS_*` constant from `dispatch.rs` into `linux_abi.rs`; `dispatch.rs` imports, never declares.
- **Plan D — Goal #2:** split `dispatch.rs` by subsystem (`fs/`, `mem/`, `signal/`, `creds/`, `net/`, `time/`) behind the now-uniform contract; move god-object fields into owned sub-structs (`SignalState`, `CredState`, `MmapState`, …) handlers borrow narrowly.
- **Plan E — Goal #5:** split the 243 KB `tests/syscall_dispatch.rs` along the same subsystem seams; make adding a conformance probe the path of least resistance.
