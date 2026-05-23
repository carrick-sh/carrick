# Gap Research Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every open finding in `gap-research.md` against Carrick's current runtime, with tests, bookkeeping, and a fast-forward back to `main`.

**Architecture:** Treat the review as a live requirements document. Security and guest-visible correctness fixes must land with regression tests; maintainability items must reduce the named risk directly or document a verified false-positive with evidence. Keep the existing branch `codex/address-gap-research` as the integration branch and fast-forward `main` only after verification.

**Tech Stack:** Rust, Cargo integration tests, macOS/Darwin libc/HVF APIs, Carrick dispatcher/runtime tests.

---

### Task 1: Security and Guest-Visible Correctness

**Files:**
- Modify: `src/fs_backend.rs`, `src/dispatch/fs.rs`, `src/vfs/rootfs.rs`, `src/vfs/mod.rs`, `src/dispatch/mem.rs`, `src/dispatch/signal.rs`, `src/dispatch/time.rs`, `src/dispatch/net.rs`, `src/memory.rs`, `src/elf.rs`
- Test: `tests/syscall_fs.rs`, `tests/syscall_mem.rs`, `tests/syscall_signal.rs`, `tests/syscall_time.rs`, `tests/syscall_net.rs`, `tests/elf_inspector.rs`, plus module unit tests where private helpers are involved

- [ ] **Step 1: Write failing regression tests**

Add focused tests for:
- internal `user.carrick.*` xattrs hidden from set/get/list;
- symlink/path traversal and symlink-hop limits;
- memory-backed truncate/ftruncate caps instead of unbounded allocation;
- `MADV_DONTNEED` zero-fill behavior;
- invalid alt-stack signal injection rejected before host write failure;
- `sysinfo.uptime` below epoch-time scale;
- host sockets and socketpairs forced nonblocking even when Linux status flags remain blocking;
- bad ELF machine rejected.

- [ ] **Step 2: Run targeted tests and confirm failures**

Run: `cargo test --test syscall_fs -- --nocapture`, `cargo test --test syscall_mem -- --nocapture`, `cargo test --test syscall_signal -- --nocapture`, `cargo test --test syscall_time -- --nocapture`, `cargo test --test syscall_net -- --nocapture`, `cargo test --test elf_inspector -- --nocapture`, and targeted `cargo test --lib` filters for private helper tests.

- [ ] **Step 3: Implement minimal fixes**

Hide all `user.carrick.*` xattrs, strengthen rooted path following, cap guest-controlled in-memory allocations, implement zero-fill for `MADV_DONTNEED`, validate signal alt-stack range before writing the frame, compute time with monotonic/boot-time-safe arithmetic, force host socket fds to `O_NONBLOCK`, check entropy and ELF arithmetic errors, and reject unsupported ELF machines.

- [ ] **Step 4: Re-run targeted tests until green**

Run the same targeted commands from Step 2 and keep failures attached to the exact item they prove.

### Task 2: Runtime Safety and Maintainability

**Files:**
- Modify: `src/trap.rs`, `src/runtime.rs`, `src/dispatch/mod.rs`, `src/pty_relay.rs`, `src/vfs/proc.rs`, `src/thread.rs`, `src/dtrace_consumer.rs`, `src/syscall.rs`, `gap-research.md`
- Test: module unit tests in `src/trap.rs`, `src/dispatch/mod.rs`, `src/pty_relay.rs`, `src/vfs/proc.rs`, `src/syscall.rs`, and existing runtime-loop/thread tests

- [ ] **Step 1: Write failing or guard tests**

Add tests for sorted/coalesced `PROT_NONE` intervals, batched guest C-string reads, complete SIGWINCH pipe draining, syscall table sortedness, dynamic `/proc/<pid>/task` listing without a 64-entry cap, and documented futex lock ordering.

- [ ] **Step 2: Implement runtime cleanup**

Extract the GPR register table once, cache `CARRICK_TRACE_TRAPS` in runtime loop state, replace panic-prone inner overwrites with a named no-drop replacement helper, avoid leaking parent-side fork snapshot buffers, convert DTrace handles to RAII guards, and mark verified non-issues in the ledger with evidence.

- [ ] **Step 3: Re-run focused runtime tests**

Run: `cargo test --lib trap::tests`, `cargo test --lib dispatch::tests`, `cargo test --lib pty_relay::tests`, `cargo test --lib vfs::proc::tests`, `cargo test --test runtime_loop`, `cargo test --test syscall_thread -- --nocapture`, and `cargo test --test concurrency_contracts -- --nocapture`.

### Task 3: Final Integration

**Files:**
- Modify: `gap-research.md`

- [ ] **Step 1: Update ledger**

Record each item as fixed, verified already addressed, or intentionally documented compatibility limitation, with the test command proving it.

- [ ] **Step 2: Run final verification**

Run: `cargo fmt --all -- --check`, `cargo clippy --all-targets`, `cargo test`, and any Carrick-specific signed/HVF test needed by touched runtime paths.

- [ ] **Step 3: Commit and fast-forward main**

Create logical commits on `codex/address-gap-research`, switch to `main`, `git merge --ff-only codex/address-gap-research`, rerun final verification on `main`, and leave the worktree clean.
