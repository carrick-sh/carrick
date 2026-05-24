# pidfd (SP2b) — kernel-backed via kqueue EVFILT_PROC — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans. Steps use `- [ ]` checkboxes.

**Goal:** Implement Linux pidfd so Go 1.24's `os/exec` works: `pidfd_open(434)`, `CLONE_PIDFD` in clone, poll/epoll readiness, and `waitid(P_PIDFD)` — each backed by a host `kqueue` `EVFILT_PROC`/`NOTE_EXIT` registration on the real macOS child process (the kernel tracks process lifecycle; carrick only maps the guest pidfd ↔ host pid).

**Architecture:** A guest pidfd is a new `OpenDescription::Pidfd { host_pid, kq: Arc<Kqueue> }` (mirroring the kqueue-backed `OpenDescription::Epoll`). The kqueue has one `EVFILT_PROC` filter with `NOTE_EXIT` on `host_pid`, so it becomes read-ready exactly when the process dies — which is how poll/epoll/`pidfd`-readiness and `waitid(P_PIDFD)` observe exit. Guest pids mirror host pids in carrick (fork returns the real `libc::fork` pid; `wait4` maps straight through), so no pid translation table is needed.

**Tech stack:** Rust, libc kqueue (`EVFILT_PROC`, `NOTE_EXIT`, `NOTE_EXITSTATUS`), the existing `darwin_kqueue::Kqueue`, `OpenDescription`/fd-table, the fork path (`ForkOutcome::Parent { child_pid }`).

**Evidence (why):** Go `os/exec` `forkExec` aborts in the PARENT at `pidfd_open(434)`→ENOSYS, before any `clone`/fork (trace: no `fork-post`, no `execve`). So `pidfd_open` must return a real pollable fd. Clears `os/exec` (26), `sync` TestMutexMisuse, most `os/signal`.

---

## File structure

- Modify: `src/dispatch/fs.rs` — add `OpenDescription::Pidfd { host_pid: i32, kq: Arc<Kqueue> }`; handle it in the fd close/poll/fstat match arms (follow each existing `OpenDescription::Epoll { .. }` arm).
- Modify: `src/dispatch/proc.rs` — `pidfd_open` handler; `CLONE_PIDFD` write in the clone/clone3 path (the runtime writes it post-fork, see below); `waitid(P_PIDFD)`.
- Modify: `src/syscall.rs` — route 434 (`pidfd_open`), 424 (`pidfd_send_signal`), and `waitid`(95) to the right handler; drop 434 from the "unhandled" set.
- Modify: `src/runtime.rs` — in the `ForkOutcome::Parent { child_pid }` arms, if the clone requested `CLONE_PIDFD`, allocate a Pidfd fd for `child_pid` and write it to the guest-supplied `pidfd` location.
- Create: `src/pidfd.rs` (optional) — `fn open_pidfd_kqueue(host_pid: i32) -> io::Result<Kqueue>` registering `EVFILT_PROC|NOTE_EXIT`, shared by `pidfd_open` and the CLONE_PIDFD path.
- Test: `fixtures/mn-probes/src/bin/pidfd_spawn.rs` — fork+exec a child, get a pidfd (clone CLONE_PIDFD or pidfd_open), poll it for exit, waitid it; differential vs Docker.

## Notes for the implementer

- `EVFILT_PROC` registration: `kevent` with `ident = host_pid`, `filter = EVFILT_PROC`, `fflags = NOTE_EXIT | NOTE_EXITSTATUS`, `flags = EV_ADD | EV_ONESHOT`. The kqueue fd is readable (via `poll`/`kevent`) once the process exits. Register at pidfd creation while the child is alive (register right after fork, before the parent might reap).
- Guest pidfd readiness for epoll/poll/ppoll: return the kqueue's own fd from the fd's `host_fd_for_poll` equivalent so the existing `io_wait`/epoll-kqueue path watches it with `EVFILT_READ` (a kqueue fd is itself pollable). Reuse exactly the mechanism `OpenDescription::Epoll` uses to be watched.
- `CLONE_PIDFD` flag = `0x00001000`. On clone with it set, the kernel writes the new pidfd (an int) to the address in the `parent_tid` argument (clone) or `clone_args.pidfd` (clone3). carrick's clone currently routes non-thread clones to `DispatchOutcome::Fork`; thread the `CLONE_PIDFD` request + target address out so the runtime writes the fd post-fork (it has `child_pid`).
- `waitid(P_PIDFD=3, pidfd, ...)`: resolve the pidfd → `host_pid`, then `waitpid(host_pid, …)` (reuse `wait4`'s status translation).
- `rseq(293)`: Go 1.24 registers rseq; carrick returns ENOSYS. Verify Go tolerates it (it should fall back). If it doesn't, make `rseq` return `0` with no effect (a benign no-op is safe — carrick doesn't migrate guest threads across host CPUs in a way that breaks rseq's contract for single-runtime use). Decide via the gate.

---

### Task 1: `pidfd_open(434)` returns a kqueue-backed fd

**Files:** `src/dispatch/fs.rs` (OpenDescription variant + arms), `src/dispatch/proc.rs` (handler), `src/syscall.rs` (route 434).

- [ ] **Step 1: Failing test** — extend the gate target: build `os/exec` and run `pidfd_open`-probe. Concretely, add `fixtures/mn-probes/src/bin/pidfd_spawn.rs`:

```rust
// Probe F — pidfd via pidfd_open on a forked child; poll for exit; waitid.
use std::process::Command;
fn main() {
    // Spawn a child that exits 7.
    let mut child = Command::new("/bin/true").spawn().expect("spawn");
    let pid = child.id() as i32;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if pidfd < 0 { println!("PIDFD_OPEN_FAIL errno={}", std::io::Error::last_os_error()); std::process::exit(1); }
    // Poll the pidfd for readability (child exit).
    let mut pfd = libc::pollfd { fd: pidfd as i32, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut pfd, 1, 5000) };
    let _ = child.wait();
    if n == 1 && (pfd.revents & libc::POLLIN) != 0 { println!("PIDFD_OK"); }
    else { println!("PIDFD_POLL_FAIL n={n} revents={}", pfd.revents); std::process::exit(1); }
}
```

- [ ] **Step 2: Run under Docker (oracle) + carrick** — Docker prints `PIDFD_OK`; carrick (pre-fix) `PIDFD_OPEN_FAIL errno=...function not implemented`.

- [ ] **Step 3: Add the OpenDescription variant + handler.** In `src/dispatch/fs.rs`, add `Pidfd { host_pid: i32, kq: std::sync::Arc<crate::darwin_kqueue::Kqueue> }` and handle it everywhere `OpenDescription::Epoll { .. }` is matched (close, fstat → S_IFIFO-ish/anon, poll-readiness via the kqueue fd). In `src/dispatch/proc.rs`, add `pidfd_open`: register `EVFILT_PROC|NOTE_EXIT` on `arg0` (host pid), allocate the fd, return it. Route 434 in `src/syscall.rs`.

- [ ] **Step 4: Run** — both print `PIDFD_OK`.

- [ ] **Step 5: Commit** `feat(pidfd): pidfd_open backed by kqueue EVFILT_PROC`.

### Task 2: `CLONE_PIDFD` writes the child pidfd

**Files:** `src/dispatch/proc.rs` (thread the flag+addr), `src/runtime.rs` (write post-fork).

- [ ] **Step 1: Failing test** — `os/exec` gate (`TestEcho`): carrick still fails (`forkExec` uses CLONE_PIDFD).
- [ ] **Step 2:** Extend `DispatchOutcome::Fork` to carry `pidfd_out: Option<u64>` (the guest address from `parent_tid` when `CLONE_PIDFD` set; from `clone_args.pidfd` for clone3). In `runtime.rs` `ForkOutcome::Parent { child_pid }` arms, when `pidfd_out` is `Some(addr)`, create a Pidfd fd for `child_pid` (same kqueue helper) and write its number to `addr`.
- [ ] **Step 3: Run** the `os/exec` gate.
- [ ] **Step 4: Commit** `feat(pidfd): honor CLONE_PIDFD in the fork path`.

### Task 3: `waitid(P_PIDFD)` + `pidfd_send_signal(424)`

**Files:** `src/dispatch/proc.rs`, `src/syscall.rs`.

- [ ] **Step 1:** `waitid` with `idtype == P_PIDFD(3)`: resolve fd→host_pid, `waitpid(host_pid,…)`, translate status (reuse `wait4` helpers). `pidfd_send_signal(424)`: fd→host_pid, `kill(host_pid, linux_to_macos_signum(sig))`.
- [ ] **Step 2: Run** `os/exec` gate + `pidfd_spawn` waitid path.
- [ ] **Step 3: Commit** `feat(pidfd): waitid(P_PIDFD) + pidfd_send_signal`.

### Task 4: rseq + full gate sweep

- [ ] **Step 1:** Run the gate over `sync os/exec os/signal`. If `rseq(293)` ENOSYS still breaks a test, make `rseq` a benign no-op-success in `src/dispatch/proc.rs` + route it; else leave ENOSYS.
- [ ] **Step 2:** Confirm `os/exec` carrick PASS count matches Docker (was 10 vs 36), `sync` TestMutexMisuse passes, `os/signal` pidfd failures clear.
- [ ] **Step 3:** Update `docs/superpowers/go-conformance-baseline.md`. Commit.

## Self-review

- **Spec coverage:** pidfd_open (T1), CLONE_PIDFD (T2), waitid/send_signal (T3), rseq + validation (T4) — covers the SP2b spec section.
- **Kernel-heavy-lifting:** every pidfd is a kqueue `EVFILT_PROC` on the real child; exit detection + readiness are the macOS kernel's job. ✓
- **Consistency:** `OpenDescription::Pidfd { host_pid, kq }` and the kqueue helper are used identically in T1/T2/T3.
- **Anchor:** T1 reproduces `pidfd_open`→ENOSYS; T2 reproduces the `forkExec` no-fork abort — both observed in the SP2b trace.
