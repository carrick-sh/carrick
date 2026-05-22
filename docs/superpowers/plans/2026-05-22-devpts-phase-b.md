# devpts Phase B (interactive `carrick run -t`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `carrick run -t <image> bash` gives a real interactive terminal driven from the user's macOS terminal — line editing, `isatty`, window resize, and job control (Ctrl-C → SIGINT to the foreground process group).

**Architecture:** carrick allocates a host pty (reusing `devpts::open_master`), saves the real terminal, `dup2`s the **slave** onto its own fds 0/1/2 so the guest's existing stdio passthrough drives the slave, puts the real terminal in raw mode, and runs a **relay thread** copying bytes between the real terminal and the pty **master** (plus `SIGWINCH`→`TIOCSWINSZ`). The guest's controlling tty is the slave; job control rides the host line discipline because guest pgrps are real macOS pgrps. The blocking guest run happens on the main thread; the relay runs concurrently and is torn down on exit.

**Tech Stack:** Rust, `libc` (poll, dup2, tcsetattr, tcgetpgrp/tcsetpgrp, sigaction, ioctl), `clap` (CLI), the existing `src/host_tty.rs` termios/raw helpers and `src/vfs/devpts.rs::open_master`.

**Spec:** `docs/superpowers/specs/2026-05-22-devpts-design.md` (Case B). Phase A (`/dev/ptmx` + `/dev/pts`) is complete and merged; this builds on its `open_master` helper and pty ioctl passthrough.

---

## Design decisions baked in (review these first)

1. **Flag:** a single `-t` / `--tty` on the `Run` subcommand allocates the pty + relay (implies interactive stdin and raw output, like `docker run -it` combined). Docker's separate `-i`/`-t` split is YAGNI for now; `--tty` does both. `shell`/`exec` subcommands are out of scope (follow-up; they can call the same `PtyRelay`).
2. **fd strategy:** carrick `dup2`s the slave onto host fds 0/1/2 and reuses the existing stdio passthrough, rather than installing `PtySlave` `OpenDescription`s for 0/1/2 (which would fight the `is_stdio_fd` special-casing). Consequence: the stdio ioctl handlers must passthrough termios/winsize/pgrp to the host fd when fd 0/1/2 is a real tty — termios/winsize already do (`host_isatty` gate); **pgrp does not yet** (it's faked), so Task 7 adds it. This is the difference between "output renders" and "real job control."
3. **`-t` implies `--raw`** semantics (stream stdio, suppress the JSON `RunResult`): all terminal I/O goes through the relay.
4. **Relay teardown:** the relay thread exits when the master read returns EOF (guest closed all slave fds) OR a shutdown self-pipe is written. Raw mode is restored via an RAII guard so a panic/early-exit can't wedge the user's terminal.

If you disagree with #1 or #2, raise it before implementing — they shape several tasks.

---

## File Structure

- **Create** `src/pty_relay.rs` — `PtyRelay`: owns the host pty (master fd + slave fd), the saved real-terminal fds, the raw-mode guard, the relay thread handle, and the SIGWINCH wiring. One responsibility: bridge carrick's real terminal to a guest pty for the duration of an interactive run. Public surface: `PtyRelay::start(real_in, real_out) -> io::Result<PtyRelay>`, `PtyRelay::slave_fd(&self) -> i32`, `PtyRelay::stop(self)`.
- **Modify** `src/main.rs` — add `--tty`/`-t` to `Run`; in the run setup, when set, build a `PtyRelay`, `dup2` the slave onto 0/1/2, `set_stream_stdio(true)`, run the guest, then `relay.stop()`. Suppress the JSON result (like `raw`).
- **Modify** `src/dispatch/fs.rs` — stdio `TIOCGPGRP`/`TIOCSPGRP` ioctl arms passthrough to the host fd when it `host_isatty` (job control for the `-t` shell).
- **Modify** `src/host_tty.rs` — add a `make_raw(fd) -> io::Result<()>` helper (cfmakeraw-style) if not already present, reusing the existing termios save/restore tracking so restoration is automatic.
- **Modify** `src/lib.rs` — `pub mod pty_relay;`.
- **Create** `tests/pty_relay.rs` — unit tests for the relay byte-copy + lifecycle, driven by pty pairs (no real tty needed).
- **Create/modify** `tests/cli.rs` or a new `tests/interactive_tty.rs` — an e2e smoke test that drives `carrick run -t` from a pty harness.

---

## Task 1: `--tty` / `-t` CLI flag

**Files:**
- Modify: `src/main.rs` (the `Run` variant of `enum Commands`, ~line 83; and the `Commands::Run { .. }` handler, ~line 395)

- [ ] **Step 1: Write the failing test**

In `tests/cli.rs` (it already tests CLI parsing — match its style; if it shells out to the binary, instead add a parse-level test if the `Commands` enum is exposed, otherwise assert `carrick run --help` lists `--tty`):

```rust
#[test]
fn run_accepts_tty_flag() {
    // The binary must accept `-t`/`--tty` on `run` without an "unexpected
    // argument" error. Use the built binary path helper this file already uses.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["run", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("--tty"), "run --help should mention --tty:\n{help}");
}
```

- [ ] **Step 2: Run it, confirm it fails**

Run: `cargo test --test cli run_accepts_tty_flag`
Expected: FAIL — `--tty` not in help.

- [ ] **Step 3: Add the flag**

In the `Run` variant (near the existing `raw: bool` at ~line 92):

```rust
        /// Allocate a pseudo-terminal and run interactively, bridging the
        /// guest's stdin/stdout to this terminal (like `docker run -it`).
        /// Implies raw stdio.
        #[arg(short = 't', long = "tty")]
        tty: bool,
```

In the `Commands::Run { .. }` destructure (~line 399), add `tty,` to the bound fields.

- [ ] **Step 4: Run test, confirm pass**

Run: `cargo test --test cli run_accepts_tty_flag`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs tests/cli.rs
git commit -m "cli: add -t/--tty flag to run (interactive pty)"
```

---

## Task 2: `PtyRelay` allocation (master + slave)

**Files:**
- Create: `src/pty_relay.rs`
- Modify: `src/lib.rs` (`pub mod pty_relay;`)
- Test: inline `#[cfg(test)]` in `src/pty_relay.rs`

- [ ] **Step 1: Write the failing test**

```rust
// src/pty_relay.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_opens_master_and_tty_slave() {
        let pty = PtyPair::allocate().expect("allocate pty");
        assert!(pty.master_fd >= 0);
        assert!(pty.slave_fd >= 0);
        // The slave is a real tty.
        assert_eq!(unsafe { libc::isatty(pty.slave_fd) }, 1);
        // master and slave are different host fds.
        assert_ne!(pty.master_fd, pty.slave_fd);
        // cleanup
        unsafe { libc::close(pty.master_fd) };
        unsafe { libc::close(pty.slave_fd) };
    }
}
```

- [ ] **Step 2: Run it, confirm it fails**

Run: `cargo test --lib pty_relay::tests::allocate_opens_master_and_tty_slave` (after adding `pub mod pty_relay;` to lib.rs so it compiles; the test fails because `PtyPair` doesn't exist).
Expected: FAIL.

- [ ] **Step 3: Implement allocation**

```rust
// src/pty_relay.rs  (top)
//! Interactive pty bridge for `carrick run -t`. carrick allocates a host
//! pty, hands the slave to the guest as fds 0/1/2, and relays bytes between
//! the user's real terminal and the master while the guest runs.

use std::ffi::CString;
use std::io;

/// A freshly-allocated host pty (master + already-opened slave).
pub struct PtyPair {
    pub master_fd: i32,
    pub slave_fd: i32,
}

impl PtyPair {
    /// Allocate via posix_openpt + open the slave. Reuses Phase A's
    /// `open_master` (posix_openpt/grantpt/unlockpt/ptsname).
    pub fn allocate() -> io::Result<Self> {
        let (master_fd, slave_name) = crate::vfs::devpts::open_master(false)
            .map_err(io::Error::from_raw_os_error)?;
        let cname = CString::new(slave_name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: cname is a valid NUL-terminated slave device path.
        let slave_fd = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        if slave_fd < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(master_fd) };
            return Err(e);
        }
        Ok(Self { master_fd, slave_fd })
    }
}
```

Ensure `open_master` is reachable: it is `pub fn` in `src/vfs/devpts.rs`; confirm `crate::vfs::devpts` is accessible (the module is `pub mod devpts;` in `src/vfs/mod.rs`). If `vfs` isn't `pub` at crate root, use the existing re-export path; adjust the call accordingly (grep `pub mod vfs` / `pub use` in src/lib.rs).

- [ ] **Step 4: Run test, confirm pass**

Run: `cargo test --lib pty_relay::tests::allocate_opens_master_and_tty_slave`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pty_relay.rs src/lib.rs
git commit -m "pty_relay: allocate host pty pair (reuses open_master)"
```

---

## Task 3: raw-mode helper with auto-restore

**Files:**
- Modify: `src/host_tty.rs` (add `make_raw`)
- Test: inline in `src/host_tty.rs`

`src/host_tty.rs` already tracks and restores fd-0 termios (`arm_stdin_restore`/`restore_stdin_termios`/`set_host_termios_tracking`). Add a `make_raw(fd)` that records the current termios (for restore) then applies raw mode.

- [ ] **Step 1: Write the failing test**

```rust
// src/host_tty.rs  #[cfg(test)] mod tests
    #[test]
    fn make_raw_clears_icanon_and_echo_then_restore() {
        // Drive via a pty slave (a real tty) so tcgetattr/tcsetattr work
        // without touching the test runner's terminal.
        let (master, slave) = open_test_pty();
        // Cooked initially.
        let before = unsafe { let mut t: libc::termios = std::mem::zeroed(); libc::tcgetattr(slave, &mut t); t };
        assert!(before.c_lflag & (libc::ICANON | libc::ECHO) as u64 != 0);
        make_raw(slave).unwrap();
        let raw = unsafe { let mut t: libc::termios = std::mem::zeroed(); libc::tcgetattr(slave, &mut t); t };
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO) as u64, 0, "raw must clear ICANON|ECHO");
        unsafe { libc::close(master); libc::close(slave); }
    }

    fn open_test_pty() -> (i32, i32) {
        let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        unsafe { libc::grantpt(m); libc::unlockpt(m); }
        let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
        let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        (m, s)
    }
```

- [ ] **Step 2: Run it, confirm it fails**

Run: `cargo test --lib host_tty::tests::make_raw_clears_icanon_and_echo_then_restore`
Expected: FAIL — `make_raw` not found.

- [ ] **Step 3: Implement `make_raw`**

```rust
// src/host_tty.rs
/// Put `fd` into raw mode (cfmakeraw semantics) after recording its current
/// termios for restoration via the existing dirty-tracking guard. Returns an
/// error if `fd` is not a tty.
pub fn make_raw(fd: i32) -> std::io::Result<()> {
    // SAFETY: fd is checked by tcgetattr; termios is a valid out-param.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    mark_dirty(fd); // record original for restore (existing mechanism)
    // SAFETY: cfmakeraw mutates the termios in place.
    unsafe { libc::cfmakeraw(&mut t) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
```

`mark_dirty` is the existing private fn (host_tty.rs:360) that snapshots the fd's termios so `restore_stdin_termios()` can put it back; confirm its signature and that calling it before `cfmakeraw` records the cooked state. If `mark_dirty` only handles fd 0, generalize it or snapshot here into the same store keyed by fd. Read host_tty.rs:340-410 and integrate with the existing restore path so `restore_stdin_termios()` (called on shutdown) restores this fd.

- [ ] **Step 4: Run test, confirm pass**

Run: `cargo test --lib host_tty::tests::make_raw_clears_icanon_and_echo_then_restore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/host_tty.rs
git commit -m "host_tty: add make_raw with restore tracking"
```

---

## Task 4: the relay loop (bidirectional, poll-based, clean shutdown)

**Files:**
- Modify: `src/pty_relay.rs` (add `start`, the relay thread, `stop`, `slave_fd`, a shutdown self-pipe, RAII raw-mode + restore)
- Test: inline in `src/pty_relay.rs`

- [ ] **Step 1: Write the failing test (byte round-trip through the relay, no real tty)**

```rust
// src/pty_relay.rs  #[cfg(test)] mod tests
    #[test]
    fn relay_copies_both_directions_and_stops_on_eof() {
        use std::io::{Read, Write};
        use std::os::unix::io::FromRawFd;
        // Simulate the "real terminal" with a socketpair; the relay treats one
        // end as real_in/real_out. The pty pair is the guest side.
        let (real_app, real_term) = socketpair(); // real_app = test drives it; real_term = relay's "terminal"
        let relay = PtyRelay::start_for_test(real_term, real_term).unwrap();
        let slave = relay.slave_fd();

        // Data typed at the "terminal" must reach the slave (what the guest reads).
        let mut app = unsafe { std::fs::File::from_raw_fd(real_app) };
        app.write_all(b"hi\n").unwrap();
        let mut buf = [0u8; 3];
        let mut slave_f = unsafe { std::fs::File::from_raw_fd(slave) };
        slave_f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hi\n");

        // Data the guest writes to the slave must reach the "terminal".
        slave_f.write_all(b"OK").unwrap();
        let mut buf2 = [0u8; 2];
        app.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2, b"OK");

        std::mem::forget(slave_f); // relay owns slave fd lifetime
        relay.stop();
    }
```

(Provide a `socketpair()` test helper and a `start_for_test(real_in, real_out)` constructor that skips raw-mode/SIGWINCH — those need a real tty — and only exercises the byte-copy loop over arbitrary fds. The production `start` adds raw-mode + SIGWINCH on top. This keeps the core relay logic unit-testable without a controlling terminal.)

- [ ] **Step 2: Run it, confirm it fails**

Run: `cargo test --lib pty_relay::tests::relay_copies_both_directions_and_stops_on_eof`
Expected: FAIL — methods not implemented.

- [ ] **Step 3: Implement the relay**

```rust
// src/pty_relay.rs
use std::os::unix::io::RawFd;
use std::thread::JoinHandle;

pub struct PtyRelay {
    pair: PtyPair,
    real_out: RawFd,
    shutdown_w: RawFd,
    thread: Option<JoinHandle<()>>,
    raw_active: bool, // true if make_raw was applied to real_in (production path)
    real_in_for_restore: RawFd,
}

impl PtyRelay {
    pub fn slave_fd(&self) -> i32 { self.pair.slave_fd }

    /// Production entry: allocate a pty, put `real_in` in raw mode, start the
    /// relay between (real_in, real_out) and the master. `real_in`/`real_out`
    /// are the user's terminal fds (duplicated by the caller so dup2(slave,0/1/2)
    /// doesn't clobber them).
    pub fn start(real_in: RawFd, real_out: RawFd) -> std::io::Result<Self> {
        crate::host_tty::make_raw(real_in)?; // restored on stop()
        let mut relay = Self::start_inner(PtyPair::allocate()?, real_in, real_out)?;
        relay.raw_active = true;
        Ok(relay)
    }

    #[cfg(test)]
    pub fn start_for_test(real_in: RawFd, real_out: RawFd) -> std::io::Result<Self> {
        let mut relay = Self::start_inner(PtyPair::allocate()?, real_in, real_out)?;
        relay.raw_active = false;
        Ok(relay)
    }

    fn start_inner(pair: PtyPair, real_in: RawFd, real_out: RawFd) -> std::io::Result<Self> {
        // self-pipe for shutdown wakeup
        let mut sp = [0i32; 2];
        // SAFETY: sp is a 2-int array for pipe(2).
        if unsafe { libc::pipe(sp.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let (shutdown_r, shutdown_w) = (sp[0], sp[1]);
        let master = pair.master_fd;
        let thread = std::thread::Builder::new()
            .name("pty-relay".into())
            .spawn(move || relay_loop(real_in, real_out, master, shutdown_r))?;
        Ok(Self {
            pair,
            real_out,
            shutdown_w,
            thread: Some(thread),
            raw_active: false,
            real_in_for_restore: real_in,
        })
    }

    /// Stop the relay, restore the terminal, close the pty.
    pub fn stop(mut self) {
        // wake the relay's poll() so it exits
        let _ = unsafe { libc::write(self.shutdown_w, b"x".as_ptr().cast(), 1) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if self.raw_active {
            crate::host_tty::restore_stdin_termios(); // restores tracked fds
            let _ = self.real_in_for_restore;
        }
        unsafe {
            libc::close(self.shutdown_w);
            libc::close(self.pair.master_fd);
            libc::close(self.pair.slave_fd);
        }
    }
}

/// Copy bytes both ways until the master hits EOF (guest closed the slave) or
/// the shutdown pipe is signalled. Uses poll(2) so neither direction starves.
fn relay_loop(real_in: RawFd, real_out: RawFd, master: RawFd, shutdown_r: RawFd) {
    let mut fds = [
        libc::pollfd { fd: real_in, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: shutdown_r, events: libc::POLLIN, revents: 0 },
    ];
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: fds is a valid 3-element pollfd array.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 3, -1) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted { continue; }
            break;
        }
        if fds[2].revents & libc::POLLIN != 0 { break; } // shutdown
        // real terminal -> master (what the user types)
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(real_in, &mut buf) {
                Some(0) | None => break,
                Some(k) => { if write_all_fd(master, &buf[..k]).is_none() { break; } }
            }
        }
        // master -> real terminal (what the guest prints)
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match read_fd(master, &mut buf) {
                Some(0) | None => break, // guest exited / closed slave
                Some(k) => { if write_all_fd(real_out, &buf[..k]).is_none() { break; } }
            }
        }
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> Option<usize> {
    // SAFETY: buf is a valid mutable slice.
    let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if r < 0 { None } else { Some(r as usize) }
}

fn write_all_fd(fd: RawFd, mut data: &[u8]) -> Option<()> {
    while !data.is_empty() {
        // SAFETY: data is a valid slice.
        let w = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if w <= 0 { return None; }
        data = &data[w as usize..];
    }
    Some(())
}
```

Add the test `socketpair()` helper:

```rust
    #[cfg(test)]
    fn socketpair() -> (i32, i32) {
        let mut sv = [0i32; 2];
        // SAFETY: sv is a 2-int array for socketpair(2).
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
        (sv[0], sv[1])
    }
```

NOTE on the test: when `real_in == real_out` (the test passes the same socket fd for both), the relay reads typed bytes from it and writes guest output back to it — the test drives the *other* socketpair end. Confirm the relay never echoes real_in→real_out directly (it only bridges to/from the master), so there's no loopback storm.

- [ ] **Step 4: Run test, confirm pass**

Run: `cargo test --lib pty_relay::tests::relay_copies_both_directions_and_stops_on_eof`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pty_relay.rs
git commit -m "pty_relay: poll-based bidirectional relay with clean shutdown"
```

---

## Task 5: SIGWINCH → propagate window size to the master

**Files:**
- Modify: `src/pty_relay.rs` (capture initial winsize at `start`; install a SIGWINCH handler that re-reads `real_in` winsize and sets it on the master)
- Test: inline in `src/pty_relay.rs` (test the propagation function directly, not the signal)

- [ ] **Step 1: Write the failing test**

```rust
// src/pty_relay.rs  tests
    #[test]
    fn propagate_winsize_copies_rows_cols_to_master() {
        let from = open_test_pty(); // (master, slave) — use the slave as a tty source
        let to = open_test_pty();
        // Set a known winsize on `from.1` (a tty).
        let ws = libc::winsize { ws_row: 40, ws_col: 100, ws_xpixel: 0, ws_ypixel: 0 };
        unsafe { libc::ioctl(from.1, libc::TIOCSWINSZ, &ws) };
        // Propagate from.1 -> to.0 (master).
        propagate_winsize(from.1, to.0);
        let mut got: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { libc::ioctl(to.0, libc::TIOCGWINSZ, &mut got) };
        assert_eq!((got.ws_row, got.ws_col), (40, 100));
        unsafe { libc::close(from.0); libc::close(from.1); libc::close(to.0); libc::close(to.1); }
    }
```

(`open_test_pty` returns `(master, slave)` — reuse the helper from Task 3's tests or hoist it to the shared test module.)

- [ ] **Step 2: Run it, confirm it fails**

Run: `cargo test --lib pty_relay::tests::propagate_winsize_copies_rows_cols_to_master`
Expected: FAIL — `propagate_winsize` not found.

- [ ] **Step 3: Implement winsize propagation + SIGWINCH wiring**

```rust
// src/pty_relay.rs
/// Read the window size from `tty_fd` and apply it to `master_fd` so the
/// guest's slave sees the resize.
pub(crate) fn propagate_winsize(tty_fd: RawFd, master_fd: RawFd) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: both fds are live; ws is a valid winsize buffer.
    if unsafe { libc::ioctl(tty_fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
        unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &ws) };
    }
}
```

SIGWINCH handler wiring (in `start`): SIGWINCH must reach the relay. The safe pattern given carrick already has a `host_signal` self-pipe/atomic mechanism: register a handler that sets an `AtomicBool` (or writes the shutdown-style self-pipe with a distinct byte), and have `relay_loop` call `propagate_winsize(real_in, master)` when it observes the SIGWINCH signal. Concretely: add a second self-pipe (or reuse one with tagged bytes) that the SIGWINCH handler writes to; add its read end to the `poll` set; on readiness, drain it and call `propagate_winsize`. Do the initial `propagate_winsize(real_in, master)` once at `start` so the guest gets the correct size immediately. Install the handler with `sigaction(SIGWINCH, …)` in `start` and remove/restore it in `stop`. Read `src/host_signal.rs` for the existing async-signal-safe self-pipe pattern and reuse it rather than inventing one.

ASYNC-SIGNAL-SAFETY: the SIGWINCH handler must only do `write()` to the self-pipe (async-signal-safe). Do NOT call ioctl from the handler. The poll loop does the ioctl.

- [ ] **Step 4: Run test, confirm pass**

Run: `cargo test --lib pty_relay::tests::propagate_winsize_copies_rows_cols_to_master`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pty_relay.rs
git commit -m "pty_relay: SIGWINCH propagates window size to the guest pty"
```

---

## Task 6: wire `-t` into the `run` command

**Files:**
- Modify: `src/main.rs` (both fs-backend arms of `Commands::Run`)

This is integration; verify via the e2e smoke test in Task 8 (it can't be cleanly unit-tested because it needs a controlling tty).

- [ ] **Step 1: Implement the wiring**

In each `Commands::Run` fs arm, before calling the runtime, when `tty` is set:

```rust
            // Interactive pty: save the real terminal, hand the guest the
            // slave as fds 0/1/2, relay master<->real terminal.
            let relay = if tty {
                // Duplicate the real terminal fds so dup2(slave,0/1/2) below
                // doesn't clobber the relay's view of the user's terminal.
                let real_in = unsafe { libc::dup(0) };
                let real_out = unsafe { libc::dup(1) };
                let r = carrick::pty_relay::PtyRelay::start(real_in, real_out)
                    .context("failed to allocate interactive pty")?;
                let slave = r.slave_fd();
                // SAFETY: redirect guest stdio to the pty slave.
                unsafe {
                    libc::dup2(slave, 0);
                    libc::dup2(slave, 1);
                    libc::dup2(slave, 2);
                }
                dispatcher.set_stream_stdio(true);
                Some(r)
            } else {
                if raw { dispatcher.set_stream_stdio(true); }
                None
            };
```

After the `run_*` call returns its `result`, before emitting output:

```rust
            if let Some(relay) = relay {
                relay.stop(); // restores the terminal, tears down the relay
            }
```

And suppress the JSON dump when `tty` (treat like `raw`): wherever the code does `if raw { emit_raw(&result); ... } else { print json }`, change the condition to `if raw || tty`. For `-t`, the guest's output already went to the terminal via the relay, so `emit_raw` should NOT re-print buffered stdout (under `set_stream_stdio` the buffer is empty, so `emit_raw` is a no-op for stdout — verify, and if it would double-print, skip `emit_raw` entirely for `tty`).

CAUTION — ordering with fork: carrick forks guest processes that inherit fds 0/1/2 = slave. The `dup2`s happen in the carrick parent before the run, so all guest processes inherit the slave. Confirm the runtime doesn't itself reset 0/1/2. Confirm `relay.stop()` runs even on the error path (use a guard or explicit stop before `?`-returns; simplest: don't `?`-return between `start` and `stop` — capture the result and stop first). If the run can early-return via `?`, wrap so the terminal is always restored (the raw-mode RAII guard in host_tty also protects against this, but stop() should still run).

- [ ] **Step 2: Build + manual sanity (deferred to Task 8 for the real check)**

Run: `cargo build && ./scripts/build-signed.sh`
Expected: builds clean. (Functional check is Task 8.)

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "cli: wire -t to allocate an interactive pty and relay the terminal"
```

---

## Task 7: job-control pgrp passthrough for stdio ttys

**Files:**
- Modify: `src/dispatch/fs.rs` (the stdio `LINUX_TIOCGPGRP`/`LINUX_TIOCSPGRP` ioctl arms, ~lines 1006-1031)
- Test: `tests/syscall_fs.rs`

The `-t` shell does `tcsetpgrp(0, pgrp)` to set the foreground group. fd 0 is a bare stdio fd (dup2'd slave), so it hits the stdio ioctl arms, which currently FAKE pgrp (return `LINUX_BOOTSTRAP_PGID` / EPERM). Make them passthrough to the host fd when it's a real tty, so job control rides the host line discipline (Ctrl-C → SIGINT to the real foreground pgrp, which contains the real guest processes).

- [ ] **Step 1: Write the failing test**

```rust
// tests/syscall_fs.rs — drive a dispatcher whose fd 0 is a real tty (a pty slave).
#[test]
fn stdio_tty_pgrp_roundtrips_through_host() {
    // Install a pty slave as host fd 0 for this test process, then a dispatcher
    // TIOCGPGRP on fd 0 must reflect the host tcgetpgrp, and TIOCSPGRP must not
    // be the faked BOOTSTRAP value path. Build a pty, dup the slave to a spare
    // fd, and call the dispatcher ioctl against that fd via the stdio path.
    // (If wiring a real fd-0 in a unit test is impractical, assert the simpler
    // invariant: TIOCGPGRP on a stdio fd that host_isatty returns the host
    // tcgetpgrp value, not LINUX_BOOTSTRAP_PGID.)
    // See implementation note below; keep this test honest — if it can't
    // exercise a real tty fd deterministically, test `pgrp_passthrough` as a
    // free fn over an explicit host fd instead.
}
```

IMPLEMENTATION NOTE for the test: rather than hijack the test process's fd 0, factor the passthrough into a free fn `fn tty_pgrp_get(host_fd) -> i32` / `fn tty_pgrp_set(host_fd, pgrp) -> Result<(),i32>` and unit-test those directly against a pty slave fd (open a pty, `tcsetpgrp(slave, getpgrp())`, assert `tty_pgrp_get(slave) == getpgrp()`). This is deterministic and doesn't touch fd 0. Write THIS test (concrete, in `src/dispatch/fs.rs` tests or tests/syscall_fs.rs):

```rust
    #[test]
    fn tty_pgrp_get_reflects_host_foreground_group() {
        // open a pty, set fg pgrp on the slave, read it back via the helper.
        let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        unsafe { libc::grantpt(m); libc::unlockpt(m); }
        let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
        let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
        // Note: setting fg pgrp requires the slave to be a controlling tty for
        // the session; in a test harness tcsetpgrp may EPERM. If so, assert the
        // get-path returns the host value or -1 consistently and that the code
        // does NOT return the faked BOOTSTRAP constant. Keep the assertion to
        // what the environment allows; the production value is the host kernel's.
        let _ = (m, s);
    }
```

(Be honest in this test about what the CI/test environment permits for `tcsetpgrp`; the real validation is Task 8's interactive Ctrl-C check. At minimum assert the code path calls `libc::tcgetpgrp(host_fd)` rather than returning `LINUX_BOOTSTRAP_PGID` for an isatty stdio fd.)

- [ ] **Step 2: Run it, confirm current behavior (faked)**

Run the test; confirm it fails against the faked pgrp path.

- [ ] **Step 3: Implement passthrough**

In the stdio `LINUX_TIOCGPGRP` arm (fs.rs ~1006): when `crate::host_tty::host_isatty(fd)` (fd is a real tty), return `libc::tcgetpgrp(fd)` written to `arg` instead of `LINUX_BOOTSTRAP_PGID`. Keep the `LINUX_BOOTSTRAP_PGID` fallback for the non-tty (headless) case. Symmetric for `LINUX_TIOCSPGRP` (~1019): when `host_isatty(fd)`, call `libc::tcsetpgrp(fd, pgrp)` and translate errno; keep the faked accept for non-tty. Mirror the structure of the pty-fd passthrough added in Phase A Task 6 (which already does this for `PtySlave`/`PtyMaster` fds) — reuse a shared helper if clean.

- [ ] **Step 4: Run test, confirm pass**

Run the test.
Expected: PASS (or the environment-appropriate assertion).

- [ ] **Step 5: Commit**

```bash
git add src/dispatch/fs.rs tests/syscall_fs.rs
git commit -m "dispatch: stdio tty pgrp ioctls passthrough to host (job control for -t)"
```

---

## Task 8: end-to-end interactive smoke test

**Files:**
- Create: `tests/interactive_tty.rs`

carrick `-t` needs a controlling tty on its stdin. The test allocates a pty, spawns `carrick run -t … <cmd>` with the pty slave as the child's stdin/stdout, writes input on the master, and asserts on the output.

- [ ] **Step 1: Write the e2e smoke test**

```rust
// tests/interactive_tty.rs
// Requires: a built+signed carrick (release) and Docker image available.
// Drives `carrick run -t debian:stable /bin/sh -c '...'` over a pty.
use std::io::{Read, Write};
use std::process::Command;
use std::time::Duration;

#[test]
#[ignore] // run explicitly: needs signed binary + image; not in the default unit run
fn interactive_run_sees_a_tty() {
    // Allocate a pty; child stdio = slave.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    unsafe { libc::grantpt(master); libc::unlockpt(master); }
    let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(master)) }.to_owned();
    let slave = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };

    let mut child = Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["run", "-t", "--fs", "host", "docker.io/library/debian:stable",
               "/bin/sh", "-c", "test -t 0 && echo IS_A_TTY; tty"])
        .stdin(unsafe { std::process::Stdio::from_raw_fd(slave) })
        .stdout(unsafe { std::process::Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { std::process::Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn().unwrap();

    std::thread::sleep(Duration::from_secs(30)); // image pull + boot bound
    let _ = child.kill();
    let mut out = String::new();
    let mut mf = unsafe { std::fs::File::from_raw_fd(master) };
    // Non-blocking-ish read of whatever the guest emitted onto the pty.
    let _ = mf.read_to_string(&mut out);
    assert!(out.contains("IS_A_TTY"), "guest stdin should be a tty under -t:\n{out}");
    assert!(out.contains("/dev/pts/"), "tty(1) should report /dev/pts/N:\n{out}");
}
```

(This test is `#[ignore]` by default — it needs the signed release binary, Docker, and is timing-based. It documents the executable contract and is run on demand. Refine the read to use the relay output if the harness flakes; the controller will run it manually in Task 9.)

- [ ] **Step 2: Build, sign, run the smoke test explicitly**

Run:
```bash
./scripts/build-signed.sh
cargo test --test interactive_tty -- --ignored --nocapture
```
Expected: `IS_A_TTY` and a `/dev/pts/N` path appear. If it flakes on timing, increase the bound or switch to reading until a sentinel.

- [ ] **Step 3: Commit**

```bash
git add tests/interactive_tty.rs
git commit -m "test: interactive -t e2e smoke (guest sees a /dev/pts tty)"
```

---

## Task 9: manual interactive verification + docs

**Files:**
- Modify: `docs/tier-b-demo-report.md` (or the devpts spec) — note Phase B complete + how to demo.

- [ ] **Step 1: Manual interactive check (the real proof)**

In a real terminal:
```bash
./scripts/build-signed.sh
./target/release/carrick run -t --fs host docker.io/library/debian:stable /bin/bash
```
Verify by hand:
- A shell prompt appears and line editing works (backspace, arrow keys, Ctrl-U).
- `ls`, `vi`/`less` render correctly (full-screen apps see a tty).
- **Ctrl-C** at the prompt and during `sleep 100` interrupts the foreground job (job control).
- Resize the terminal, run `stty size` or `tput cols` — reflects the new size (SIGWINCH).
- `exit` returns cleanly and the host terminal is restored (not stuck in raw mode).

Record the results in the doc. If Ctrl-C doesn't interrupt, Task 7's pgrp passthrough needs revisiting.

- [ ] **Step 2: Full gate suite**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --lib --tests
cargo test --lib && cargo test --test syscall_fs && cargo test --test pty_relay
./scripts/build-signed.sh && cargo test --test conformance -- --nocapture   # no devpts regression
```
Expected: all green; conformance still 38/38 (Phase B doesn't touch the single-process pty path).

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: devpts Phase B complete — interactive carrick run -t"
```

---

## Self-review notes

- **Spec coverage (Case B):** `-t` flag (Task 1), pty alloc (Task 2), raw mode (Task 3), relay loop (Task 4), SIGWINCH (Task 5), wiring + slave-as-stdio (Task 6), job control (Task 7), e2e (Task 8), manual verify + docs (Task 9). All Case-B bullets map to a task.
- **Honest testing:** the relay core (Task 4), raw mode (Task 3), winsize (Task 5), and pgrp helpers (Task 7) are unit-tested via pty pairs / socketpairs with no dependency on a real controlling terminal. The genuinely terminal-dependent behavior (full interactive shell, Ctrl-C, resize) is a documented manual check (Task 9) + an `#[ignore]`d pty-driven e2e (Task 8) — not faked.
- **Risk areas called out:** (a) `dup2(slave,0/1/2)` vs fork — slave inherited by guest children (Task 6 caution); (b) async-signal-safety of the SIGWINCH handler — handler only writes a self-pipe, poll loop does the ioctl (Task 5); (c) terminal restoration on panic/early-return — RAII guard in host_tty + explicit `stop()` (Tasks 3/6); (d) job control depends on guest pgrps being real host pgrps (true in carrick) + Task 7's pgrp passthrough.
- **Reuse:** `devpts::open_master` (pty alloc), `host_tty` termios/restore (raw mode), Phase A pty ioctl passthrough (model for Task 7), `host_signal` self-pipe pattern (SIGWINCH). No new dependencies.
- **Out of scope (follow-ups):** `-t` for `shell`/`exec` subcommands; separate Docker-style `-i`/`-t` semantics; the Phase A follow-ups (`DT_CHR`, splice-to-pty, `F_GETFL` access mode).
```
