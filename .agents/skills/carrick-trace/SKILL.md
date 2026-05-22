---
name: carrick-trace
description: >-
  Debug ANY guest problem in the carrick project (the Linux-binary-on-macOS HVF
  runtime) with `carrick trace`, its in-process libdtrace tracer. Consult this
  before debugging or tracing a carrick guest: when a `carrick run`/`run-elf`
  hangs, wedges, exits early, or returns the wrong result; a syscall gives
  ENOSYS/EINVAL/EAGAIN; a pipe/fork/dup/fd bug, an undelivered signal, or
  apt/dpkg/a shell pipeline misbehaves; or to compare the guest's Linux syscalls
  against the macOS host syscalls carrick actually makes. The right technique is
  non-obvious and easy to get wrong — following forked children with progenyof,
  the pid-provider no-follow-fork trap, bounding runaway traces, reducing to a
  fast fixture, codesigning to avoid HV_DENIED — so skipping it wastes hours and
  yields misleading traces. Don't hand-roll one-off dtrace or add
  eprintln!/printf to a carrick guest; reach for this on any carrick guest
  debugging, hang, wedge, ENOSYS, or "why did the guest do that" question.
compatibility: >-
  Requires the carrick project + a release build codesigned with the HVF
  entitlement, macOS on Apple silicon, and root (carrick trace auto-sudos for
  /dev/dtrace).
metadata:
  version: "1.0"
  upstream-scripts: carrick repo scripts/*.d and src/probes.rs
license: Apache-2.0 OR MIT
---

# Debugging carrick with `carrick trace`

`carrick trace` is carrick's own DTrace front-end: it compiles a D script via
libdtrace in-process, spawns the traced `carrick` child under
`dtrace_proc_create`, and streams events. It is THE tracer for this project —
improve and use it rather than hand-rolling one-off `dtrace -s` invocations or
sprinkling `eprintln!`. (See [[feedback_carrick_trace_tracing]].)

## Invocation

```
carrick trace [--script <file.d>] [--trace-out <file>] [--flowindent] -- <run-args>
```

- Everything after `--` is a normal carrick command, e.g. `run ubuntu:24.04 /usr/bin/sh -c '…'` or `run-elf <static-elf>`.
- It **auto-sudos** (DTrace needs `/dev/dtrace` / root). Don't prefix `sudo` yourself. (NOPASSWD covers the carrick binary path + `/usr/sbin/dtrace`, so `sudo -n true` failing does NOT mean the trace needs a password — the binary path is what's allowlisted.)
- With no `--script`, it runs the bundled `scripts/syscalls.d` (per-syscall stream + a frequency-sorted aggregation at exit).
- `-s/--script <file.d>` runs a custom/targeted D program. Writing a focused script is almost always faster than reading the full stream.
- `-o/--trace-out <file>` writes the probe stream + aggregations to `<file>` instead of stdout. **Essential for tracing an interactive `-t` guest** (or any run whose own stdout you care about): without it the probe output intermixes with the guest's terminal stream and is unreadable. With it, the guest pty stays clean and you read events from `<file>` (it's written as root, so `cat`/`grep` it; `rm` may need sudo). The file is opened with `fopen("w")` (truncates per run).

`$target` inside the script binds to the spawned carrick pid.

## Operating rules (learned the hard way)

1. **Always follow the whole process tree with `progenyof($target)`.** A guest
   `fork`/`clone` becomes a real macOS child carrick process that re-registers
   its USDT probes, so `carrick*:::` probes fire for children too — but only if
   the predicate is `/pid == $target || progenyof($target)/`. Forget this and
   you only see the main process and miss everything in forked children.

2. **The `pid$target` provider does NOT follow fork — use `syscall::`/`carrick*::`
   instead for anything in a forked child.** The `pid` provider is bound to a
   single static PID and DTrace actively removes its probes from a newly-forked
   child (and they're absent after exec). So `pid$target::*foo*:entry` silently
   never fires for grandchildren. Kernel-side providers (`syscall::`, carrick's
   USDT) honor `progenyof` and are what you want. (To name a function in a
   child, spawn a fresh `dtrace -p <childpid>` via `proc:::start`, but that's
   rarely worth it — prefer the USDT/syscall route.)

3. **Bound every trace so it can't run away.** Add a host `timeout N` AND, in
   the script, `tick-1s { secs++ } tick-1s /secs >= N/ { exit(0); }`. A guest
   that hangs will otherwise stream forever.

4. **Kill stale carrick processes before each run:** `pkill -9 -f carrick`.
   Leftover hung guests from a prior run get caught by `progenyof` and pollute
   counts/events badly — this is the #1 source of confusing traces.

5. **Reduce to a fast Rust fixture before tracing anything big.** Tracing apt or
   a shell is millions of events. The `fixtures/linux-aarch64-hello` crate holds
   tiny raw-syscall ELF repros (build with `scripts/build-linux-fixtures.sh`,
   run via `carrick run-elf`). A ~15-syscall fixture that reproduces the bug
   turns each hypothesis into a <10s loop. Add a new fixture mirroring the
   failing pattern when one doesn't exist.

6. **Build + re-sign before tracing, or you get HV_DENIED (0xfae94007).**
   `cargo build --release` then
   `codesign --force --sign - --entitlements scripts/entitlements.plist target/release/carrick`.
   (See [[feedback_carrick_trace_and_match_footgun]].)

7. **A D-script compile error silently kills the trace — and looks like the
   guest dying.** libdtrace fails `dtrace_program_strcompile` BEFORE the child
   spawns, `carrick trace` exits, and a driver pty sees an immediate EIO with no
   obvious cause. If a trace produces an empty `--trace-out` file or an instant
   EIO, suspect the script, not carrick. Constructs that bite:
   - **`cond ? printf(...) : 1;` as a statement** — not valid D. Use a separate
     clause with the condition in the predicate instead.
   - **`copyin(...)` inside a predicate** — flaky/aborts; do the `copyin` in the
     clause **body**, gate the predicate on `arg0`/`arg2`/`arg3` only.
   - **`this->x` is clause-local** — it does NOT carry from a `syscall-entry`
     clause to the matching `syscall-return`. Use **`self->x`** (thread-local)
     to pair entry args (e.g. the fd) with the return value.
   - **`args[1]->pr_pid`-style stable-probe fields** — get them wrong and the
     program won't compile. When unsure, print the raw `arg2`/`argN` ints.
   Build the script up from the minimal known-good shape and add one clause at a
   time. Aggregations printed only in `END {}` are lost if the driver kills the
   child before the script's own `tick`/`exit` fires — let the `tick`-based
   `exit(0)` fire (size the driver's run > the tick budget) or print per-event
   and count with `grep | sort | uniq -c`.

8. **Interactive (`-t`) / driven traces: use `--trace-out` + drive over a pty.**
   To trace a scenario that needs input (Ctrl-C, Ctrl-Z, typed commands), run
   `carrick trace --trace-out /tmp/ev.out -- run -t … /bin/bash` with its
   stdin/stdout wired to a pty you drive from a small Python harness
   (`pty.openpty()` + `select`); send the keystrokes (`b"\x03"` = Ctrl-C,
   `b"\x1a"` = Ctrl-Z) and read the guest output from the pty master. Probe
   events go to `/tmp/ev.out` (clean, root-owned). sudo's password prompt (if
   any) goes to your real `/dev/tty`, not the harness pty, so the harness still
   works.

## The three probe families — triangulate guest ↔ host

Combine them in one script to correlate what the guest asked for with what
carrick actually did on macOS. Full arg tables: `references/probes.md`.

- **carrick USDT** (`carrick*:::`): the guest's Linux syscalls and carrick
  internals. Key ones: `syscall-entry`/`syscall-return` (`arg0`=Linux sysno,
  `arg1`=name, `arg2`=retval, `arg3`=errno; entry's `arg2` is the address of the
  6-u64 args — `copyin(arg2,48)`), `host-pipe-io` (the *host* fd a guest
  read/write hit + byte count), `fork-post`, `guest-exit`, `unhandled-syscall`,
  `path-open`, `signal-inject`.
- **macOS native `syscall::`**: the real host syscalls carrick issues
  (`pipe`, `read`/`write`, `close`, `fcntl`, `setrlimit`, `fork`). This is the
  **Linux-guest-vs-macOS-host comparison** — the most powerful move here. It is
  what reveals e.g. a guest `read` returning `0` (EOF) while the host
  `libc::read` returned `-1`, or a host write succeeding to a fd the reader
  can't see.
- **`profile-997`** (sampling): when something "hangs," sample first. A handful
  of syscalls then silence == *blocked* (in a syscall), not a busy spin — that
  reframes the whole investigation. Bound it with the `tick`/`exit` pattern.

## Workflow

1. Reproduce with a minimal fixture (or the smallest `run` command). Confirm the
   symptom and whether it's a wrong-value, an error, or a hang.
2. For a hang: profile first (`profile-997` + syscall counts) to learn blocked
   vs spinning.
3. Write a targeted script over the suspect area (fds, fork, signals…) using
   the relevant probes + `progenyof`. Print retval/errno and correlate guest
   syscalls with host syscalls.
4. Read the ordered events per pid. Use `fork-post child=<pid>` to map the
   process tree, then `grep "\[<pid> "` a single actor.
5. Form ONE hypothesis, then **disprove or confirm it cheaply with a probe**
   before changing code (e.g. trace `fcntl(F_DUPFD_CLOEXEC)` to prove an fd
   relocation engaged). Don't fix on a hunch.

## Templates and ready-made scripts

This skill bundles reusable D programs in [`scripts/`](scripts/). Run one with
`carrick trace --script <path-to>/scripts/<x>.d -- <run-args>` (in the carrick
repo the same files also live at the repo's top-level `scripts/`):

- [`scripts/trace-host-fds.d`](scripts/trace-host-fds.d) — correlate guest pipe
  I/O (`host-pipe-io`) with host `pipe`/`close`/`write`/`dup` syscalls; the
  go-to for pipe/fd bugs.
- [`scripts/trace-profile.d`](scripts/trace-profile.d) — `profile-997`
  host-stack sampler + syscall mix, bounded by a tick/exit.
- [`scripts/trace-failing-child.d`](scripts/trace-failing-child.d) — DTrace
  *speculations*: record every process's syscalls but COMMIT only for a child
  that exits non-zero without exec'ing (the fork-then-`_exit` failure class).
  Use when one of hundreds of forked children fails.
- [`scripts/trace-relocation.d`](scripts/trace-relocation.d) — worked example of
  proving/disproving a host-fd hypothesis (`setrlimit`, `fcntl(F_DUPFD_CLOEXEC)`).

carrick also ships two D programs **inside the binary** (no `--script` needed):
the default per-syscall stream + aggregation (`carrick trace -- …`), and a
guest AArch64 frame-pointer stack walker via `carrick trace --stack` (needs a
frame-pointer guest — Ubuntu 24.04, NOT raw-asm fixtures or stock Debian).

Minimal targeted-script skeleton:

```d
#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 63 || arg0 == 64)/   /* read|write */
{ printf("[%d] nr=%d ret=%d errno=%d\n", pid, arg0, (int)arg2, (int)arg3); }

carrick*:::host-pipe-io
/pid == $target || progenyof($target)/
{ printf("[%d]   host_fd=%d dir=%d n=%d\n", pid, (int)arg1, (int)arg2, (int)arg3); }

tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
```

## Symbolicating carrick (host) stacks

`ustack()` on the carrick PIE binary often prints raw hex. Build with symbols +
frame pointers so `atos`/dtrace can resolve:

```
RUSTFLAGS="-C force-frame-pointers=yes" CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release
```

Symbols are in the binary (`nm target/release/carrick` confirms). Then `atos -o
target/release/carrick -l <slide> <addr…>`, or — since a hung guest stays alive
— `atos`/`vmmap` the live process. Forked children share the parent's ASLR
slide. For the *guest* stack, use `--stack` / `guest_stack.d` with a
frame-pointer guest image.

See `references/probes.md` for the full USDT arg tables and a Linux aarch64
syscall-number cheat-sheet.
