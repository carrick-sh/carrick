# Diagnostics and debugging

Carrick is a syscall-translation layer, so almost every bug is "the guest asked
the macOS host for something and got the wrong answer." The tools below let you
watch that translation boundary from the host side without touching the guest
binary. Three of them are first-class subcommands of the `carrick` CLI
(`carrick trace`, `carrick debug …`, `carrick compat-report`); the rest are host
debug environment variables and an lldb plugin.

> [!IMPORTANT]
> The project method is **real debuggers and probes, not `eprintln!`/`printf`**.
> Reach for `carrick trace` (libdtrace) on a *reproducible* guest, and the lldb
> event ring on a *timing-sensitive* one that tracing perturbs. A guest is an
> unmodified Linux ELF: you cannot recompile it, and instrumenting carrick's own
> hot path with prints changes the schedule of the very races you are chasing.

All of these require a **codesigned** release binary (`just build`, i.e.
[`scripts/build-signed.sh`](../scripts/build-signed.sh)). A bare `cargo build`
strips the `com.apple.security.hypervisor` entitlement, so every run dies with
`HV_DENIED` (`0xfae94007`) before any guest syscall fires — see the
[README](../README.md) build notes.

---

## 1. `carrick trace` — in-process libdtrace tracer

```sh
carrick trace [-F/--flowindent] [-s/--script SCRIPT.d] [-o/--trace-out FILE] -- <cmd>
```

`carrick trace` is carrick's own DTrace front-end. It compiles a D script with
libdtrace **in-process**, spawns the traced `carrick` child under
`dtrace_proc_create`, and streams events. Everything after `--` is an ordinary
carrick invocation:

```sh
# Per-syscall stream + a frequency-sorted aggregation at exit (bundled syscalls.d)
carrick trace -- run ubuntu:24.04 /bin/echo hi

# A raw static-ELF fixture, with flow indentation
carrick trace -F -- run-elf fixtures/linux-aarch64-hello/hello

# A targeted custom probe, output to a file (keeps an interactive guest's tty clean)
carrick trace -s scripts/trace-host-fds.d -o /tmp/ev.out -- run -t alpine /bin/sh
```

**It auto-sudos.** libdtrace needs root (`/dev/dtrace`), so `carrick trace`
re-execs itself under `sudo`; do **not** prefix `sudo` yourself. The trace parent
keeps root for libdtrace while the traced guest child drops back to your original
uid/gid/groups (carried across `sudo`'s env-reset via hidden `--trace-uid` /
`--trace-gid` / `--trace-groups` / `--forward-env` args — CLI args survive `sudo`
where `CARRICK_*` env vars would be stripped).

### Reading the output

With no `-s`, the bundled [`scripts/syscalls.d`](../scripts/syscalls.d) runs:
each event is a per-syscall line tagged with the firing pid, and `END {}` prints
frequency-sorted aggregations (which syscalls, how often, top errnos). `-F`
indents each `entry`/`return` by call depth like `dtrace -F`. `-o FILE` writes
the probe stream and aggregations to `FILE` (opened `fopen("w")`, truncated per
run) instead of stdout, leaving the traced command's own stdio untouched — this
is **essential** when tracing an interactive `-t` guest, whose terminal stream
would otherwise interleave with probe lines and be unreadable. The file is
written as root: `cat`/`grep` it without sudo, `rm` may need sudo.

### USDT probe families

The probes are static USDT, wired at the translation boundaries via the `usdt`
crate (`crates/carrick-hvf/src/probes.rs`, `#[usdt::provider(provider =
"carrick")]`). Three families let you triangulate guest vs host:

- **carrick USDT (`carrick*:::`)** — the guest's Linux syscalls and carrick
  internals: `syscall-entry`/`syscall-return` (`arg0`=Linux sysno, `arg1`=name,
  `arg2`=retval, `arg3`=errno; entry's `arg2` is the *host* address of the 6-u64
  arg array, so `copyin(arg2,48)` works), `host-pipe-io`, `fork-pre`/`fork-post`,
  `path-open`, `signal-inject`, `unhandled-syscall`, plus the page-table
  Pause-Modify-Resume probes (`pt-pause-*`) and supervisor fork/foreground probes.
- **macOS native (`syscall::`)** — the *real* host syscalls carrick issues
  (`pipe`, `read`/`write`, `fcntl`, `fork`). Correlating these against the
  `carrick*:::` stream is the most powerful move available: it reveals e.g. a
  guest `read` returning EOF while the host `libc::read` returned `-1`.
- **`profile-997`** — a sampling profiler. For a hang, sample first: a burst of
  syscalls then silence means *blocked in a syscall*, not a busy spin.

> [!WARNING]
> A faster linker than `ld64` can silently break this. LLVM `lld`'s Mach-O port
> drops the `__DATA,__dof_carrick` section that `register_probes()` reads, so the
> provider registers empty and `carrick trace` emits nothing. Verify with
> `otool -l target/release/carrick | grep dof` and confirm events still fire.
> Set `CARRICK_DTRACE_DEBUG=1` to log probe registration (and any failure) at
> startup.

### Gotchas (the authoritative methodology lives in the `carrick-trace` skill)

> [!NOTE]
> The `carrick-trace` skill
> ([`.agents/skills/carrick-trace/SKILL.md`](../.agents/skills/carrick-trace/SKILL.md))
> is the canonical guide; consult it before any non-trivial trace. The points
> below are the load-bearing ones.

- **Follow the whole tree with `progenyof($target)`.** A guest `fork`/`clone`
  becomes a real macOS child carrick process that re-registers its USDT probes.
  Predicate on `/pid == $target || progenyof($target)/` or you miss everything in
  forked children. `$target` binds to the spawned carrick pid.
- **The `pid$target` provider does NOT follow fork.** DTrace removes its probes
  from a newly-forked child (and they are gone after exec), so `pid$target::*foo*`
  silently never fires for grandchildren. Use the kernel-side `syscall::` /
  carrick USDT providers, which honor `progenyof`.
- **Bound every trace.** A hung guest streams forever. Add a host `timeout N`
  *and* an in-script `tick-1s { secs++ } tick-1s /secs >= N/ { exit(0); }`.
- **Reduce to a fast fixture first.** Tracing apt or a shell is millions of
  events. The `fixtures/linux-aarch64-hello` crate holds tiny raw-syscall ELF
  repros (`scripts/build-linux-fixtures.sh`, run with `carrick run-elf`); a
  ~15-syscall fixture turns each hypothesis into a <10s loop.
- **Re-sign before tracing** or you get `HV_DENIED`: `cargo build --release` then
  `codesign --force --sign - --entitlements scripts/entitlements.plist
  target/release/carrick` (or just `just build`).
- **A D-script compile error looks like the guest dying.** libdtrace fails
  `dtrace_program_strcompile` *before* the child spawns; an empty `--trace-out`
  or an instant EIO usually means the script, not carrick. Build the script up
  one clause at a time. `this->x` is clause-local and does *not* carry from
  `syscall-entry` to `syscall-return` — use `self->x` (thread-local) to pair an
  entry arg with the return value.
- **Kill stale guests scoped to YOUR run.** Set `CARRICK_RUN_ID=<unique>` so
  carrick stamps `carrick:<run-id>` into each guest's proctitle, then reap only
  yours with `scripts/sudo/kill.sh "$CARRICK_RUN_ID"`. Never a bare `pkill -9 -f
  carrick` — that reaps every concurrent lane's guests and silently wedges them.
- **A guest VA is not a host VA.** `copyin(addr,n)` reads the *traced carrick
  host* address space, so `copyin(guest_va, …)` on a buffer pointer the guest
  passed reads garbage and the probe silently drops. To read guest bytes: use
  host pointers a probe already carries (the 6-u64 arg array, stack-region
  translation), or add a one-line temporary probe at the carrick site that
  already holds the host `Vec`.

### Bundled and custom scripts

The repo ships ~46 `scripts/trace-*.d` programs plus the default
[`scripts/syscalls.d`](../scripts/syscalls.d); run any with `-s`. Notable ones:
[`trace-host-fds.d`](../scripts/trace-host-fds.d) (correlate guest pipe I/O with
host `pipe`/`dup`/`close` — the go-to for fd bugs),
[`trace-failing-child.d`](../scripts/trace-failing-child.d) (DTrace speculations:
commit only for a child that exits non-zero without exec'ing), and the
fork/futex/job-control families. Writing a focused script is almost always
faster than reading the full stream.

---

## 2. The event ring + lldb (zero-perturbation)

```sh
carrick debug lldb-plugin   # prints the carrick_lldb.py path to `command script import`
```

Every carrick process keeps an **always-on, lock-free in-memory ring** of its
last 8192 `bind / connect / listen / accept / epoll_ctl(ADD) / epoll_pwait /
fork / exec` events (`crates/carrick-runtime/src/event_ring.rs`). Recording is
unconditional and costs only a few relaxed atomics on the hot path — so it does
**not** shift the schedule the way a per-syscall dtrace probe or an `eprintln!`
does, and a core from *any* run carries the history with nothing pre-armed. The
ring is per-process and is reset on each guest fork (so a per-process core shows
that process's own history); AF_UNIX `bind`/`connect` carry a `pathhash` so you
can match a `connect` to the `bind` of the same socket across processes.

> [!IMPORTANT]
> Use the event ring when `carrick trace` perturbs the bug away. dtrace's
> per-syscall probes change a timing-sensitive race's outcome (it stops
> reproducing, or moves) — intermittent Heisenbugs: nested-fork wedges, lost
> wakes, epoll/kqueue stalls, "which process is stuck and why." For a
> *reproducible* live guest, `carrick trace` is still the richer tool (guest↔host
> correlation, fork-post tree, sampling). The ring is what cracked the CPython
> forkserver-from-forkserver `test_parent_process` deadlock
> (`docs/forkserver-parent-process-deadlock.md`).

### Loading the plugin and reading the ring

```sh
# Live: attach to the GUEST (the process whose ring is non-empty; find it by
# the carrick:<run-id> proctitle). The orchestrator parent's ring is empty.
lldb --batch \
  -o "command script import scripts/carrick_lldb.py" \
  -o "attach <pid>" \
  -o "carrick eventring" \
  -o "thread backtrace all" \
  -o "detach"

# Post-mortem from a core (durable, share-able, no live process):
lldb -o "attach <pid>" \
  -o "process save-core --style modified-memory /tmp/c.core" -o detach -o quit
lldb -c /tmp/c.core target/release/carrick \
  -o "command script import scripts/carrick_lldb.py" \
  -o "carrick eventring" -o "thread backtrace all"
```

A wedged thread's `bt` plus the ring usually pins the bug immediately (e.g. a
worker parked in `SignalPump::stop_inner -> thread::join -> __ulock_wait` with a
ring that ends at `LISTEN` and no `FORK`). `kq`/`hfd` values ≥ 16384 are
relocated carrick-internal fds (an epoll instance's kqueue, eventfd/pidfd/wake-
pipe backings): a guest blocking on one is parked on an internal object.

The plugin (`scripts/carrick_lldb.py`) registers a `carrick` command with these
subcommands: **`eventring`** (needs only a target + process/core), and the
guest-mapping helpers **`where`**, **`mappings`**, **`gva <addr>`**,
**`decode-esr <hex>`**, **`info`**, **`load-state <path>`**.

> [!WARNING]
> Cores must be `--style modified-memory` (or `full`), never `stack`. The ring is
> a `.data`/`.bss` static, not on any stack, so a `stack` core reads back
> `core file does not contain <addr>`. `modified-memory` captures the dirty pages
> (ring + Rust statics) but skips the multi-GB clean guest aperture, staying
> ~100 MB. The build must also retain symbols (`carrick eventring` resolves
> `event_ring::{RING,IDX}` by symbol name) — the default release keeps them; a
> stripped binary breaks the reader.

### Guest address-space mapping: the debug-state JSON

The `mappings`/`gva`/`info` subcommands translate guest VAs back to image /
segment / file context, which they read from a JSON dump of the guest layout.
Produce it with `--debug-state-path`, which writes the layout (PIE base,
interpreter base, HVF mappings, vector + trampoline pages) **before** starting the
vCPU:

```sh
carrick run-elf <static-elf> --debug-state-path /tmp/state.json
# or on a container run:
carrick run --debug-state-path /tmp/state.json <image> -- <cmd>
```

`carrick debug inspect-state /tmp/state.json` prints that JSON as a human summary
without lldb; `carrick debug decode-esr <syndrome>` decodes an AArch64 `ESR_EL1`
value (exception class, IL, ISS, with DFSC for data aborts) so you do not
hand-parse syndromes during a session.

`CARRICK_EVENTRING=<dir>` enables an optional autonomous file dump — a 1 Hz
watchdog thread writes `<dir>/carrick-ring.<pid>` per process. It is *perturbing*
(prefer the lldb reader for real debugging); the file dump is a convenience for a
quick reproducible run.

---

## 3. Host debug environment variables

These are opt-in (set the var to anything; carrick checks presence with
`var_os(...).is_some()` unless noted) and gate verbose stderr traces or
probe-only watchpoints. They are cached after the first read where they sit on a
hot path, so they do not re-hit the environment per syscall.

| Variable | Effect | Site |
|---|---|---|
| `CARRICK_TRACE_TRAPS` | Trace every HVF VM-exit (the EL1 trap → host boundary) as it is serviced. | `crates/carrick-runtime/src/runtime.rs:801` |
| `CARRICK_TRACE_REGS` | Dump guest GPRs at the trap boundary (PC, x0–x8) for register-level inspection. | `crates/carrick-hvf/src/trap.rs:2037` |
| `CARRICK_TRACE_SYSCALLS` | Emit one `[carrick-syscall] {json}` line per compat event (entry/return/unhandled) to stderr, alongside the USDT probe. The blunt "what did the guest call" log when you cannot attach dtrace. | `crates/carrick-hvf/src/compat.rs:207` |
| `CARRICK_TRACE_MAPS` | Trace guest memory-map establishment (HVF `hv_vm_map` of guest regions). | `crates/carrick-hvf/src/trap.rs:1295` |
| `CARRICK_TRACE_ELF` | Trace ELF loading: segment layout, PIE/interpreter base selection, auxv seeding. | `crates/carrick-mem/src/elf.rs:209` |
| `CARRICK_KICK_STATS` | At process teardown, print vCPU "kick" (cross-thread interrupt) statistics — how often siblings were interrupted, and the carrick-vs-guest invariant counters from `inject_at_el1` (which must be 0). | `crates/carrick-hvf/src/trap.rs:668` |
| `CARRICK_FAULT_DEBUG` | Verbose guest fault diagnostics: decode each data/instruction abort (faulting VA, ESR/DFSC) instead of just translating it. The first stop for an unexplained guest SIGSEGV. | `crates/carrick-runtime/src/runtime/fault.rs:109` |
| `CARRICK_IO_DBG` | Trace host read/write byte movement (the bytes a guest fd read/write actually transferred on the host fd). | `crates/carrick-runtime/src/dispatch/fs.rs`, `host_tty.rs` |
| `CARRICK_TTY_DBG` | Trace tty/pty byte flow specifically — the tool for the ONLCR / staircase-newline and line-discipline races. | `crates/carrick-runtime/src/dispatch/fs.rs:1478`, `vfs/dev.rs` |
| `CARRICK_DTRACE_DEBUG` | Log USDT probe registration (and any failure) at startup. Use it to confirm the `__dof_carrick` section survived linking before blaming a silent `carrick trace`. | `crates/carrick-cli/src/runtime_util.rs:196` |
| `CARRICK_WATCH_ADDR=<hex>` | Reusable guest-memory watchpoint. Fires the `mem-watch` USDT probe before *every* syscall with `(syscall_nr, addr, the current LE u64 at addr)`, so a trace can bracket exactly which syscall changes a guest address — e.g. which operation corrupts a GOT slot. Zero-cost (and not even read) when unset. | `crates/carrick-hvf/src/probes.rs:195` |
| `CARRICK_GUEST_MEM_SUB_OFFSET` / `_LEN` | Configure the `guest-mem` USDT probe to dump a fixed subrange of a guest buffer (offset+length); `_LEN=0` disables it. | `crates/carrick-hvf/src/probes.rs:510` |
| `CARRICK_EVENTRING=<dir>` | Autonomous per-process event-ring file dump (see §2). Perturbing; prefer the lldb reader. | `crates/carrick-runtime/src/event_ring.rs` |

> [!WARNING]
> `CARRICK_XMMAP` does **not** exist. It was a transient debug var used during
> one mmap-zero-fill investigation and removed; do not reach for it. `rg
> CARRICK_XMMAP crates` returns nothing.

### Non-diagnostic tunables

These change behavior rather than emit diagnostics, but are useful for
differential measurement (run with and without, compare):

- `CARRICK_DISABLE_VDSO` / `CARRICK_VDSO_MODE` — disable or switch the vDSO
  fast-path implementation (`runtime.rs:58`).
- `CARRICK_DISABLE_TSO` — disable the Apple-silicon Total Store Ordering memory
  model toggle for the guest (`runtime.rs:83`).
- `CARRICK_NO_FPSIMD` — disable FP/SIMD save-restore across signal handlers;
  built specifically to A/B the SIMD/FP register-restore ABI path (`trap.rs:651`).
- `CARRICK_MMAP_ARENA_GIB=<n>` — override the guest mmap-arena size (default
  32 GiB) (`crates/carrick-mem/src/memory.rs:192`).
- `CARRICK_EXPOSED_CPUS=<n>` — override the CPU count carrick advertises to the
  guest instead of the host hardware-thread count (`host_facts.rs:158`).

---

## 4. `carrick compat-report` — what did the guest need that we don't handle?

```sh
carrick compat-report [--format json|text] -- <cmd>
# or, on a container run, the same envelope as a flag:
carrick run --json <image> -- <cmd>
```

`compat-report` runs the guest and, on exit, emits a USDT-backed aggregation of
everything carrick could **not** fully service: unhandled syscalls (by number +
name, with invocation counts), partially-implemented syscalls, unhandled
`ioctl(2)` requests, unimplemented `/proc` and `/sys` read paths, unsupported
signals, and unknown syscall-flag bits (`crates/carrick-hvf/src/compat.rs`,
`CompatReporter` → `CompatReport`). It is the **"what does this workload need
that we don't handle yet"** tool — point it at a new binary and the report is
your gap list, sorted by frequency.

The report is emitted as pretty JSON by default (`--format json`) or as a human
summary (`--format text`). The same envelope (exit code + traps + report) is
available on a normal container run via `carrick run --json …` (off by default;
`run` otherwise behaves like `docker run`, streaming guest stdio and matching the
guest's exit code). Internally each gap is a `CompatEvent` recorded through the
carrick USDT provider, so the same data is visible live under `carrick trace`
(`carrick*:::unhandled-syscall`, etc.) — `compat-report` is the batch
aggregation, `carrick trace` is the live stream.

---

## See also

- [conformance-testing.md](conformance-testing.md) — running and interpreting the
  probe suite and Docker differential tests; the compile-time no-panic gate.
- [conformance-coverage.md](conformance-coverage.md) — the active probe gate
  mapping (which invariant each `conformance-probes/` probe owns).
- [architecture-overview.md](architecture-overview.md) — HVF traps, stage-1
  paging, and the BKL-free scheduling these tools observe.
- [syscalls-emulation-map.md](syscalls-emulation-map.md) — the per-syscall
  translation map a `compat-report` gap points back into.
- [../README.md](../README.md) — quickstart, the `ld64`-vs-`lld` `__dof_carrick`
  warning, and the codesigning requirement.
- Skills: [`.agents/skills/carrick-trace/SKILL.md`](../.agents/skills/carrick-trace/SKILL.md)
  and [`.agents/skills/carrick-lldb/SKILL.md`](../.agents/skills/carrick-lldb/SKILL.md)
  carry the full, hard-won methodology for each tool.
