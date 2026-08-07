# Diagnostics and debugging

Carrick is a syscall-translation layer, so almost every bug is "the guest asked
the macOS host for something and got the wrong answer." The tools below let you
watch that translation boundary from the host side without touching the guest
binary. Three of them are first-class subcommands of the `carrick` CLI
(`carrick trace`, `carrick debug …`, `carrick compat-report`); the rest are
compile-time debug-trace Cargo features, a few runtime env-var tunables, and an
lldb plugin.

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
carrick trace -s scripts/dtrace/trace-host-fds.d -o /tmp/ev.out -- run -t alpine /bin/sh
```

**It auto-sudos.** libdtrace needs root (`/dev/dtrace`), so `carrick trace`
re-execs itself under `sudo`; do **not** prefix `sudo` yourself. The trace parent
keeps root for libdtrace while the traced guest child drops back to your original
uid/gid/groups (carried across `sudo`'s env-reset via hidden `--trace-uid` /
`--trace-gid` / `--trace-groups` / `--forward-env` args — CLI args survive `sudo`
where `CARRICK_*` env vars would be stripped).

### Reading the output

With no `-s`, the bundled [`scripts/dtrace/syscalls.d`](../scripts/dtrace/syscalls.d) runs:
each event is a per-syscall line tagged with the firing pid, and `END {}` prints
frequency-sorted aggregations (which syscalls, how often, top errnos). `-F`
indents each `entry`/`return` by call depth like `dtrace -F`. `-o FILE` writes
the probe stream and aggregations to `FILE` (opened `fopen("w")`, truncated per
run) instead of stdout, leaving the traced command's own stdio untouched — this
is **essential** when tracing an interactive `-t` guest, whose terminal stream
would otherwise interleave with probe lines and be unreadable. The file is
written as root: `cat`/`grep` it without sudo, `rm` may need sudo.

### Built-in DSR profiles

For performance attribution on the Darwin-native dynamic syscall rewriter, use
`--profile dsr`, `--profile dsr-indirect`, or `--profile dsr-fork` with
`--summary-jsonl FILE`. The broad profile measures prepare/run/resolve/translate
and dispatcher phases, the indirect profile attributes resolver misses by
guest source and target, and the fork profile measures child repair and exec
lifecycle intervals. (A fourth profile, `dsr-live-arena`, existed only for the
2026-08-05..06 live-translation-arena campaign and was deleted with that
mechanism in `1cb06de6`.) DSR is the sole Darwin-native instruction-execution
path, so native trace commands require no separate code-mode selection.
`--profile` conflicts with a custom `--script`;
`--summary-jsonl` requires a profile. Use a separate `--trace-out` path when the
raw `DSRPROF1` stream should be retained.

The parser fails closed on malformed or truncated streams, missing completion,
incomplete phase pairs, and DTrace drops. Enabled profiling is deliberately
diagnostic and can materially perturb runtime, so use its counts and phase
relationships to choose work, then prove improvements with untraced workload
measurements. The supported commands, schema, measured overhead, current long
poles, and interruption behavior are recorded in the
[native DSR profile report](native-dsr-dtrace-profile.md).

### The Darwin kernel amplification ledger (`native-amplification`)

`carrick trace --profile native-amplification` answers "how much Darwin kernel
work does ONE Linux guest operation cost", in the four currencies a
CPU-second budget can be ranked against: host syscall count, host syscall
**CPU-ns** (`vtimestamp`, so a blocked call is not counted as kernel work),
mach traps (libmalloc's large zone reaches the kernel through
`mach_vm_allocate`, which every `syscall:::`-only census misses), and
`vminfo:::` faults. All four join on the same guest-op service window, so the
output is per-guest-op and never a kernel-stack family ranking.

```sh
carrick trace --profile native-amplification --preflight-quiet-host \
  -o target/perf/amp1/baseline.raw \
  -- run --exec-backend native <image>@sha256:… /bin/sh -c '<workload>'
carrick debug amplification-ledger target/perf/amp1/baseline.raw \
  --output target/perf/amp1/baseline.ledger.json
carrick debug amplification-compare baseline.ledger.json candidate.ledger.json
```

| command | what it owns |
|---|---|
| `carrick trace --profile native-amplification` | the capture. Refuses a non-native or tag-pinned target at launch, and writes libdtrace's own consumer-side drop counters into the stream as an `AMP1\|consumer-drops\|…` record. |
| `carrick trace --preflight-quiet-host` | settles the one-minute load average, then **aborts** if a `yes` load generator or a stray `carrick:` guest is still running; the receipt (settle time, settled load) goes into the stream header. |
| `carrick debug amplification-ledger <raw>` | the typed `carrick.amplification-ledger.v1` artifact: per-guest-op host calls, host CPU-ns and faults, with exact-integer ratios, asserted closure against the capture's independent totals, `carrick-only` as a bucket that *cannot* carry a ratio, and libdtrace's own `kdebug_trace*` subtracted into a named sub-bucket. |
| `carrick debug amplification-compare <a> <b>` | the determinant-locked A/B. Refuses to cross a program digest, `joins=` set, declared buffer headroom, OS build, image digest, fixture argv digest, or guest-op set; identical ledgers report exact zeros. |

Three properties are worth knowing before reading a number:

- **Wall is never authority.** Four probe families in one program perturb the
  traced run an expected 2–4x. Counts and same-instrument ratios are citable;
  the elapsed time in the completion record is diagnostic metadata, and the
  comparator publishes no wall difference at all.
- **A `--script` capture cannot produce a ledger.** The header must name the
  digest of the bundled `scripts/dtrace/native-amplification.d`.
- **Drops are refusals, and absent is not zero.** DTrace drops silently, and on
  this instrument a dropped event reads as *lower* amplification. A lost
  `service_slot` entry moves host work from a guest op into `carrick-only`
  without breaking a single closure sum — an amplification that *improved* —
  so the consumer-side counters are written in-band and any nonzero one, or a
  missing record, refuses the capture. `CARRICK_AMP1_CONSUMER_DROPS=0` skips
  writing the record for bisection only; the resulting stream is refused.

The driver for a paired arm is
[`scripts/perf/amplification-capture.sh`](../scripts/perf/amplification-capture.sh)
(stamps `CARRICK_RUN_ID`, reaps with `scripts/sudo/kill.sh`).

### Profiling a running FreeBSD native-x86 process

Launch-time `carrick trace --profile dsr` owns its target and may use Carrick
USDT probes. An already-running FreeBSD native process has a different safety
contract: **never attach with `dtrace -p`, `pid$PID`, or USDT fasttrap probes**.
Fasttrap teardown delivered a leaked `SIGTRAP` and killed a continuing Kaniko
build. Use the bounded kernel-provider profiler instead:

```sh
sudo scripts/native-x86-profile.py PID --seconds 5
sudo scripts/native-x86-profile.py PID --guest-elf /path/to/guest --json
```

The tool discovers the current host process tree and follows later forks through
`proc:::create`; discovers Carrick, libc, and executable POSIX-SHM JIT mappings
with `procstat`; and obtains `%r15` plus the `exit_resume` offset from the
matching binary's versioned `carrick debug native-x86-layout` contract. It
reports host syscall counts, PIE-normalized/`addr2line`-symbolicated host PCs,
guest-PC samples, and sampled `memcpy` callers and sizes. It rechecks executable mappings and tracee liveness after
capture and fails closed when DTrace reports drops or action errors.

For an unexplained signal death in a long-running process tree, start the
kernel-provider lifecycle trace while the root still runs:

```sh
sudo dtrace -q -s scripts/dtrace/native-x86-signal-lifecycle.d ROOT_PID \
  > /tmp/native-x86-signals.out
```

It records the sender PID/name, target PID, and signum for signals delivered to
the root or descendants created after tracing starts, then exits with the root.
It enables only the kernel `proc` provider: no `-p`, pid provider, USDT, or
fasttrap attachment. Start it before the child of interest is created; the
initial PID set contains only `ROOT_PID`.

Do not use `ustack()` as ground truth while the JIT runs: DSR has installed the
guest RSP, so host unwinding either stops or follows guest data. Do not copy a
numeric context offset into a D script; XSAVE expansion already moved
`exit_resume` from 720 to 33024. Raw guest PCs remain authoritative when a
stripped Go ELF retains no symbol table; `--guest-elf` symbolizes ordinary ELF
symbols when available.

For a controlled xstate-ownership investigation, launch the target under trace
(the tracer must own its whole lifetime) and select only the relevant guest PCs:

```sh
CARRICK_NATIVE_X86_TRACE_PC=0x20114d,0x201138 \
  target/release/carrick trace \
  --script scripts/dtrace/native-x86-pc.d -- run ...
```

The trace emits edge event/decision flags plus FCW, MXCSR, XSTATE_BV, PKRU and
bounded legacy/YMM/opmask-ZMM/extended hashes. To bisect a transitive chain,
`CARRICK_NATIVE_X86_EDGE_BARRIER` accepts `all`, a source PC, or
`source->target`; selected edges stay on their cold gateway stub. The exact
value `CARRICK_NATIVE_X86_XSTATE_POLICY=unsafe-local-diagnostic` deliberately
clobbers skipped entries for a red-first diagnostic. The experimental
`neutral-domains` policy keeps locally classified state-user targets cold and
uses host-resident physical state only for neutral entries; nonzero virtual
guest PKRU forces guest residency. RDPKRU/WRPKRU are sensitive-emulated outside
the hardware XSAVE image so guest key-0 rights cannot revoke gateway access;
guest-memory pkey enforcement is not implemented yet. The legacy
`unsafe-target-barrier-diagnostic` spelling
is an alias retained for reproducing the original experiment. Only
`unsafe-local-diagnostic` is intentionally corrupting. Combine diagnostic modes
with selected PCs and a bounded launch-time trace. To discover candidate PCs on an
exact workload, set `CARRICK_NATIVE_X86_TRACE_XSTATE_GRAPH=1` and launch with
`scripts/dtrace/native-x86-xstate-graph.d`; it aggregates translation and patch
lifecycle edges without gateway-entry events or component hashing. These are
USDT probes, so the prohibition on attaching them to an already-running FreeBSD
native process still applies.

### USDT probe families

The probes are static USDT, wired at the translation boundaries via the `usdt`
crate (`crates/carrick-observability/src/probes.rs`, `#[usdt::provider(provider =
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
> Build with `--features trace-dtrace` to log probe registration (and any
> failure) at startup.

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

The repo ships a small set of `scripts/dtrace/*.d` programs (the trace-*.d
fork/futex/fd families) plus the default
[`scripts/dtrace/syscalls.d`](../scripts/dtrace/syscalls.d); run any with `-s`. Notable ones:
[`trace-host-fds.d`](../scripts/dtrace/trace-host-fds.d) (correlate guest pipe I/O with
host `pipe`/`dup`/`close` — the go-to for fd bugs),
[`trace-failing-child.d`](../scripts/dtrace/trace-failing-child.d) (DTrace speculations:
commit only for a child that exits non-zero without exec'ing), and the
fork/futex/job-control families. Writing a focused script is almost always
faster than reading the full stream.

For HVF syscall-transport attribution, the maintained
[`hvf-syscall-transport.d`](../scripts/dtrace/hvf-syscall-transport.d) consumer
counts the actual register API operations at request decode and ordinary return
publication:

```sh
CARRICK_HVF_SYSCALL_TRANSPORT=mailbox target/release/carrick trace \
  -s scripts/dtrace/hvf-syscall-transport.d -- \
  run-elf --exec-backend vmm <native-pie-probe>
```

Transport `0` is legacy and `1` is mailbox; phase `0` is decode and phase `1`
is return publication. An ordinary mailbox boundary should report zero register
reads, sysreg reads, and register writes in both phases.

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
> (`docs/archive/forkserver-parent-process-deadlock.md`).

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

The plugin (`scripts/carrick_lldb.py`) registers a `carrick` command with the
**`eventring`** subcommand (needs only a target + process/core) and the
guest-mapping helpers **`where`**, **`mappings`**, **`gva <addr>`**,
**`decode-esr <hex>`**, **`info`**, **`load-state <path>`**. (An
`xlat-live-arena` subcommand existed only for the 2026-08-05..06
live-translation-arena campaign and was deleted with that mechanism in
`1cb06de6`.)

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

Built with `--features event-ring-dump`, setting `CARRICK_EVENTRING=<dir>`
enables an optional autonomous file dump — a 1 Hz watchdog thread writes
`<dir>/carrick-ring.<pid>` per process. It is *perturbing* (prefer the lldb
reader for real debugging); the file dump is a convenience for a quick
reproducible run. The in-memory ring itself is always-on, feature or not.

---

## 3. Debug-trace build features

The verbose stderr traces and the watchpoint / event-ring file dump are
**compile-time Cargo features** (default off), so a stock build carries none of
them on its hot paths. Build with the feature(s) you need — e.g.
`cargo build -p carrick-cli --features trace-tty`, or `--features debug-all` for
the lot — then run normally.

| Feature | What it traces |
|---|---|
| `trace-tty` | tty/pty byte flow — the tool for the ONLCR / staircase-newline and line-discipline races (`dispatch/fs.rs`, `dispatch/mod.rs`, `vfs/dev.rs`). |
| `trace-io` | host read/write byte movement — the bytes a guest fd actually transferred on the host fd (`dispatch/mod.rs`, `dispatch/fs.rs`, `host_tty.rs`). |
| `trace-traps` | every HVF VM-exit (the EL1 trap → host boundary), with the guest syscall frame, as each is serviced (`runtime.rs`). |
| `trace-hvf` | trap-handler internals: guest registers at the boundary, `hv_vm_map` of guest regions, and EL0 abort fault dumps (faulting VA, ESR/DFSC) — the first stop for an unexplained guest SIGSEGV (`hvf/trap.rs`). |
| `trace-syscalls` | one `[carrick-syscall] {json}` line per compat event (entry/return/unhandled) to stderr, alongside the always-on USDT probe — the blunt "what did the guest call" log when you can't attach dtrace (`hvf/compat.rs`). |
| `trace-elf` | ELF loading: segment layout, PIE/interpreter base selection, auxv seeding (`mem/elf.rs`). |
| `debug-stats` | at teardown, vCPU "kick" (cross-thread interrupt) and lazy-alias re-map counters to stderr; the USDT probes + atomic counters stay always-on (`hvf/trap.rs`). |
| `trace-dtrace` | log USDT probe registration (and any failure) at startup — confirm `__dof_carrick` survived linking before blaming a silent `carrick trace` (`carrick-cli/runtime_util.rs`). |
| `watchpoint` | reusable guest-memory watchpoint. With the feature built **and** `CARRICK_WATCH_ADDR=<hex>` set, fires the `mem-watch` USDT probe before *every* syscall with `(syscall_nr, addr, current LE u64 at addr)`, so a trace can bracket exactly which syscall changes a guest address — e.g. which operation corrupts a GOT slot (`hvf/probes.rs`, `dispatch/mod.rs`). |
| `event-ring-dump` | with the feature built **and** `CARRICK_EVENTRING=<dir>` set, a 1 Hz watchdog writes `<dir>/carrick-ring.<pid>` (see §2). Perturbing; prefer the lldb reader. The in-memory ring itself is always-on regardless (`runtime/event_ring.rs`). |
| `debug-all` | umbrella enabling every feature above. |

### Runtime tunables (still environment variables)

These take a runtime value (or toggle behavior rather than emit a trace), so
they remain environment variables — useful for differential measurement (run
with and without, compare):

- `CARRICK_GUEST_MEM_SUB_OFFSET` / `_LEN` — configure the `guest-mem` USDT probe
  to dump a fixed subrange of a guest buffer; `_LEN=0` disables it.
- `CARRICK_DISABLE_VDSO` / `CARRICK_VDSO_MODE` — disable or switch the vDSO
  fast-path implementation.
- `CARRICK_DISABLE_TSO` — disable the Apple-silicon Total Store Ordering memory
  model toggle for the guest.
- `CARRICK_NO_FPSIMD` — disable FP/SIMD save-restore across signal handlers;
  built specifically to A/B the SIMD/FP register-restore ABI path.
- `CARRICK_MMAP_ARENA_GIB=<n>` — override the guest mmap-arena size (default
  32 GiB).
- `CARRICK_EXPOSED_CPUS=<n>` — override the CPU count carrick advertises to the
  guest instead of the host hardware-thread count.

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
signals, and unknown syscall-flag bits (`crates/carrick-observability/src/compat.rs`,
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
- [architecture-overview.md](architecture-overview.md) — mature HVF traps,
  stage-1 paging, and the BKL-free scheduling these tools observe.
- [hal.md](hal.md) — KVM, bhyve, NVMM, host-primitive crates, and the shared
  x86_64 engine.
- [syscalls-emulation-map.md](syscalls-emulation-map.md) — the per-syscall
  translation map a `compat-report` gap points back into.
- [../README.md](../README.md) — quickstart, the `ld64`-vs-`lld` `__dof_carrick`
  warning, and the codesigning requirement.
- Skills: [`.agents/skills/carrick-trace/SKILL.md`](../.agents/skills/carrick-trace/SKILL.md)
  and [`.agents/skills/carrick-lldb/SKILL.md`](../.agents/skills/carrick-lldb/SKILL.md)
  carry the full, hard-won methodology for each tool.
