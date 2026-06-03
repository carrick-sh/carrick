---
name: carrick-lldb
description: >-
  Post-mortem and live debugging of the carrick runtime (the Linux-binary-on-
  macOS HVF runtime) with lldb + the project's `scripts/carrick_lldb.py` plugin —
  on a LIVE process (attach) or a CORE file. Reach for this when a `carrick run`/
  `run-elf` HANGS or WEDGES and you need the guest's recent fork/socket/epoll
  history, the per-process deadlock topology, or host-thread stacks WITHOUT
  perturbing the timing — i.e. the cases where `carrick trace` (dtrace) changes
  the manifestation (intermittent Heisenbugs: nested-fork wedges, lost wakes,
  epoll/kqueue stalls, "which process is stuck and why"). The always-on in-memory
  event ring means a core from ANY run carries the history with nothing pre-armed.
  Complements carrick-trace: use carrick-trace to watch a reproducible guest live;
  use carrick-lldb when tracing perturbs the bug away, for post-mortem of a hang,
  or to read carrick's own state (event ring, guest mappings, ESR) from a core.
compatibility: >-
  Requires the carrick project + a release build with symbols (the default
  release retains them; do not strip), macOS on Apple silicon, and lldb. Live
  attach + `process save-core` work on the adhoc-signed binary as the owning
  user (no get-task-allow needed); reading a core needs no special privilege.
---

# Debugging carrick with lldb + the event ring

carrick ships an lldb plugin at `scripts/carrick_lldb.py` and an always-on
in-memory **event ring** (`crates/carrick-runtime/src/event_ring.rs`). Together
they give a **zero-perturbation** view of a hung or wedged carrick process —
live or from a core file. This is the tool for timing-sensitive races that
`carrick trace` (dtrace) perturbs away (see [[carrick-trace]]); the event ring is
recorded with a few relaxed atomics on the hot path, so it doesn't shift the
schedule the way a per-syscall dtrace probe or an `eprintln!` does.

It is what cracked the CPython forkserver-from-forkserver `test_parent_process`
deadlock: the ring showed the worker `BIND`+`LISTEN` the nested server's listener
then STOP with no `FORK` — wedged in `prepare_host_fork`'s pump stop — which
neither dtrace nor eprintln could show without changing the outcome. See
`docs/forkserver-parent-process-deadlock.md`.

## What the event ring records (always on)

Every carrick process keeps a lock-free ring of its last 8192 events; each
records `bind / connect / listen / accept / epoll_ctl(ADD) / epoll_pwait / fork /
exec`. Recording is unconditional (a core from any run has it). The ring is
per-process and is **reset on each guest fork**, so a per-process core shows that
process's own history. AF_UNIX `bind`/`connect` carry a `pathhash` so you can
match a `connect` to the `bind` of the same socket across processes.

Optional autonomous file dump (perturbing — a 1 Hz watchdog thread): set
`CARRICK_EVENTRING=<dir>` and each process writes `<dir>/carrick-ring.<pid>`.
Prefer the lldb reader (below) for real debugging; the file dump is a convenience
for a quick reproducible run.

## Loading the plugin

```
(lldb) command script import /path/to/carrick/scripts/carrick_lldb.py
(lldb) carrick                       # lists subcommands
```

Subcommands: `eventring`, `where`, `mappings`, `gva <addr>`, `decode-esr <hex>`,
`info`, `load-state <path>`. `eventring` is the one that needs only a target +
process/core; the rest are guest-mapping helpers that want a debug-state JSON
(`carrick run --debug-state-path <p>` then `carrick load-state <p>`).

## Workflow A — live (attach to a hung process)

A `carrick run` is **two host processes**: an orchestrator parent and the guest.
**Attach to the GUEST** — the one whose ring is non-empty. Find pids by the
proctitle (`carrick:<run-id>`), set with `CARRICK_RUN_ID` (see [[carrick-trace]]):

```sh
# reproduce the hang, then:
pids=$(ps -A -o pid=,command= | grep "carrick:<run-id>" | grep -v grep | awk '{print $1}')
# attach to each (or the guest) and dump its ring + stuck stacks:
lldb --batch \
  -o "command script import scripts/carrick_lldb.py" \
  -o "attach <pid>" \
  -o "carrick eventring" \
  -o "thread backtrace all" \
  -o "detach"
```

A wedged thread's `bt` plus the ring usually pins it immediately (e.g. a worker
parked in `SignalPump::stop_inner -> thread::join -> __ulock_wait` with a ring
ending at `LISTEN` and no `FORK`).

## Workflow B — core file (durable, share-able, no live process)

Use a **`modified-memory`** core: it captures dirty pages (which include the
written-to event ring + Rust statics) but NOT the multi-GB clean guest-memory
window, so it stays ~100 MB instead of gigabytes. `--style full` would bloat it
with the guest aperture; `--style stack` MISSES the ring (it lives in the data
section, not the stack).

```sh
# capture from a live (hung) guest:
lldb -o "attach <pid>" -o "process save-core --style modified-memory /tmp/c.core" -o detach -o quit
# analyse later / elsewhere — no live process needed:
lldb -c /tmp/c.core target/release/carrick \
  -o "command script import scripts/carrick_lldb.py" \
  -o "carrick eventring" \
  -o "thread backtrace all"
```

(A core's `eventring` header shows `pid=0` — cosmetic; the events are real.)

## Operating rules (learned the hard way)

1. **Attach to the GUEST, not the orchestrator parent.** The parent's ring is
   empty (it runs no guest syscalls); `eventring` shows `total=0`. Pick the pid
   whose ring is non-empty (or, with `CARRICK_EVENTRING` set, the per-pid file
   with the most lines).

2. **Cores must be `modified-memory` (or `full`), never `stack`.** The ring is a
   `.data`/`.bss` static, not on any stack. `stack` cores read back
   `core file does not contain <addr>`.

3. **The build must retain symbols.** `carrick eventring` finds
   `carrick_runtime::event_ring::{RING,IDX}` by symbol-name components (the Rust
   `::h<hash>` suffix is matched, not required to be known). The default release
   keeps them; a stripped binary breaks the reader.

4. **Reach for this when carrick-trace perturbs the bug.** dtrace's per-syscall
   probes and any `eprintln!` change a timing-sensitive race's outcome (the bug
   stops reproducing, or moves). The event ring is on the hot path but only a few
   relaxed atomics, so it (and a passive core read) leave the schedule intact.
   For a *reproducible* live guest, [[carrick-trace]] is still the richer tool
   (guest↔host syscall correlation, fork-post tree, profile sampling).

5. **Read the ring as a timeline + cross-process.** Reconstruct who-forks-whom
   from `FORK child_pid=…` (one process's ring) joined to the child's own ring
   (per-pid cores/attaches); match a `CONNECT pathhash=X` to the `BIND
   pathhash=X` that created that listener. A process whose ring ENDS abruptly
   (e.g. at `LISTEN` with no following `FORK`/`CONNECT`) is wedged in whatever it
   does next — confirm with its thread backtraces.

6. **Symbolicating carrick host stacks:** `thread backtrace all` resolves Rust
   frames when the binary has symbols. For frame pointers / cleaner stacks build
   with `RUSTFLAGS="-C force-frame-pointers=yes" CARGO_PROFILE_RELEASE_DEBUG=1`
   (same as [[carrick-trace]]'s symbolication note). For the GUEST (vCPU) state,
   `carrick trace --stack` / a debug-state JSON + `carrick mappings`/`gva` is the
   route — lldb sees the *host* threads, not the guest registers.

## The `eventring` output

```
# carrick event ring  pid=<host pid>  total=<events seen>  showing=<min(total,8192)>
   <seq> BIND     gfd=<guest fd> hfd=<host fd> pathhash=<0x…>     # AF_UNIX bind
   <seq> LISTEN   hfd=<host fd>
   <seq> CONNECT  hfd=<host fd> rc=<0|errno> pathhash=<0x…>
   <seq> ACCEPT   listener_hfd=<host fd> ret=<new host fd>
   <seq> EPADD    kq=<epoll-instance kqueue fd> hfd=<watched host fd> events=<0x…>
   <seq> EPWAIT   kq=<kqueue fd> ready=<n ready> timeout=<ms, -1=block>
   <seq> FORK     child_pid=<host pid of the forked child>
   <seq> EXEC     path_present=1
```

`kq` ≥ 16384 is a relocated carrick-internal fd (the epoll instance's kqueue);
`hfd` ≥ 16384 likewise (eventfd/pidfd/wake-pipe backings). A guest blocking on a
≥16384 host fd in a wait is parked on one of those internal objects.

## Adding more to the ring

To capture a new event class, add a `pub const` kind + a `decode` arm in
`crates/carrick-runtime/src/event_ring.rs`, a matching arm in
`scripts/carrick_lldb.py`'s `_EVENTRING_KINDS`, and a `crate::event_ring::rec(…)`
call at the carrick site. Keep `rec` calls cheap (no allocation/format on the hot
path — pass ints; hash strings via `event_ring::path_hash`).
