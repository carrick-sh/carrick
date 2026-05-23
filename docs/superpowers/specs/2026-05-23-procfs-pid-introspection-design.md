# Design: guest-only `/proc/<pid>/` introspection

Date: 2026-05-23
Status: approved (brainstorm), pending implementation plan

## Problem

LTP tests synchronise a parent with a child (or a process with its threads) by
**polling `/proc/<pid>/stat` field 3 — the process state char — until it reads
`'S'` (sleeping in a syscall)** before issuing a wake, and some enumerate
`/proc/<pid>/task/` to find all threads. carrick today synthesises only
`/proc/self/*` (plus a few `/proc/sys/*`), so any `/proc/<numeric-pid>/...`
access returns `ENOENT`. That blocks, at minimum:

- `pause01`, `pause02`, `pause03` — parent reads `/proc/<child>/stat`, waits for
  `'S'`, then signals the paused child (also uses `tst_checkpoint`, now fixed).
- `futex_wait03`, `futex_wake02`, `futex_wake03`, `futex_cmp_requeue01` — a
  process spawns waiter threads/processes and polls their state via
  `/proc/<pid>/stat` (and `/proc/<pid>/task/`) until they are sleeping in
  `futex`, then wakes them.

These break with `TBROK` ("Failed to open `/proc/<pid>/stat`" /
"opendir(`/proc/<pid>/task/`)"), hiding every assertion behind setup failure.

## Goal

Synthesise `/proc/<pid>/` for **live carrick guest processes only**, with enough
fidelity that the state-polling pattern observes `'S'` when a guest is blocked
and `'R'` when running. Files: `stat`, `status`, `cmdline`, `comm`, and
`task/<tid>/` (with per-tid `stat`).

Non-goal: exposing arbitrary host processes; full Linux `/proc` field accuracy
beyond what these tests read; per-tid state for *other* multi-threaded
processes (deferred — see "Deferred work").

## Approach: hybrid (libproc-first, local fast path, shared registry deferred)

Chosen over a pure shared-memory state registry (more infrastructure,
duplicates what the host kernel already knows) and over an optimistic always-`S`
stub (too loose — ordering-sensitive tests like `futex_wake02` need waiters to
*actually* be sleeping). Aligns with the project preference for durable
macOS-native / host-kernel bookkeeping over in-memory state.

### Components

**1. `procpid` synthesis module (`src/dispatch/procpid.rs` or a section of the
proc synthesis code).**
Given a parsed `(pid, subpath)`, returns `Option<Vec<u8>>` for a file or a
directory listing. Plugs into the existing `synthetic_proc_file(path, ctx)` and
the proc VFS readdir path. Reuses the existing 52-field `/proc/self/stat`
builder, generalised to accept identity + state inputs rather than hard-coding
self.

**2. Guest-pid validation (libproc — the "A" half).**
`proc_pidinfo(pid, PROC_PIDTBSDINFO, …)` fetches the target's BSD info. Walk
`pbi_ppid` upward (repeated `proc_pidinfo`) until the chain reaches the root
guest host pid (`ProcState.bootstrap_host_pid`, already recorded) or terminates
at pid 1 / an unknown parent. Reaches root → it's one of our guests; otherwise
`ENOENT`. This needs no shared registry: ancestry + the known root pid suffice.
`/proc/self` and `/proc/<own-pid>` short-circuit to the local fast path below.

**3. State + identity sourcing.**
- *Other guest processes:* state char from `pbi_status`
  (`SSLEEP→'S'`, `SRUN→'R'`, `SSTOP→'T'`, `SZOMB→'Z'`, `SIDL→'R'`); ppid/pgrp/uid
  from `proc_pidinfo`. A guest blocked in `pause()`/`futex_wait` has its carrick
  run loop parked in a host syscall → host `SSLEEP` → `'S'`, exactly what the
  pollers await. EL0 userspace (in `hv_vcpu_run`) → `SRUN` → `'R'`.
- *Self / own threads:* prefer carrick's own knowledge over libproc — the
  `ThreadRegistry` / run loop knows whether a tid is parked (blocked in
  futex/poll/wait → `'S'`) or running (`'R'`), which is more precise than the
  host status. Identity from `ProcState`.

**4. Files.**
- `stat` — 52 fields; state from (3); pid/ppid/pgrp/sid/comm filled, the rest
  zeroed (matches the existing synthetic `/proc/self/stat` precedent).
- `status` — human-readable `Name:`, `State:`, `Pid:`, `PPid:`, `Uid:`, `Gid:`
  lines (the fields LTP reads).
- `cmdline` / `comm` — from libproc process name (self: `ProcState.executable_path`).
- `task/` — directory of tids. **Self / own-pid:** enumerate the local
  `ThreadRegistry`; `task/<tid>/stat` per tid with state from carrick's per-tid
  park/run state. **Other (single-threaded) guests:** a single `task/<pid>/`.

### Data flow

```
guest open("/proc/<N>/stat")
  -> proc VFS / synthetic_proc_file
  -> procpid::parse(path) = (N, "stat")
  -> if N == self|own: local fast path (ProcState + ThreadRegistry)
     else: guest_validate(N) via libproc ancestry -> ENOENT if not a guest
           -> proc_pidinfo(N) -> state/identity
  -> build_stat(...) -> bytes
```

### Error handling

- Non-guest / dead pid → `ENOENT` (open returns the standard not-found error).
- libproc failure (`proc_pidinfo` returns 0/err) → treat as not-found (`ENOENT`).
- Unknown `/proc/<pid>/<file>` we don't synthesise → `ENOENT` (current default),
  not a crash.
- All libproc calls are read-only; no guest-controlled pointers reach them.

### Testing

Reproduction probes (the established static-musl `run-elf` + Docker diff
pattern), each printing deterministic booleans:
- `procstat.rs` — fork a child that `pause()`es; parent polls
  `/proc/<child>/stat` until state `'S'`, then signals it; assert the child
  was observed sleeping and woke. (Mirrors `pause01`.)
- `proctask.rs` — spawn N threads that block in `futex`; read `/proc/self/task/`,
  poll each `task/<tid>/stat` until all `'S'`; then wake. (Mirrors `futex_wake02`.)

Plus the differential LTP harness: `pause01/02/03`, `futex_wait03`,
`futex_wake02/03`, `futex_cmp_requeue01` should move from `TBROK` toward
matching Docker.

## Deferred work

A shared-memory (`MAP_SHARED`, fork-inherited) registry where each carrick
process publishes its threads' states — added **only if** a test reads another
*multi-threaded* process's `/proc/<pid>/task/` with per-tid state (none of the
current blocked tests do; they read their own `task/`). Until then the local
`ThreadRegistry` + libproc cover the cases.

## Risks / open questions

- Host-state → Linux-state mapping is approximate; acceptable because the tests
  only distinguish "sleeping" from "not". If a test needs finer states
  (`D` uninterruptible, `t` traced) we extend the mapping.
- `proc_pidinfo` requires the target to be inspectable by the carrick process;
  for our own descendants this holds.
- libproc thread enumeration returns mach thread ports, not Linux tids — which
  is why `/task/` for *own* processes uses the `ThreadRegistry` (authoritative
  tid source) rather than libproc.
