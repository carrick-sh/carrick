---
name: carrick-lldb
description: Use when a Carrick guest hangs, wedges, crashes, or needs live kernel and scheduler inspection, post-mortem analysis, host stacks, event-ring history, or mapping diagnostics; also when asked about carrick debug or Carrick LLDB commands.
---

# Carrick debugging

Read the applicable section of [commands.md](references/commands.md) before
running a diagnostic.

| Need | Interface | Effect |
|---|---|---|
| Live tasks, queues, executors, resource graph | `carrick debug hvpatch-kernel` | Read-only coherent projection; requires responsive carrier |
| Reproducible hang capture | `carrick debug lldb-run` | Launches workload; deadline/signal capture terminates scoped run |
| Capture an existing run | `carrick debug lldb-snapshot` | Attaches LLDB; caller owns cleanup |
| Host stacks, ring, saved host core | `lldb`, then plugin `carrick …` | Live attach pauses process; offline core needs no live target |
| Intentional kernel termination with evidence | `carrick debug abort` | Destructive abort, not a read-only snapshot |
| Guest core or diagnostic ledger validation | Other `carrick debug` commands | Input formats are not interchangeable |

## Safety and evidence

- Use a signed, symbol-bearing binary for HVF guests (`just build` or
  `just build-debug`). Preserve the exact executable/symbols with cores and
  record source revision and binary identity. Do not rebuild under a live run.
- Scope by `CARRICK_RUN_ID` / `--name`. Inspect the **VM carrier**, not merely
  its CLI parent, namespace supervisor, or file-authority helper. HVPatch guest
  fork does not create a host process per guest. The carrier owns kernel state.
- Capture live kernel JSON **before** LLDB attach; its server needs a running
  carrier. Busy/timeout is evidence, not an empty healthy graph.
- Do not pre-SIGSTOP macOS targets: this can break LLDB's attach handshake.
  Attach and debug requests have observer effects, not zero perturbation.
- Save `modified-memory` cores and all-thread backtraces before deadlock cleanup.
  Stack-only cores omit ring/statics; full cores can be huge. Missing core memory
  is not proof that a value was zero or absent.
- Cleanup with `scripts/sudo/kill.sh <run-id>`, never broad `pkill`. Abort needs
  authorization to terminate that exact run.

## Namespaces and interpretation

The audited shell CLI has `carrick debug lldb-run`, `lldb-snapshot`, and
`lldb-plugin`, **not a top-level `carrick lldb` command**. Importing
`scripts/carrick_lldb.py` registers `(lldb) carrick` inside LLDB. Check matching
build help when versions differ; do not invent commands.

The plugin's guest-process/thread views derive from host thread names, not a
complete GMP logical-task census. Prefer kernel tables for queued/parked tasks.
`where` reads host registers, not guest vCPU registers. Mapping-state JSON,
kernel snapshots, structured post-mortems, guest ELF cores, and host LLDB cores
are distinct artifacts.

The always-on ring lives in `crates/carrick-kernel/src/event_ring.rs`. It needs
no pre-armed tracing; it does not imply zero observer effect. Correlate its
timeline with stacks and typed identities, not a historical per-guest-fork host
process model. Ring `ERROR BUSY/GAP/OVERWRITTEN/TORN/UNKNOWN` invalidates range
completeness. An empty parent ring says nothing about carrier activity.

Use [carrick-trace](../carrick-trace/SKILL.md) for reproducible guest syscall
flow/profiling. Avoid logging that changes races. New ring events require kernel
writer and plugin decoder updates together, bounded allocation-free recording,
and tests of both sides.
