# Debug command reference

Examples run from the repository root; substitute angle-bracket placeholders.
Use the intended signed artifact. Source authorities are CLI `args.rs`,
`debug.rs`, `debug_core.rs`, and `scripts/carrick_lldb.py`. Platform availability
differs; check the matching build's help and dispatch implementation.

## Live kernel and scheduler

```sh
target/release/carrick debug hvpatch-kernel --list-tables
target/release/carrick debug hvpatch-kernel --run-id <run-id>
target/release/carrick debug hvpatch-kernel --run-id <run-id> \
  --table scheduler,run-queue,executor,executor-receipt
```

Omit `--table` for the whole graph. Other tables: `task`, `zombie`, `thread`,
`task-shared`, `thread-resources`, `mm`, `vma`, `frame`, `mapping`, `file-table`,
`file-slot`, `file-description`, `fs-context`, `credentials`, `process-group`,
`session`, `sighand`, `task-signal`, `thread-signal`. Discover tables rather than
inventing `wait` or `continuation` names. Inspect actual fields for ownership;
request the full graph when filtering omits required relationships.

The authenticated socket validates coherent JSON. Unknown schema/table,
missing requested tables, duplicate IDs, broken joins, partial/trailing frames,
and deadline failures must remain explicit. Structural validation is not proof
of every runtime invariant.

Phase 3 builds additionally expose `scheduler[].host_wait`: coherent enter/resume
counts and conserved slots with CPU, root executor, current owner, and exact
waiter executor/epoch/thread/generation plus return-readiness. A null census
means the ledger was contended or the producer predates this field, not zero
host waits. A host-waiting thread still holds a scheduler claim even though its
executor has relinquished the CPU. Do not interpret a vacant slot owner as an
exited task.

## Automatic capture and existing runs

```sh
target/release/carrick debug lldb-run --deadline-seconds 35 \
  --out-dir target/conformance/logs/lldb-runs --run-id <run-id> -- \
  --fs host <image> <guest-command> <args>
target/release/carrick debug lldb-snapshot --run-id <run-id> \
  --out-dir target/conformance/logs/lldb-runs
```

After `--`, supply `carrick run` arguments **without `run`**. Runner injects
`--name` if absent and sets `CARRICK_RUN_ID`; an explicit name must match.
Natural completion returns child status; deadline/signal capture terminates
the scoped run and returns 124.

- `--stop-on-signal <Linux-signum>` stops the dying guest for capture.
- `--fatal-hold-seconds <seconds>` holds fatal paths for capture (default:
  deadline; 0 disables); a fatal-hold log line triggers early capture.
- `--lldb-plugin <path>` overrides plugin discovery.
- `--no-core` omits cores, not stacks/ring; avoid for real hang triage.

Artifacts: `<run-id>.manifest.txt`, `.guest.log` (both streams), `.ps.txt`,
`.lldb.txt`, `.kernel-debug.json`, and `<run-id>.<pid>.core`. Live kernel capture
precedes attach. Failure is retained as `KERNEL_SNAPSHOT_ERROR`, not a fabricated
snapshot. Check LLDB statuses and file existence. Manifest paths alone do not
attest executable identity; preserve binary hashes and symbols separately.

**Snapshot caveat:** help says processes remain stopped, but the audited
implementation does not pre-freeze them and ends attachments with `detach`.
Do not rely on a stopped-state guarantee; verify process state and own scoped
cleanup. This command is not passive observation.

## Interactive LLDB and host cores

```sh
lldb -p <carrier-pid>
lldb -c <host-core-path> <exact-matching-executable>
```

Inside LLDB:

```text
command script import /absolute/repo/scripts/carrick_lldb.py
carrick
carrick guest-processes
carrick guest-threads
carrick guest-threads <guest-pid>
carrick eventring 8192
thread backtrace all
image lookup -s CARRICK_LAST_FATAL
p CARRICK_LAST_FATAL
process save-core --style modified-memory /absolute/output/carrier.core
detach
```

Save/detach apply to live targets. If fatal-record expression display fails,
read the symbol address with `memory read`, using the actual `FatalRecord`
layout in `crates/carrick-fatal/src/lib.rs`, never guessed offsets. Preserve
domain/message. Guest-thread commands use host names and can miss GMP tasks.

`carrick debug lldb-plugin` prints a path; the audited implementation can print
a nonexistent crate-relative path. Check existence and fall back to the
checkout's absolute `scripts/carrick_lldb.py` path.

## Mapping state and registers

Request `run --debug-state-path <path>`, then use shell commands:

```sh
target/release/carrick debug inspect-state <path>
target/release/carrick debug decode-esr 0x96000004
```

Inside LLDB:

```text
carrick load-state /absolute/path/to/debug-state.json
carrick info
carrick mappings
carrick gva 0x400000
carrick decode-esr 0x96000004
carrick where
```

`info`, `mappings`, `gva`, and `where` require mapping state. `gva` classifies
against saved inventory; it does not authenticate live HVPatch VA→IPA→owner
generation. `where` displays host `pc/x0/x1/x8`, not guest registers. No dedicated
guest-register plugin command exists in this version. Use verified backend
state/layout, guest core notes, or the trace skill; never relabel host registers.

## Structured abort and offline artifacts

Configure `run --post-mortem-dir <directory>` or `CARRICK_POSTMORTEM_DIR` before
reproduction. Only when termination is authorized:

```sh
target/release/carrick debug abort --run-id <run-id>
```

This requests kernel abort, freezes scheduling, and produces a post-mortem at
a runner boundary; unpublished jobs report KernelAborted. An acknowledgement
does not prove writes finished. Confirm `post-mortem.json` and `event-ring.jsonl`;
retain reason and capture failures. These and `.kernel-debug.json` are offline
JSON artifacts, but this CLI has no dedicated offline kernel-snapshot command.
Do not pass them to `inspect-state`. Interpret against typed definitions in
`crates/carrick-kernel/src/kernel/debug/{dto,post_mortem}.rs`.

In `post-mortem.json`, inspect `schema`, `run_id`, `reason`, optional `kernel`,
`findings`, `event_ring`, and `truncated`. A null kernel or named truncation is
an incomplete capture, not an empty graph or a clean invariant report. Preserve
unreadable ring records alongside readable ones.

## Related diagnostics

| Shell command | Input and purpose |
|---|---|
| `carrick debug core <path>` | Validate Linux aarch64 **guest ELF** core; not host Mach-O LLDB core |
| `carrick debug hvpatch-vm-ledger <artifact> --run-id <id> --source-sha256 <hash> --command-sha256 <hash>` | Authenticated VM lifecycle; executing CLI's binary hash participates |
| `carrick debug amplification-ledger <trace> [--output <path>]` | Complete AMP1 trace to typed work ledger; incomplete input fails |
| `carrick debug amplification-compare <a> <b> [--output <path>]` | Determinant-locked work/CPU comparison, not wall-time proof |
| `carrick debug exec-stamp-census <input> --workload-ns <ns>` | Complete EXECSTAMP2 export analysis |
| `carrick debug container-gate --image <image> --probe <binary> --gate-dir <dir> --mode sequential --output <path>` | Launch two containers in one carrier; concurrent mode also supported; not introspection |

Check subcommand help before use. Trace generation belongs to the trace skill;
never substitute missing evidence with relaxed validators or debug logging.
