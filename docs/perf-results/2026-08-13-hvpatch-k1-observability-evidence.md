# HVPatch K1 — observability contract landed, GO withheld

**Decision: NO-GO for K1.** Three of the four remaining K1 deliverables are
GREEN and live-verified. The fourth — the exact `68 fork / 67 exec / 69
process` lifecycle receipt — **cannot be produced on any commit tested**,
including the commit this session started from. The blocker is a
pre-existing HVPatch fork/exec lifecycle defect, newly attributed here, not
a regression from this work.

This document exists because the K1 gate is a contract. The observability
work is done and demonstrable; claiming GO without the lifecycle receipt is
exactly the scope error the 2026-08-12 re-baseline was written to prevent.

## Provenance

| Field | Value |
| --- | --- |
| Commit | `ce369be390c1590cf2edcbe31d5a80acf60dc665` |
| Signed binary SHA-256 | `c37ff8c09169e2dc5a3ae28718b677ebced1a03339062f2bb94210d954a137e4` |
| Signed binary LC_UUID | `FECD2346-FFF9-39EA-B80E-210D7D5EC7C8` |
| Entitlement | `com.apple.security.hypervisor` present (built via `just build`) |
| Host OS | macOS 27.0, build `26A5406e` |
| Kernel | `Darwin 27.0.0 arm64` |
| Hardware | Apple M4, 10 logical CPUs (4 performance + 6 efficiency) |
| Toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Go fixture image | `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b` |
| Ubuntu image | `sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea` |
| Baseline commit for attribution | `25f67f1fa` (session start) |

Carrick and the Docker oracle were never run concurrently. No Docker
workload ran during any measurement below; the daemon was only queried for
image digests.

### Fixture

Exact argv for every HVPatch go-build run in this document:

```
carrick run --exec-backend hvpatch -e CARRICK_RUN_ID=<scoped> -w /tmp \
  localhost:5005/carrick-go-conformance:1.24 /bin/sh -c '<guest script>'
```

The guest script is `scripts/perf/native_go_build.py`'s `guest_script()`
verbatim (write `h.go`, `go build -o h ./h.go` under a run-scoped `GOCACHE`,
run `./h`, print `WORKLOAD_NS` and `BUILD_OK`).

### Raw artifacts

| Artifact | SHA-256 | Bytes |
| --- | --- | --- |
| Live kernel snapshot (`e2e-snap.json`) | `25aee63ad5d1a3bd47a580a0a21a4e6f56a748e138ce0b1921b86aed0df328ab` | 12,667 |
| K1 lifecycle raw stream (`k1-lifecycle.raw`) | `0fa1887cbd9ce638ea12f60bcc7c3e7e3547667640128278a67347f7f32934f9` | 1,031 |
| Post-fix go-build log (`k1-fixed.log`) | `024f748ab2101f3a14b50105678b1fe372de86aac64b009cfba2dad955e92c0f` | 1,238 |
| Baseline-commit go-build log (`k1-base.log`) | `5df3ff865c68639e3363b8cad9adb36e4290c6dc15e967f5db91f976fad074c5` | 153 |

## Measured results

Everything in this section was observed. Nothing here is projected.

### Live debug protocol (#26) — GREEN

`carrick debug hvpatch-kernel --run-id <id> [--table ...]` reads one
coherent snapshot from a running guest over a per-run authenticated
`AF_UNIX` socket.

Against a live `ubuntu:24.04 /bin/sleep` under `--exec-backend hvpatch`,
CLI exit 0, **12,667 bytes** of validated canonical JSON:

- schema `carrick.kernel-debug-snapshot.v1`, snapshot schema version 6;
- root task `id=25365, serial=6`, `lifecycle=live`, `mm=1`, `sighand=2`;
- its thread `tid=25365, serial=7`, `file_table=3`, `fs_context=4`,
  `credentials=5`;
- mm 1 with `asid=1`, `stage1_root_gpa=0xb0000000`, `ttbr0`, 20 mapping ids;
- 39 VMA rows, frame rows joined to mapping rows in both directions;
- file table / slot / description, fs, credentials, group, session, sighand
  and signal tables all present and mutually joined.

Endpoint on disk: `drwx------` directories, `srw-------` socket,
`-rw-------` owner record. The path carries only a 128-bit digest of the
run ID, never the run ID.

Failure modes exercised: not-listening (named error, exit 1), a second
server refused against a live owner, stale-owner reclamation after a dead
owner, `--table` filtering, unknown table name refused by name, and the
protocol's schema / missing-table / duplicate-id / broken-join /
partial-frame / trailing-byte / timeout rejections.

### Coherent file snapshots (#25) — GREEN

The snapshot joins the current file authority (the Kernel `FileTable` that
production dispatch already reads — `IoState` no longer exists) with
task/mm/frame/signal state and fails closed on busy or torn data. Proven by
the live capture above rather than by tests alone.

`RuntimeIo` (stdout/stderr buffers, stream mode) is deliberately **not** in
the snapshot: it is process-local output transport, and the code states that
Linux fd-table authority lives exclusively in the Kernel `FileTable`. It
carries no guest-visible Linux semantics, so including it would violate the
module's own "typed kernel graph only" invariant.

### Typed lifecycle identity (#27) — GREEN

Lifecycle records now carry identity that cannot be conflated. A Linux TGID
is reused within a run and an ASID is recycled on exit, so the previous
`(pid, asid)` key could not prove two records described the same task.
`TaskSerial` is never reused by one Kernel and was being discarded —
`task_identity` returned `TaskId` and dropped the serial its own `TaskKey`
already held.

Live on the signed binary, a real HVPatch run emits the paired records:

```
IDENTITY  pid=31648 task_serial=6 parent_serial=0 mm=1
LIFECYCLE phase=0 pid=31648 ppid=0 tid=31648 asid=1
IDENTITY  pid=31648 task_serial=6 parent_serial=0 mm=1
LIFECYCLE phase=5 pid=31648 ppid=0 tid=31648 asid=1
```

A root correctly reporting no parent. The `hvpatch-k1-lifecycle.d` profile
is at version 2 and joins the identity into its birth and exec aggregations;
`dtrace -e` compiles it against the rebuilt provider. The strict Rust reader
requires a nonzero serial and mm on every birth, rejects a duplicate
`TaskSerial`, and rejects an exec naming a serial no birth declared.

### Gates

`cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
and `just test` (41 suites, including the 1,536-test sequential
`carrick-runtime` library suite) all pass at the evidence commit.

`just ci` was **not** run end-to-end at this commit; `test-integration`,
`doc`, `deny`, `check-matrix` and `lint-domains` remain unverified here.
That is a gap in this document, not a claim.

## The blocker: no 68/67/69 receipt

A cold `go build` under `--exec-backend hvpatch` does not complete.

**Attribution.** The failure reproduces on a signed binary built from
`25f67f1fa`, the commit this session started from, with none of this
session's changes present: exit 134, identical single-line diagnostic. It is
therefore **pre-existing**, not caused by the K1 observability work. The
handoff's claim that the Phase-4 prototype completes 68/67/69 describes an
earlier state that has since regressed.

Two distinct defects, in the order the run hits them.

### 1. Fork-path fd install aborted the runtime — FIXED here

`handle_in_process_fork` installs the child's pidfd into the forking
parent's fd table but reached it through the fd helpers' ambient
`captured_file_table()`. The HVPatch fork path runs on the vCPU loop outside
any dispatch boundary, so no captured resources exist on that thread and the
lookup took its fail-closed branch: `std::process::abort()`. Any guest
forking with `CLONE_PIDFD` — which the Go toolchain does — killed the whole
runtime with SIGABRT.

Backtrace at the abort point:

```
captured_file_table
  <- install_fd_at_or_above (fd_helpers.rs:98)
  <- install_fd (fd_helpers.rs:209)
  <- install_reserved_hvpatch_child_pidfd (proc.rs:1188)
  <- handle_in_process_fork (quiesce.rs:1172)
```

Fixed in `ce369be39` by passing the exact parent `KernelContext` the fork
handler already holds and establishing the scope with
`with_captured_resources` around the install and its rollback — the K1 rule,
not a workaround.

### 2. Fork/exec context staleness — RED, unfixed

With the abort removed the run advances and fails differently:

```
WARN  hvpatch kernel child reservation failed; fork(2) = EAGAIN
      error=kernel context revision is stale
go: error obtaining buildID for go tool compile:
    fork/exec .../compile: resource temporarily unavailable
ERROR hvpatch child loop failed child_pid=34456
      error=configuration refused: prepare authoritative Kernel exec:
            kernel context is foreign or internally inconsistent
```

The parent's captured `KernelContext` goes stale across the fork
reservation, and children then fail the exec transaction's context
authenticity check. This is K3/K4 territory — the fork reservation and exec
prepare/commit contracts.

**Diagnosed, not yet fixed.** `PublishedFork::commit` bumps the **parent's**
task revision, because committing a child calls `add_child` and the
children set is observable state the revision covers
(`operations.rs:623`, `:634`). `reserve_fork` then rejects any caller whose
captured `parent.revision` no longer equals the registry's current record
revision (`operations.rs:1097`).

So two threads of one Linux process forking concurrently cannot both
succeed: thread A's commit advances the shared parent's revision, and
thread B — which captured its context before that — is refused with
`StaleContext` and the guest receives `EAGAIN`. The Go toolchain forks
concurrently from several threads, which is exactly why it reports
`fork/exec .../compile: resource temporarily unavailable`. **Linux requires
both forks to succeed**, so this is a semantic defect, not a load
condition.

The same reasoning applies one layer down: for `ForkParentMode::Caller` the
reservation records `child_parent_revision = caller_revision`, and commit
re-checks it (`child_parent_record.revision != child_parent_revision` →
`ForkParentChanged`), so relaxing only the reserve-time check would move the
failure to commit rather than remove it.

The shape of the fix — deliberately not applied here without room to test it
properly — is that gaining a child must not invalidate a sibling's in-flight
fork. Commit already holds the registry write lock, so it can read the
parent's current revision and advance from it atomically; the captured
revision should only prove the parent *task generation* is unchanged, which
the `task.key()` comparison already does. Changing a lifecycle transaction
contract needs red tests for concurrent sibling forks first.

Simple fork/exec guests are unaffected: `sh -c 'echo a; /bin/true; echo b'`,
a three-iteration `/bin/true` loop, and `ls /` all exit 0 under HVPatch. The
defect needs the Go toolchain's concurrent `CLONE_PIDFD` fork/exec pattern.

## Incidental correctness fix

The live debug protocol found a real runtime bug on its first use against a
guest. The snapshot refused with "file-table open-path index names no live
slot", naming the orphan `(3, "/usr/lib/locale/C.utf8/LC_CTYPE")` — glibc's
locale file, opened, mapped and closed during startup. Only one of the
several slot-removal sites cleared `fd_open_paths`, so every other close
path left the index claiming a freed fd number for the lifetime of the
table. Fixed in `b72d11142` at the common `note_fd_closed` funnel, with a
red-first regression test.

A second, subtler defect was fixed in the same area: `validate_snapshot` ran
*before* every revision check, so a mutation landing between two collection
guards was reported as `InvariantViolation` — telling an operator a healthy
run was corrupt. Verifying revisions and the registry epoch first means a
moved revision retries and is never validated, while a surviving join
failure on an unmoved revision is genuine corruption.

## Design correction recorded

The K1 spec's endpoint layout,
`$TMPDIR/carrick-kernel/<uid>/<sha256>/snapshot.sock`, is **not bindable**
on the reference platform. macOS `sun_path` holds 104 bytes including the
NUL; a per-user `$TMPDIR` (49 bytes) plus `carrick-kernel/<uid>/` plus a
64-hex digest plus the socket name is **146 bytes**, so every bind would
fail `EINVAL`. Shipped instead: a fixed `/tmp/carrick-kernel` base and a
32-hex (128-bit) token, landing at 70 bytes, with an over-long path refused
by name rather than deferred to `bind`.

The fixed base is also the more correct rendezvous — the runtime and the CLI
are separate processes and `$TMPDIR` is not guaranteed equal between them.
Isolation is unchanged: 0700 parents, 0600 socket, and the peer's effective
uid checked through the fallible `peer_credentials` on every connection,
with best-effort zero credentials refused.

Also recorded: Darwin returns `EINVAL` from `setsockopt` on an `AF_UNIX`
socket whose peer has closed and whose write half is shut down. Setting the
socket timeout once per operation instead of per loop iteration avoids
turning every completed exchange into a transport failure on the final read;
the absolute deadline still bounds the loop.

## Retained commits

| Commit | Content |
| --- | --- |
| `b72d11142` | Retire fd open paths on every close (+ red-first test) |
| `3db419d5e` | Live kernel debug protocol, CLI, and snapshot validation ordering |
| `bec10645f` | Unambiguous task identity in K1 lifecycle events (Rust + USDT + D + reader) |
| `ce369be39` | Exact parent context for the HVPatch fork-path fd operations |

## K1 gate ledger at this commit

| Row | State |
| --- | --- |
| Final coherent file snapshots (#25) | GREEN — live-verified |
| Live `carrick debug` protocol (#26) | GREEN — live-verified |
| Typed lifecycle/CTF identity (#27) | GREEN — live-verified |
| 68/67/69 lifecycle receipt | **RED — cannot be produced; blocker above** |
| `just ci` end-to-end | RED — not run at this commit |
| Durable K1 GO evidence (#29) | this document; records NO-GO |
| File lifecycle binding (K3, task #41) | RED — unchanged, still K3 |
| Sole file/VFS authority (K3) | RED — 0 of 361 call sites migrated |
| Legacy file state deletion (K3) | RED — unchanged |

The three K3 rows are **not** K1 completion criteria and are named here as
remaining RED rather than claimed, per the 2026-08-12 re-baseline.

## Risks

- The 68/67/69 receipt is load-bearing for K1 and for every later phase's
  comparison baseline. Until the fork/exec context defect is fixed there is
  no current lifecycle receipt on any commit, so K2's "fork work scales with
  writable table paths" gate has nothing to measure against.
- No product-visible performance number has been produced since the
  ~4.27 CPU-s reading of 2026-08-09, and that reading cannot be reproduced
  while the fixture aborts. K1 was designed to require no performance claim;
  that must not continue past K1 GO.
- A run that exits without unbinding leaves its debug socket behind, because
  Rust statics are never dropped. Stale-owner reclamation handles it (the
  next run with the same run ID proves the owner PID is dead and reclaims),
  and that path is tested, but the socket is not removed at exit.

## Next architectural question

Why does the parent's captured `KernelContext` go stale across the HVPatch
fork reservation, and why does the child's context then read as foreign to
the exec transaction? That is one question about the fork/exec transaction
contracts, and answering it is the precondition for every remaining K-phase
receipt.
