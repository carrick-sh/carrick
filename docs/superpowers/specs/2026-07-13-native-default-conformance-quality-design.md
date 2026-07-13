# Native-Default Conformance Quality Campaign Design

**Date:** 2026-07-13

**Status:** approved design

## Purpose

The Darwin-native DSR backend is Carrick's default execution backend. This
campaign makes that default credible for real workloads: run the complete
conformance manifest through the native lane, remove crashes, hangs, load
instability, and broad ecosystem blockers, then produce a reviewed native-lane
bless whose remaining differences are narrow, deterministic, and understood.

HVF/VMM performance is outside this campaign. HVF remains a lifecycle reference
when useful, but native correctness and workload coverage determine priority.

## Completion boundary

The campaign is complete only when all of the following are true at the same
checked-in revision:

- `just ci` passes;
- the signed native ABI probe gate passes;
- every suite in the 2,127-suite manifest runs through `macos-native-dsr`;
- the final native run contains no `TIMEOUT`, `CARRICK_CRASH`, unexplained
  `REGRESSION`, or load-dependent verdict;
- Node, Go, and CPython real-world workload lanes are usable, including
  fork-to-exec children that create threads;
- serial and loaded runs agree after repeat sampling;
- every remaining native-only difference has a written semantic diagnosis and
  is narrow enough not to block ordinary workloads;
- `scripts/conformance/baseline.native-dsr.jsonl` is blessed only from that
  reviewed full run; and
- `docs/native-default-conformance-campaign.md` contains the measured ladder,
  evidence paths, remaining gaps, and final proof commands.

A successful build, a partial suite, or a baseline rewrite by itself is not
completion evidence.

## Measured starting point

Fresh signed smoke evidence at `df43c414` is
`target/conformance/native-default-goal-smoke-20260713.jsonl`:

- 23 selected suites;
- 15 `MATCH`;
- 4 `REGRESSION`;
- 3 `TIMEOUT`;
- 1 `CARRICK_CRASH`.

The failures separate into three measured classes:

1. **Fork-child lock inheritance.** An isolated `cpython-threading` run times
   out at 300 seconds. Live LLDB captured the child in
   `host_signal::reinit_after_fork -> clear_thread_waiters ->
   parking_lot::Mutex::lock`. The forking thread holds the waiter mutex across
   `fork`, yet the child still observes the waiter mutex as locked. A copied
   contended parking-lot queue is the leading mechanism hypothesis; the required
   red test must prove that detail before implementation receives credit.
2. **Direct-exec reservation false collisions.** Node and gzip replacements
   fail before image retirement because hint-based `mmap` redirects to
   `0x7000000000`. After a current Direct mapping splits the dyld delegated
   range, the old single-covering-region test no longer recognizes the vacant
   tail.
3. **Post-fork thread creation.** `go-runtime`, `go-sync`, and 19 CPython
   threading assertions reach the explicit `EOPNOTSUPP` guard that prevents
   guest thread creation after fork-to-emulated-exec. `go-build` separately
   times out with its compiler child executing; its exact terminal interaction
   with the guard still needs the diagnostic clone trace. This class is not an
   esoteric gap: it blocks normal compilers, runtimes, subprocesses, and test
   workers.

The isolated Go and CPython artifacts, LLDB cores, and raw logs are recorded in
the campaign ledger. No current count is projected beyond these measured runs.

## Priority and bless policy

Work is ordered by user-visible impact:

1. crashes, hangs, deadlocks, corruption, and load-sensitive behavior;
2. blockers for Node, Go, CPython, shells, compilers, and package/build tools;
3. broad syscall and LTP framework blockers that hide many assertions;
4. isolated fidelity gaps;
5. esoteric features with no demonstrated real-workload impact.

The first three classes are fix-forward. They cannot be blessed away.

A native-only difference may be blessed only when it is deterministic across
repeats, has an understood Linux-versus-Darwin semantic explanation, has no
crash/timeout/load signature, does not prevent a real workload from completing,
and is explicitly listed in the ledger. TCONF-on-both-sides is recorded as not
exercised, not as parity. Inversions are reviewed assertion-by-assertion before
they are accepted.

## Considered architectures

### 1. Incremental fork-safe reconstruction with a mandatory escalation

This is the selected approach. Repair the Carrick-owned post-fork state that
evidence identifies, then experimentally reopen post-fork host-thread creation
behind a diagnostic fail-closed switch. Promote support only after live
fork-exec-thread workloads are repeatably clean.

If the resulting host failure is inside irreparable Apple runtime state rather
than a Carrick-owned registry or synchronization primitive, stop incremental
patching and implement the self-reexec path below. This is a hard evidence gate,
not permission to leave the workload unsupported.

This approach is the smallest route that can retain Linux PID/fd semantics and
may avoid serializing the whole runtime when the actual unsafe state is local.

### 2. PID-preserving Carrick self-reexec immediately

On every guest `execve` reached from a fork child, host-`execve` the Carrick
binary itself and reconstruct the preserved Linux process state from an
inherited capsule. Host exec preserves the PID and resets Darwin libc,
libpthread, and libdispatch state.

This is the most robust boundary but requires a versioned state capsule for
guest fd metadata, namespace/process-arena attachment, cwd/root/mount state,
signal state that Linux preserves, VFS mutations, and the new ELF request. It is
the required fallback if the incremental experiment proves Darwin process state
cannot be repaired safely, but starting here would delay the already isolated
lock and mapping fixes.

### 3. Bless the post-fork thread rejection

Rejected. It would make a full overlay mechanically green while `go build`, Go
runtime tests, and ordinary CPython subprocess/threading behavior remain
broken. That conflicts with the purpose of a native default.

## Architecture

### Slice A: fork-resettable waiter state

`THREAD_WAITERS` must not reuse a mutex or parking queue copied from a
multithreaded parent. Replace it with a fork-resettable registry whose backing
allocation is reached through an atomic pointer. The parent never frees a
published backing. In the single-threaded child, before any waiter operation,
install a fresh empty backing and intentionally leak the inherited copy. This
mirrors the existing fork-safe `NATIVE_PROCESS_KICKER` lifetime rule and avoids
running destructors or unlock paths through copied synchronization state.

Keep the current at-fork guards for stores that still need a coherent parent
snapshot, but do not treat guard ownership as proof that a parking-lot wait queue
is safe after fork. Extend the resettable pattern to another registry only when
a red test or live stack proves the same failure class there.

The red test creates actual contention on the waiter registry, forks while the
forking thread owns the prepare guard, then bounds the child's reset and exit.
Current code must time out; repaired code must exit promptly. The live
`cpython-threading` case then proves the integration behavior.

### Slice B: exact non-overwriting Direct reservations

Replace the hint-based first attempt with an exact Mach reservation using
`mach_vm_allocate(..., VM_FLAGS_FIXED)` without `VM_FLAGS_OVERWRITE`. The local
SDK contract says fixed allocation succeeds at the requested address only when
possible; overwrite is a separate explicit flag. Protect a successful
allocation with `VM_PROT_NONE` and keep the existing RAII reservation through
image mapping and relocation.

If exact allocation reports no space, accept only the already measured dyld
delegated empty tuple. Never use `MAP_FIXED` as a vacancy probe and never accept
an arbitrary gap without acquiring ownership. Use maintained Rust Mach bindings
rather than adding a new raw FFI declaration.

The red host test reproduces the real split shape: map a source page in the
canonical Direct range, fork, then reserve the Node-sized target tail. Existing
sentinel-preservation tests remain the collision safety gate. Live gzip exec,
Node app smoke, and Node V8 smoke prove the workload path.

### Slice C: post-fork thread lifecycle

Keep the production `EOPNOTSUPP` guard while gathering evidence. Add one
explicitly unsafe diagnostic opt-in that bypasses only this guard; it must not
alter mapping, signal, or thread semantics. Run the smallest fork-exec-
`pthread_create` probe with `carrick debug lldb-run`, then `go-build`, isolated
Go runtime/sync suites, and CPython threading/subprocess suites.

For each failure, distinguish:

- a Carrick-owned copied lock/registry, which is rebuilt or replaced in the
  child before guest execution;
- a stale DSR cache/publication state, which is reset through the existing
  translator lifecycle;
- an Apple libc/libpthread/libdispatch state failure not owned by Carrick,
  which triggers the self-reexec architecture; or
- a Linux emulation gap after thread creation succeeds, which receives its own
  probe and ordinary syscall fix.

The production guard is removed only after the dedicated probe and the four
real-workload gates pass repeatedly without a host trap, crash, timeout, or
load-only flip. The diagnostic bypass is then removed so the supported path and
the tested path are identical.

If self-reexec is triggered, the fresh Carrick image inherits a single
non-CLOEXEC capsule fd. The capsule is versioned and checksum-validated before
old-image retirement. It contains only Linux state preserved across exec plus
references needed to reattach durable shared arenas and surviving host fds.
Failure before host exec returns Linux `ENOMEM`/`ENOEXEC` without retiring the
old image; failure after host exec is a fatal runtime error because rollback is
impossible. The host PID remains unchanged.

### Slice D: conformance ladder and load proof

Each slice climbs the narrowest relevant gates before broadening:

1. forked host unit tests and exact native reducers;
2. signed `just conformance-probes`;
3. native smoke at one worker;
4. native smoke at four workers, repeated three times;
5. Node, then Go, then CPython ecosystem runs;
6. LTP full-tier run, fixing framework blockers before individual assertions;
7. one complete 2,127-suite candidate run at one worker;
8. one complete loaded run at four workers;
9. review every non-MATCH row against the bless policy;
10. a full, unfiltered `--bless` run for `macos-native-dsr`; and
11. a post-bless full run proving the overlay has no gating regressions.

Carrick and Docker never run concurrently. Every run has a scoped
`CARRICK_RUN_ID`, JSONL output, and raw logs. Any intermittent row is sampled at
least three times and remains unblessed until classified.

## Progress tracking

`docs/native-default-conformance-campaign.md` is the controller ledger. Every
entry records date, revision, exact gate and worker count, measured verdict,
artifact path, classification, and next action. Expected post-fix results are
kept in a separate `Target` column and never promoted to measured state before
the authoritative run completes.

Source fixes, probes, and ledger updates are committed in narrow logical
changes. The final overlay bless is a separate commit so its evidence and
review surface are unambiguous.

## Verification and failure discipline

- Every production fix begins with a failing automated test that is observed
  red for the expected reason.
- Runtime behavior is verified with the signed CLI, not a bare `cargo build`.
- A timeout is captured with LLDB/event-ring evidence before changing waits.
- A conformance mismatch is checked against the Docker oracle in a separate
  phase; Linux syscall-shape evidence uses in-container `bpftrace` when needed.
- A fix is not credited from compile success alone: its reducer, originating
  suite, nearby ecosystem lane, and load sample must all pass.
- `just ci` and the signed live workload close the campaign.

## Out of scope

- HVF/VMM performance optimization or backend comparison;
- declaring Carrick production-ready or a hardened trust boundary;
- hiding real-workload failures behind the native overlay; and
- unrelated cleanup outside code touched by a proven native failure.
