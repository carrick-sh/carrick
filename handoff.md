# Native-lane performance: state of play

**Date:** 2026-08-03 · **Branch:** `codex/native-store-default` · **Latest
implementation decision:** stop the current translation-publication memory
hypothesis; initialized metadata plus JIT bytes written project to 7.411% /
7.425% of total CPU, below the 10% opportunity gate ·
**Scope:** Darwin/aarch64 native backend (`--exec-backend native`, the shipped
default). VMM is explicitly NOT the target: one process per VM against a
~127-VM macOS ceiling makes it a dead end for build-shaped workloads.

## The goal

**Cold `go build` within 2-3x of native-arm64 Docker.** Carrick's premise is
running unmodified Linux binaries at host-native cost, so this number is the
product, not a metric about it.

The plan is [`docs/superpowers/specs/2026-08-02-performance-roadmap.md`](docs/superpowers/specs/2026-08-02-performance-roadmap.md).
Read it first; it carries the phase structure, the invalidation conditions, and
an appendix of rejected alternatives so nobody re-litigates them.

## Where we are

The authoritative shipped-default cold-build scoreboard is the serialized,
five-sample Carrick-then-Docker run in
[`docs/perf-results/2026-08-03-persistent-store-default-confirmation.md`](docs/perf-results/2026-08-03-persistent-store-default-confirmation.md):

| metric | Carrick | Docker | ratio |
|---|---:|---:|---:|
| cold `go build` workload wall | 8,575 ms | 821 ms | **10.4446x** |
| cold `go build` process elapsed | 9,326 ms | 977 ms | **9.5455x** |

This is still the official ratio. Reaching 3x requires removing another 71.28%
of Carrick's current workload wall (a 3.4815x reduction); reaching the 2x
product bar requires removing 80.85% (5.2223x).

The required current-default three-sample workload spread is also complete:
compute **3.3868x**, fs-walk **18.9286x**, 20-exec `compile -V` **72.1579x**,
and cold build **10.8761x**. It confirms the band but does not replace the
five-sample official result. Startup rounded Docker to zero milliseconds and
has no citable ratio. Full provenance and raw samples:
[`docs/perf-results/2026-08-03-current-default-workload-spread.md`](docs/perf-results/2026-08-03-current-default-workload-spread.md).

The latest campaign tested monotonic augmentation of already-published
translation units. Its mechanism was real: private translations fell 56.0%
and `segment-repeat` fell 56.3%. Its product result was decisively negative:
eight-quad same-binary ABBA measured child CPU ratio **1.0728**, paired 95%
interval **[1.0653, 1.0806]**, and workload-wall ratio **1.2786**. The candidate
lost every quad, so it and its temporary controls were removed. Full evidence:
[`docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md`](docs/perf-results/2026-08-03-native-store-monotonic-augmentation.md).

The approved trusted-entry route attribution is now complete. Two independent,
naturally completed 997 Hz captures agreed within 0.1703 percentage points on
the dominant route. Direct arrival projects to only 4.17% of total CPU;
indirect arrival to 3.77%; even removing all three route copies projects to
only 7.96%. All samples joined to exact JIT ranges, both native-emitted and
persistent-unit replay origins were observed, and all DTrace drop/error counts
were zero. The route line is therefore stopped without a production candidate.
Full evidence:
[`docs/perf-results/2026-08-03-trusted-entry-route-attribution.md`](docs/perf-results/2026-08-03-trusted-entry-route-attribution.md).

The approved exec/exit attribution is also complete. The opt-in `EXECSTAMP2`
export and fail-closed Rust census reconciled every exec, fork, terminal exit,
and reap in two independent 20-exec runs and two independent cold builds. The
micro named exec-total at a stable 16.80% of invocation CPU, but that same
segment was only 4.98% on the cold build. The cold build's complete strict
lifecycle opportunity was **8.858% / 8.791%** (mean **8.824%**), below the
campaign gate. The separately reported child-to-exec window averaged 9.644%,
mixed guest execution with Carrick repair, and did not name the same segment.
The first capture was correctly rejected for a missing spawned-thread terminal
stamp; the fixed exporter then closed all accepted trees exactly. No production
exec/exit hypothesis was selected. Full evidence:
[`docs/perf-results/2026-08-03-current-exec-exit-attribution.md`](docs/perf-results/2026-08-03-current-exec-exit-attribution.md).

The approved exact context-traffic census is now complete. The new Rust
diagnostic fail-closed joins sampled JIT PCs to authenticated retirement
snapshots and classifies each 64-bit context access by exact slot, physical
register, and direction. Two independent accepted cold-build captures joined
every JIT sample. Aggregate context traffic projects to **16.0730% / 16.1738%**
of total CPU, but source audit splits it into distinct mechanisms. The largest,
x17 authority through slot 1128, is only **7.0008% / 7.1812%**. No
non-overlapping mechanism clears 10%, so no emitter candidate was selected.
Full evidence:
[`docs/perf-results/2026-08-03-current-context-traffic.md`](docs/perf-results/2026-08-03-current-context-traffic.md).

The refreshed current-default fault ownership line is now complete. Two
source-identical NFAULT2 captures put host-other at **63.2115% / 62.7395%** of
sampled zfod, with exact `as_fault` and `zfod` totals agreeing within 0.67% and
0.52%. Two independent export-only translation censuses then reconciled
140/140 process-image epochs apiece and named 6.873/6.877 GB of initialized PC
map/recovery metadata plus 618.7/618.9 MB of JIT output. Even charging the old,
favorable 3.84 us all-system-CPU cost to every corresponding page projects
only **7.4111% / 7.4247%** of total CPU. No production allocation or metadata
change was selected. Full evidence:
[`docs/perf-results/2026-08-03-current-native-fault-ownership.md`](docs/perf-results/2026-08-03-current-native-fault-ownership.md).

## What landed (2026-08-02/03, six waves, all merged with `just ci` green)

**Exec pipeline.** Payload SHA-256 removed from the default artifact digest
(`CARRICK_EXEC_FAST=0` hatch); eligible PT_LOADs map `MAP_PRIVATE` from the
executable's own host file (`CARRICK_EXEC_FILE_BACKED=0`); execve probes read 1
and 256 bytes instead of walking the whole image twice. The per-exec chain is
~20 ms, of which ~5.3 ms is Darwin's own execve+dyld floor. The roadmap's "fixed
~18 ms" item was mis-measured and is corrected in place
([`2026-08-03-native-exec-fixed-cost-decomposition.md`](docs/perf-results/2026-08-03-native-exec-fixed-cost-decomposition.md)):
the zygote shape cannot exist under the libdispatch and PID-preservation
constraints, and the real win there was a per-MB term misfiled as fixed.

**Tier D (direct execution).** From "a guest could only leave by calling exit"
to: exit path plus a written guest-leave contract, dynamic linking (real glibc
`ld.so`), guest-created executable pages (`mmap(PROT_EXEC, fd)` scan+patch, two
lowerings), per-thread TLS via a **runtime-proven** Darwin TSD chain, wiring
into the shipped driver with fork/vfork/execve and real fd passthrough, and
async signal delivery + `rt_sigreturn`. Live-verified: `/bin/dash -c 'echo hi'`,
real CPython `print(1)`, real CPython `threading.Thread`, `timeout 1 sleep 5` →
rc=124 all-tier-D. Everything unproven fails closed with a named reason.
Reachable behind `CARRICK_NATIVE_DIRECT=1`; **default OFF** (blockers below).

**Persistent translation store.** Per-host, keyed by image identity, single
publisher elected via non-blocking host locks, LRU-pruned, crash-safe, corrupt
store fails closed to local translation. Template emission reached **parity with
native emission** (proven by disassembly plus a word-identity test) once the
regression was root-caused to block-ENTRY shape — an 11-12 instruction
`BindingIndex` guard versus a 3-instruction trusted entry, NOT the recorded
fusion-loss suspect. The v5 wire splits each block into a hot blob (decoded at
first lookup) and a cold blob (pc-map/recovery, ~98% of records, left undecoded
in the mmap until a fault needs it). The persistent store is now **default
ON**; exact
`CARRICK_DSR_PERSISTENT_STORE=0` is the rollback/control hatch. Its retained
same-binary result was -8.33% child CPU and -8.84% workload wall. Roughly 22k
lines of superseded machinery (the Mach-O emitter, the
codesign+dlopen transport, `BindingIndex`, cell sidecars, edge trampolines, V3
metadata) were DELETED, not parked behind flags.

**Memory.** Protection bookkeeping went from one BTreeMap entry per 16 KiB page
(~295k entries per Go process, re-consulted on every dispatch write) to
coalesced intervals — anon reservations are O(1), and the fixture that pinned it
went 1.66 s → <10 ms. Identical host syscall sequence, identical guest ABI.

## What's next

The exec/exit and context-traffic lines are closed at attribution rather than
carried into production experiments. Their exact exporters and censuses remain
opt-in diagnostics. A crashed run can also be read from a saved core through
the always-on event ring. No official ratio refresh is warranted because
neither line retained a production candidate. `RUST_TEST_THREADS=1 just ci`
passes at the current source authority.

1. **Attribute the residual host-allocation first-touch population.** The
   current fault captures establish that host-other dominates zfod, while the
   largest named source (translation publication metadata plus JIT bytes)
   explains about 47% of the scaled host-other population and fails the 10%
   gate. Add export-only cumulative allocation/initialization counters at
   source-distinct remaining owners, close them at exec/exit, and carry a
   production candidate forward only if the same owner clears 10% in two
   agreeing captures. Core decoding of these counters is a future diagnostic;
   the always-on event ring remains the crash path for lifecycle history.
2. **Keep eager full translation as a deferred future design, not the next
   patch.** Translating a complete eligible image once up front could amortize
   publication and avoid the losing per-process merge path measured here. It
   would not replace incremental augmentation for JIT-on-JIT/dynamically
   generated code, so both semantics would eventually be required. The user
   explicitly deferred this until the current performance campaign has a
   higher-confidence next bucket.
3. **Tier D remains default-off.** Its ubuntu image-specific x18 crash,
   multi-threaded fork/signal tail, bad64 decode gap, and record-lock blocker
   still require correctness closure before any performance flip.

## Confidence

- **Very high (98%):** current fault ownership is stable and complete. Both
  captures completed naturally with every loss/identity/catalog counter zero;
  host-other zfod differs by only 0.472 percentage points.
- **Very high (98%):** the translation-publication source census is stable.
  Both accepted runs reconcile 140/140 independent process-image epochs and
  initialized metadata differs by only 0.052%.
- **High (96%):** the named publication-memory mechanism does not clear the
  production gate. Two deliberately favorable projections remain below 7.7%
  in both bindings; untallied allocator churn was not promoted into a result.
- **High (95%):** the official shipped-default result remains 10.4446x. No
  rejected candidate code is retained and no projection was substituted for a
  fresh Carrick/Docker run.
- **Medium-high (80%):** residual host-allocation first touch is the best next
  lane. The population has measured mass, but it is not yet source-distinct and
  therefore cannot authorize a patch.

## Discipline that earned its keep (do not relearn these)

- **The perf knobs are HOST env vars.** Passing them through `carrick run -e`
  makes both ABBA arms identical — an entire measurement round was invalidated
  this way and read as "no effect".
- **Rebuild and prove the binary.** `just build` after runtime changes, then
  `strings -a target/release/carrick | grep <knob>`. A second round was
  invalidated by measuring a pre-merge binary, and it was caught only because
  the numbers contradicted mechanism-level counters.
- **Verify every merge with the FULL serial suite, twice.** Two defects reached
  the merge gate that the lanes' own green runs missed: a cross-lane SIGTRAP
  (which turned out to be a fork-poisoned libdispatch semaphore masking a real
  panic) and a suite-order failure from tier D hint cursors colliding with
  `BIAS_CANDIDATES` to the digit.
- **Attribute before fixing.** Three investigations each redirected the campaign
  off a wrong target: the build is amplified, not serialized; the template
  regression is entry shape, not fusion; lazy install alone could not win
  because `compile` touches ~99% of its unit's blocks.
- Counter and mechanism evidence beat wall clock under load. Wall numbers taken
  with siblings running are "suggests", never "confirmed".

## Branch state at handoff

`0e35a2d37b8f74acdb83c245f5fcfe7257f892b3` is the source authority for the
accepted fault and publication-memory captures. Its signed binary has SHA-256
`813201a8f0b71f495c2771b7e2deee941c1c6ec9832aca0bf7d571be7f065819`
and Mach-O UUID `407C0AF5-5880-3A2F-816F-5CBDA63CBB42`. Commits `aa29e872`
through `0e35a2d3` retain the authenticated owned-range publication, NFAULT2
profile, fail-closed Rust ownership reader, and export-only publication-memory
census. They do not alter default guest semantics. `RUST_TEST_THREADS=1 just
ci` passed at that source authority.
Nothing has been pushed and local `main` has not moved. Target-only raw ABBA,
mechanism, signed-binary, store, attribution, and scoreboard receipts remain
under `target/perf/` and are intentionally not committed.
