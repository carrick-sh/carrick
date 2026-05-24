# Go full-conformance bring-up on carrick — design

Date: 2026-05-24
Status: approved (brainstorming)

## Goal

Make carrick run **standard Go programs** (anything `go build` produces) and
**match Docker `linux/arm64`** on Go's own test suite for the packages that
exercise carrick's emulation, with **zero correctness differences**. Timing
differences are acceptable only where Docker at the *same* oversubscription also
struggles.

This is the T2 (runtime conformance) + T3 (arbitrary programs) bar from the
bring-up tiering. T0 (smoke) and T1 (the multithreaded HTTP fixture, ~99.5% at
`CARRICK_EXPOSED_CPUS=10` after the EL1-kick fix) are already met.

## Guiding principles

1. **The macOS kernel does the heavy lifting.** Prefer host-kernel mechanisms
   (kqueue filters, real child processes, HVF stage-2 mapping) over in-memory
   carrick bookkeeping. Keeps behavior fork-coherent and correct under load.
   (Continues [[feedback_durable_macos_gap_fills]] and the epoll-via-kqueue
   model.)
2. **Differential-vs-Docker is the oracle.** Every gap is found and every fix is
   proven by running the *same* binary under carrick and Docker `linux/arm64`
   and diffing. Environmental failures appear in both and cancel.
3. **Correctness vs performance.** A `fatal error` / panic / wrong result that
   carrick produces and Docker does not is a correctness bug — bar is **0**. A
   deadline miss under forced GOMAXPROCS=10 on 4 perf cores is a performance
   characteristic — judged against Docker (QEMU, also oversubscribed).
4. **Observe at full speed.** The dtrace consumer perturbs timing races away
   (~60x slowdown); use in-process atomic counters (`CARRICK_KICK_STATS`-style)
   and `CARRICK_TRACE_REGS` for full-speed diagnosis. Deterministic (non-racy)
   gaps may use `carrick trace` normally.

## Background (what's already known)

- The high-P deadlock is fixed: a cross-thread kick (`hv_vcpus_exit` for SIGURG)
  could capture an EL1 vector PC (`0x20404`) and inject a signal there;
  `run_until_syscall` now resumes CANCELED-at-EL1 kicks (`ExecLevel`).
- carrick currently loads only **external-static-pie** Go binaries
  (`CGO_ENABLED=1 -buildmode=pie -ldflags "-linkmode external -extldflags
  -static-pie"`); plain `go build` (internal-linked `ET_EXEC`, base `0x10000`)
  collides with carrick's low structures, and internal-PIE faults
  (data abort at `0x39ee00`).
- Go 1.24 `os/exec` uses **pidfd** (`pidfd_open(434)` / `CLONE_PIDFD`); carrick
  returns ENOSYS, so subprocess spawn fails ("fork/exec: function not
  implemented"). First found via `sync` test `TestMutexMisuse` (Docker PASS,
  carrick FAIL).

## Decomposition (sequenced: A — gate → pidfd → loader → drive-to-zero)

### SP1 — Conformance gate (instrument + regression net)

A differential harness (extend `tests/conformance.rs`, reuse the existing
bollard/Docker plumbing):

- Cross-build a curated high-signal Go std-test set with the carrick-compatible
  recipe (external-static-pie, in a `golang` arm64 container), cached.
- For each test binary, run under carrick (`run-elf --raw --fs host`) and under
  Docker `linux/arm64`, with identical args (`-test.run Test` to skip
  source-reading Examples, `-test.short`, `-test.v`).
- Parse per-test `--- PASS/FAIL`, diff the sets, and assert **no carrick-only
  failures**. Report carrick-only failures as the actionable gap list.
- High-signal packages: `runtime`, `sync`, `sync/atomic`, `os`, `os/signal`,
  `os/exec`, `net`, `time`, `runtime/pprof`, `context`. Start with the fast,
  self-contained ones (`sync`, `sync/atomic`, `time`, `context`); add `runtime`
  (large) and the subprocess-dependent ones (`os/exec`, `os/signal`) after SP2.
- Output a baseline T2 tally; wire as a gate (allowed-diff list shrinks to 0).

**macOS angle:** none directly (Docker oracle); this is the measurement.

### SP2 — pidfd, kernel-backed (unblocks `os/exec`)

Implement the pidfd surface Go uses:

- `pidfd_open(434)` → allocate a guest fd backed by a host **kqueue** registered
  `EVFILT_PROC` / `NOTE_EXIT` on the real macOS child process for that guest
  pid. (A guest fork is already a real macOS child — see the fork path.)
- `clone` with `CLONE_PIDFD` → return a pidfd for the new child the same way
  (write the fd to the parent-supplied location, per the flag's ABI).
- `pidfd_send_signal(424)` → `kill(host_child_pid, sig)` (Linux→macOS signum
  translation as elsewhere).
- `waitid(P_PIDFD, pidfd, …)` → `waitpid`/`wait4` on the host child.
- Poll/epoll/read readiness on the pidfd: the EVFILT_PROC kqueue fd is readable
  when the child exits, so the existing `io_wait`/epoll-kqueue path observes it
  natively (the kernel tracks the process lifecycle).

**macOS angle (core):** the guest pidfd ↔ (host child pid, kqueue EVFILT_PROC
fd). The host kernel does process-exit tracking and signal delivery; carrick
only maps. Fork-coherent and load-correct.

Validates by: `os/exec` tests pass; `sync` `TestMutexMisuse` matches Docker.

### SP3 — Loader: run standard `go build` output

Relocate carrick's fixed low-memory structures out of the guest's
`ET_EXEC`/Go region:

- Move EL0 trampoline (`0x10000`), EL1 vectors (`0x20000`), and stage-1 page
  tables (`0x30000`) to a high reserved window (near
  `LINUX_SIGRETURN_TRAMPOLINE_BASE = 0x30_0000_0000`, or a parallel high
  window). Update `VBAR_EL1`, the EL0-entry trampoline address, and `TTBR0`
  accordingly; keep the stage-1 identity map covering both the guest low region
  and carrick's new high structures.
- **macOS angle:** HVF stage-2 maps carrick's pages wherever; the registers just
  point at the new bases. The guest's low VA (`0x10000`+) is then free for a
  plain internal-linked Go `ET_EXEC`.
- Then diagnose/fix the residual internal-PIE data abort (`0x39ee00`): determine
  whether it was a collision symptom (resolved by relocation) or a separate gap
  (e.g., on-demand paging / a segment carrick doesn't map for internal-linked
  layouts). Use the differential gate + `CARRICK_TRACE_REGS` to localize.
- Guard with the existing static fixtures (linux-aarch64-hello, the PIE Go
  fixture) so the relocation doesn't regress what already works.

Done with the gate as a regression net (SP1 first).

### SP4 — Drive correctness diffs to zero + T3

- Run the full package set through the gate; each remaining carrick-only
  failure becomes a focused bug, debugged with differential mn-probes +
  full-speed counters (the proven method).
- T3 acceptance: build a non-trivial program with plain `go build` under carrick
  (once SP3 lands) and run a real Go app; confirm output matches native/Docker.

## Acceptance criteria (definition of done)

- The conformance gate runs the high-signal package set and reports **0
  carrick-only test failures** vs Docker `linux/arm64` (correctness bar).
- `os/exec`-based Go programs run (pidfd works end-to-end).
- A standard `go build` binary (internal-linked) loads and runs under carrick.
- The gate is wired as a permanent regression check.
- Any remaining differences are timing-only and bounded by Docker's behavior at
  equal oversubscription, documented as such.

## Risks / open questions

- **Loader relocation is invasive** (VBAR/TTBR/trampoline). Mitigated by doing
  it after the gate (SP1) and pidfd (SP2), with fixture + gate regression nets.
- **pidfd ABI nuances** (CLONE_PIDFD vs pidfd_open; waitid P_PIDFD semantics;
  Go's exact probe sequence). Mitigated by tracing Go's actual calls and the
  differential gate.
- **Docker arm64 oracle stability** (QEMU timing jitter) — only matters for
  timing tests; correctness diffs are deterministic. Per `ltp-conformance`,
  exclude inverted timing DIFFs.
- **`runtime` test suite is large/slow** and some subtests need GOROOT/testdata;
  curate the subset and run `-test.short`.
