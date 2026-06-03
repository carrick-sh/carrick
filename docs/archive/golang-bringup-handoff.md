# Handoff — Go runtime bring-up on carrick (2026-05-24, continued)

## LATEST (2026-05-24 late PM): PIE is green; current blocker is async-preempted large equality

### Logical commits landed in this continuation

- `aba7101 fix(fork): quiesce vcpus during concurrent exec`
- `9979728 fix(fs): seed raw guest baseline paths`
- `aa55a78 fix(fs): preserve host symlink stat identity`
- `3c497d5 fix(waitid): ignore unrequested stop states`
- `919e762 fix(loader): support threaded Go PIE startup`
- `10a694a test(go): add userarena large allocation repro`

### PIE status

Plain Go PIE startup is now working under the threaded runtime.

What landed in `919e762`:

- `run-elf --fs host <relative-path>` canonicalizes `argv[0]` for relative ELF
  paths, fixing the external-static-pie path regression.
- `AddressSpace::load_elf` can load a `PT_INTERP` dynamic linker and set the
  initial PC to the interpreter entry.
- Threaded engines can read guest loader bytes through the dispatcher/rootfs
  path rather than assuming host paths.
- EL0 reads of `CNTFRQ_EL0` / `CNTVCT_EL0` are emulated, which the dynamic
  loader needs.
- Thread siblings are no longer misclassified as forked children, and
  process-wide exits propagate correctly through the threaded runtime.

Verified before commit:

```sh
cargo fmt --all -- --check
cargo test --release trap::thread_sibling_tests::decodes_el0_counter_register_traps -- --nocapture
cargo test --release --test address_space -- --nocapture
./scripts/build-signed.sh

CARRICK_EXPOSED_CPUS=10 timeout -s KILL 30 \
  target/release/carrick run-elf --raw --fs host \
  fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello

CARRICK_EXPOSED_CPUS=10 timeout -s KILL 60 \
  target/release/carrick run-elf --rootfs-layer /tmp/carrick-pie-ld.tar \
  --raw --fs memory /tmp/go-conformance/bin/go-hello-internal-pie
```

`/tmp/carrick-pie-ld.tar` is the scratch loader layer used during this bring-up;
it supplies `/lib/ld-linux-aarch64.so.1` for internal dynamic PIE tests. Treat it
as temp state unless/until we promote a reproducible loader/rootfs fixture.

### Current failing Go oracle

The focused runtime test still fails under high exposed CPU count:

```sh
CARRICK_EXPOSED_CPUS=10 timeout -s KILL 90 \
  target/release/carrick run-elf --raw --fs host /tmp/go-conformance/bin/runtime.test \
  -- -test.run '^TestUserArena$/^Alloc$/^largeScalar$' -test.count=1 -test.v
```

Failure shape:

- Go reports `arena_test.go:180: failed integrity check`.
- The value is `runtime_test.largeScalar`, a `[UserArenaChunkBytes + 1]byte`.
  Since it exceeds `userArenaChunkMaxAllocBytes`, Go routes the allocation to
  the heap, not to an arena chunk. This is useful: the data path is ordinary heap
  copy/equality, not a special arena mmap edge.
- The standalone repro in
  `fixtures/go-aarch64-hello/src/userarena_large/main.go` byte-checks the whole
  array and passes under carrick.
- An uncommitted diagnostic edit adds direct array equality (`*got != *value`).
  With `CARRICK_EXPOSED_CPUS=10`, equality intermittently fails while the
  byte-by-byte check immediately after still passes. Docker `linux/arm64` passes,
  and carrick P1/P2 pass.
- 20-run sample on the equality repro:
  - default P10: `array equality failed` in **12/20**
  - `GODEBUG=asyncpreemptoff=1` P10: **0/20**

This is not an mmap/userarena data-integrity failure. It is tied to Go async
preemption (`SIGURG`) interrupting the generated large-array equality path.

### Debug evidence so far

- `go tool objdump` shows `main.main` calls `runtime.memequal`.
- `runtime.memequal` uses SIMD registers (`V8`-`V11` in the hot path) and also
  relies on condition flags across compare/branch pairs.
- Go's `runtime.asyncPreempt.abi0` saves/restores `V0`-`V31`.
- `carrick trace --script scripts/dtrace/trace-go-signal.d` confirms SIGURG
  inject/restore and no guest faults, but tracing perturbs timing enough that
  the standalone repro often passes under trace. Use trace for signal shape, not
  for pass/fail rate.
- The existing `fp-sigurg` probe only clobbered `V0`-`V7,V16`-`V23`; an
  uncommitted diagnostic edit extends it through `V8`-`V15`. The extended probe
  still passes (`PROBE_D_OK ... preempts=...`), which argues against plain
  signal FPSIMD save/restore corruption.

Current best hypothesis: kick-path signal injection saves the wrong PSTATE in
the signal frame. In `src/trap.rs`, `inject_signal` always stores
`SPSR_EL1`. That is correct for syscall-boundary signal delivery, but on a
cross-thread `hv_vcpus_exit` / `CANCELED` kick the vCPU is already running EL0
guest code and the live state is `Reg::CPSR`. If SIGURG lands between a `CMP`
and a later branch in `runtime.memequal`, restoring stale NZCV flags from
`SPSR_EL1` can make equality return false even though the bytes are identical.

Next fix to try:

```rust
frame.saved_spsr = if interrupted_pc.is_some() {
    self.vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?
} else {
    self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?
};
```

Add a small helper/unit test for this policy, then re-run the equality repro
loop and the focused Go runtime test.

### Repro commands for the current blocker

Build the equality repro from the diagnostic source:

```sh
GOEXPERIMENT=arenas CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -buildmode=pie -o /tmp/go-conformance/bin/userarena-large-eq-pie \
  fixtures/go-aarch64-hello/src/userarena_large/main.go
```

Run a failure-rate loop:

```sh
fail=0
for i in $(seq 1 20); do
  pkill -9 -f '[c]arrick' || true
  out=$(CARRICK_EXPOSED_CPUS=10 timeout -s KILL 60 \
    target/release/carrick run-elf --rootfs-layer /tmp/carrick-pie-ld.tar \
    --raw --fs memory /tmp/go-conformance/bin/userarena-large-eq-pie 2>&1)
  if printf '%s\n' "$out" | rg -q 'array equality failed'; then
    fail=$((fail+1)); printf F
  else
    printf .
  fi
done
echo " fail=$fail/20"
```

Trace signal shape, not failure rate:

```sh
CARRICK_EXPOSED_CPUS=10 timeout -s KILL 80 \
  target/release/carrick trace --script scripts/dtrace/trace-go-signal.d \
  --trace-out /tmp/carrick-userarena-signal.trace -- \
  run-elf --rootfs-layer /tmp/carrick-pie-ld.tar --raw --fs memory \
  /tmp/go-conformance/bin/userarena-large-eq-pie
```

### Dirty diagnostic changes at this handoff

The worktree currently has two intentional, uncommitted diagnostic edits:

- `fixtures/go-aarch64-hello/src/userarena_large/main.go`: direct large-array
  equality check before the byte loop.
- `fixtures/mn-probes/src/bin/fp_sigurg.rs`: clobber `V0`-`V23` instead of
  skipping `V8`-`V15`.

Commit them as repro/probe hardening if they stay useful; otherwise revert only
those lines before the signal PSTATE fix.

## PRIOR LATEST (2026-05-24 PM): `os/exec` down to raw-rootfs environment delta

Current `scripts/go-conformance.sh os/exec` result:

- Docker PASS: **36**
- Carrick PASS: **35**
- Carrick-only delta: **`TestString`** only.

`TestWaitid` is fixed. The root cause was a Darwin/Linux `waitid` state-selection
semantic mismatch: Darwin can report a SIGSTOPped child from
`waitid(P_PID, child, WEXITED|WNOWAIT)`, while Linux reports only states selected
by the caller's `W*` bits. Carrick now filters host `siginfo_t` states against
the guest waitid options before deciding whether the child is waitable. Trace
script: `scripts/dtrace/trace-waitid-stop.d`.

The remaining `TestString` item is not a wait/signal/process bug: Go skips it in
Carrick because `exec.LookPath("echo")` cannot find an executable in the raw
seeded rootfs. Do not satisfy this by planting a fake Mach-O or empty `echo`;
use a real Linux rootfs/tooling path, or keep it classified as a raw-runner
environment delta.

## PRIOR LATEST (2026-05-24 PM): Go `os/exec` multithreaded fork+exec

After the high-P deadlock fix (below), the next bring-up target was Go's
`os/exec` (clone(`CLONE_VM|CLONE_VFORK|CLONE_PIDFD`) → execve → wait) under the
per-thread-vCPU runtime. Commits: `feat(fork): multithreaded fork…`,
`feat(fork): CLONE_PIDFD write + real waitid…`,
`fix(fork): interruptible waitid + phantom-thread cleanup…`,
`fix(fork): serialize vCPU topology + destroy vCPUs on thread death…` (`7bcad9e`).

### GREEN
- `os/exec` **TestEcho** + several others PASS end-to-end on a multithreaded
  guest. Single-threaded fork+exec already worked; the new work made the
  multithreaded fork path function.
- Built on:
  - **`waitid(2)`** implemented for real (was an `ECHILD` stub). Go's
    `blockUntilWaitable` uses **`waitid(P_PID)`** (NOT P_PIDFD). A raw blocking
    `libc::waitid` is NOT interruptible by the fork stop-the-world quiesce
    (`hv_vcpus_exit` + the wake-pipe poke don't reach a thread sitting in a host
    syscall) — that was the EAGAIN straggler. Fix: probe `WNOHANG` first, then
    PARK on the child's exit via the per-thread kqueue —
    `DispatchOutcome::WaitOnProcExit`(P_PID → `EVFILT_PROC`/`NOTE_EXIT`) or
    `WaitOnPollFds`(P_PIDFD → its backing kqueue fd). Both wake on a signal OR a
    quiesce; the runtime re-dispatches the waitid to reap.
  - **`CLONE_PIDFD`**: `DispatchOutcome::Fork{pidfd_out}` carries the pidfd-out
    pointer (legacy clone = arg2/parent_tid; clone3 = clone_args.pidfd); the
    parent installs a pidfd (EVFILT_PROC on the mirror host pid) and writes the
    fd.
  - Concurrent forkers **block** (park at the in-flight fork's barrier + retry)
    instead of returning EAGAIN — Go does not retry a failed clone.
  - Topology lock (`fork_quiesce::topology_lock`) serializes VM teardown/rebuild
    vs. sibling vCPU creation; the fork quiesce counts OTHER live vCPUs from the
    **kicker**, not `registry.live_count` (a thread with a tid but no vCPU yet
    must not be awaited); a thread destroys its own vCPU on EVERY death path
    (`Drop` is a no-op).

### STILL BROKEN
- **`TestConcurrentExec`** (heavy concurrent fork+exec) intermittently
  **HV_BUSY (0xfae94002)** at the forker's `hv_vm_destroy`. Root: a stray LIVE
  vCPU at teardown. `HvfTrapEngine::drop` is a deliberate no-op, so any thread
  that dies without destroying its own vCPU leaks it; a later fork's
  `hv_vm_destroy` trips on it. Diagnosed via the new **`carrick trace`** probe
  `fork__quiesce` (phase 2 = hv_vm_destroy rc + a `VCPU_LIVE` count; phase 3 =
  release rc): confirmed `b=1..3` live vCPUs when busy, `0` when OK. The obvious
  leak paths are plugged; one source still slips through under load.

### Deferred / follow-up (priority order)
1. **Close the remaining vCPU leak** → `TestConcurrentExec` green.
2. **vfork-exec helper thread** (chosen redesign): a vCPU-less carrick thread
   does `fork()`+`execve()` for the `CLONE_VFORK|CLONE_VM`+exec case (Go
   os/exec, posix_spawn) — child execs immediately and never resumes guest
   exec, so it needs NO VM teardown / quiesce / sibling rebuild. Keep
   stop-the-world only for a true full `fork()`. (HVF binds each vCPU to its
   creating thread — only that thread may destroy/run it — so a helper thread
   can coordinate the VM but cannot destroy guest threads' vCPUs.)
3. **Consolidate the 3 duplicated run-loops** (`run_vcpu_until_exit` = prod;
   `run_syscall_loop`/`run_split_loop` = test-only) into ONE shared
   `DispatchOutcome` handler. Every new outcome variant must currently be added
   in 3 places; missing the threaded one routes to `unreachable!()` and KILLS a
   vCPU thread (this happened with `WaitOnProcExit`). Do AFTER concurrency green.
4. **os/exec gate to ~36/36** vs Docker (`scripts/go-conformance.sh os/exec`);
   blocked on #1.
5. **Loader (SP3):** run plain `go build` output, not just the
   external-static-pie test recipe.
6. **Breadth (SP4):** the rest of the conformance package set (runtime / net /
   the broader list in `scripts/go-conformance-packages.txt`).
7. **`waitid(P_ALL/P_PGID)` + blocking `wait4`** still use an uninterruptible
   `libc` block — only `P_PID`/`P_PIDFD` got the kqueue-park treatment. Latent.
8. **Residual ~1% GOMAXPROCS=10 tail** (the rare `index out of range`, below) —
   extend `mn-probes` with a SIMD+SIGURG probe.
9. Decide whether `VCPU_LIVE` / `fork__quiesce` stay as permanent probes or are
   dropped once the leak is closed.

### Specs / plans (superpowers) — the authoritative design + task docs
Built with the brainstorming → writing-plans flow; read these before resuming:
- **`docs/superpowers/specs/2026-05-24-go-full-conformance-design.md`** — the
  overall "full conformance, run standard `go build` output" north star. Covers
  deferred items #4–#6 (gate, loader/SP3, breadth/SP4).
- **`docs/superpowers/specs/2026-05-24-multithreaded-fork-design.md`** — the
  stop-the-world quiesce + hybrid design this session implemented. The
  vfork-exec helper-thread idea (#2) is the planned EVOLUTION of this design and
  is NOT yet written up — needs its own brainstorm → spec → plan before coding.
- **`docs/superpowers/plans/2026-05-24-multithreaded-fork.md`** — task plan for
  the quiesce/vCPU release-rebuild work. Tasks 1–3 done; the CLONE_PIDFD/waitid
  pieces landed; the concurrent-fork hardening (#1) overran the plan and is
  where TestConcurrentExec still fails.
- **`docs/superpowers/plans/2026-05-24-pidfd-kqueue.md`** — pidfd via host
  kqueue/EVFILT_PROC (DONE; pidfd_open + CLONE_PIDFD + waitid(P_PIDFD)).
- **`docs/superpowers/plans/2026-05-24-go-conformance-gate.md`** — the
  differential `scripts/go-conformance.sh` harness (DONE; it's how we measure
  #4).
- **`docs/superpowers/go-conformance-baseline.md`** — recorded baseline; update
  it as packages go green.
- Earlier follow-ups: `docs/superpowers/specs/2026-05-23-go-bringup-followups-design.md`.

When picking up #2 (vfork-exec helper) or #3 (loop consolidation), start a new
spec/plan under `docs/superpowers/` rather than extending the multithreaded-fork
plan — they are distinct subsystems.

---

## Headline: the high-P deadlock is root-caused and fixed

The open blocker from the previous handoff — `CARRICK_EXPOSED_CPUS=10` Go c50
deadlocking/timing out (6/10 clean) — is **fixed**. Root cause and fix below.

- Go c50 `CARRICK_EXPOSED_CPUS=10` (`-benchmark -c 50 -n 300`):
  **6/10 → ~199/201 (~99%)**, with **zero deadlocks/timeouts** (was 2 deadline
  panics + 2 timeouts per 10).
- Default Go c50 (Darwin perf-cluster CPU count): still clean (6/6 re-checked).
- New differential probe `fixtures/mn-probes/futex-sigurg` (Mutex/Condvar ring +
  Go-style SIGURG storm): was a **deterministic** deadlock under carrick at any
  CPU count, now **12/12** (and passes on the Docker arm64 oracle, as it always
  did — that's what made it a clean differential).

## Root cause: a cross-thread kick can capture an EL1 (carrick) PC

Go async-preempts a running M by sending `SIGURG` via `tgkill`. carrick delivers
a signal to an in-guest vCPU by kicking it out of `hv_vcpu_run` with
`hv_vcpus_exit` (a `CANCELED` exit), then injecting a signal frame at the
interrupted PC.

A guest `svc` traps to carrick's **EL1 vector page** (`VBAR_EL1 =
LINUX_EL1_VECTORS_BASE = 0x20000`; the sync-from-EL0 entry is at `+0x400`, i.e.
`0x20404`). There is a small window between that vector entry and the `HVC` that
exits to the host. **If the kick lands in that window**, the `CANCELED` exit
happens while the vCPU is at **EL1**, and the run loop read `current_pc()`
(`0x20404`, an EL1 trampoline address) and injected a signal frame there **as if
it were a guest EL0 PC** — overwriting the in-flight syscall/exception and
wedging the thread.

Under a SIGURG storm (high `GOMAXPROCS`) this is frequent: **~23k EL1-window
kicks per Go c50 run**. That is the `CARRICK_EXPOSED_CPUS=10`
deadlock/deadline-panic class. `GODEBUG=asyncpreemptoff=1` "fixed" it only by
removing all SIGURG (hence all kicks).

### The fix (commit `fix(hvf): resume cross-thread kicks…`)

`HvfTrapEngine::run_until_syscall` now checks `PSTATE.M` on a `CANCELED` exit via
`ExecLevel::from_pstate(cpsr)`. If the vCPU is at EL1 (in the trampoline), it
**resumes** the vCPU instead of reporting a delivery point, so the trampoline
completes its HVC and the real syscall is serviced; the pending signal is
delivered at the next clean EL0 boundary. Full-speed counter (Go c50):
`el1_kick_resumed≈23000`, `inject_at_el1=0`.

## Two traps that cost hours (read before re-debugging)

1. **`carrick trace` perturbs this timing race away.** Running under the
   in-process dtrace consumer slows the guest ~60× (≈14k vs ≈888k SIGURGs in the
   same wall-clock), so the EL1-window race basically stops happening and the
   bug **passes under trace**. Observe at full speed with cheap in-process
   atomics instead: `CARRICK_KICK_STATS=1` prints
   `el1_kick_resumed / kick_path_inject / inject_at_el1` at exit; the
   `kick-stats` USDT probe carries the same totals (one fire per exit) and
   `kick-in-kernel` fires per EL1-window kick. `CARRICK_TRACE_REGS=1` dumps guest
   regs per trap (full speed) — that's how the hot futex PC/syscalls were found.
2. **`0x20404` is NOT a wild/corrupt PC.** It's the normal EL1 vector entry that
   **every** syscall passes through (`CARRICK_TRACE_REGS` shows `pc=0x20404
   ec=0x15` on every SVC; `ELR_EL1` holds the real EL0 return). An earlier
   reading of `0x20404` as a "wild guest jump" was wrong — it's carrick (EL1)
   space. (User: "is that pc in carrick? … it does seem like the pc is the el
   space.")

## The differential method that found it

Instead of debugging the whole Go runtime, build small probes that each stress
ONE primitive at high parallelism, and run each both under carrick (exposed 4 vs
10) and on the Docker `linux/arm64` oracle (same static-musl binary). Built in a
`rust:alpine` arm64 container; sources in `fixtures/mn-probes/`:

- `futex-only`: Condvar ring, no signals (control) — always passed.
- `futex-sigurg`: same ring + a 50µs `tgkill` SIGURG storm — **isolated the bug
  to signal delivery corrupting the futex path**. Deterministic, fast (≤30s),
  2 threads enough.
- `epoll-sigurg`: epoll loopback + SIGURG storm.

Build: `docker run --rm --platform linux/arm64 -v "$PWD/fixtures/mn-probes":/work
-w /work rust:alpine sh -c 'cargo build --release'`.
Oracle: run the same binary in an `alpine` arm64 container.

## Other changes this continuation

- **FP/SIMD across signals** (`feat(abi)` + the hvf fix commit): carrick now
  saves/restores guest V0–V31 + FPSR/FPCR in the Linux `fpsimd_context`
  (`sigcontext.__reserved`) across signal handlers, like the arm64 kernel. It
  was NOT the deadlock, but it is a real correctness gap (aarch64 memcpy/memset
  use SIMD). Measured overhead on Go c50 is within run-to-run noise. Toggle with
  `CARRICK_NO_FPSIMD` for differential runs.
- **Systematic EL0/EL1 invariant** (`refactor(hvf)`): `ExecLevel{Guest,Kernel}`
  + `memory::is_carrick_el1_vector_va()`, with a `debug_assert`/release-counter
  tripwire in `inject_signal` so a kick-path resume PC in carrick's EL1 vector
  range trips loudly. Encodes the carrick-vs-guest boundary as a checked
  contract. Tests: ExecLevel classification, the VA predicate, fpsimd layout.

## Open: residual ~1% long tail at forced GOMAXPROCS=10

Across ~200 `CARRICK_EXPOSED_CPUS=10` Go c50 runs after the fix, two failures:
one `context deadline exceeded` (client 5s timeout) and one
`fatal error: index out of range`.

- The **deadline** miss is the more common residual and is consistent with
  oversubscription tail latency: forcing `GOMAXPROCS=10` onto a 4-perf-core
  machine (6 efficiency cores are much slower). `asyncpreemptoff=1` did NOT
  change the residual rate (30/30 both), i.e. it's not a remaining signal bug.
  The validated durable default (expose `hw.perflevel0.logicalcpu` = 4) is clean.
- The **index out of range** is a rare corruption (≈1 in many hundreds) — next
  to investigate. Likely a residual async-preemption edge (an EL0 inject at an
  unusual point); FP-on vs FP-off was inconclusive at this rarity. A probe that
  combines SIMD-heavy work + a SIGURG storm may reproduce it deterministically
  (extend `mn-probes`).

Next best path: extend the `mn-probes` family with a SIMD+signal probe to try to
turn the rare `index out of range` into a deterministic repro, then trace via
`CARRICK_TRACE_REGS` / `CARRICK_KICK_STATS` (NOT the dtrace consumer — it hides
the race).

## Commands

Build and sign:

```sh
./scripts/build-signed.sh
```

Differential probe (the deterministic repro for the fixed bug):

```sh
B="$PWD/fixtures/mn-probes/target/release"
CARRICK_KICK_STATS=1 CARRICK_EXPOSED_CPUS=10 \
  target/release/carrick run-elf --raw --fs host "$B/futex-sigurg" -- 2 50000
# expect: PROBE_B_OK …  + [kick_stats] el1_kick_resumed=… inject_at_el1=0
```

Go high-P oracle:

```sh
artifact="$PWD/fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello"
CARRICK_EXPOSED_CPUS=10 \
  target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300
```

Full-speed guest-reg trace (when the dtrace consumer is too perturbing):

```sh
CARRICK_TRACE_REGS=1 CARRICK_EXPOSED_CPUS=10 \
  target/release/carrick run-elf --raw --fs host "$artifact" -- -benchmark -c 50 -n 300 2>&1 \
  | grep TRAP | grep -oE 'ec=0x[0-9a-f]+\) pc=0x[0-9a-f]+ .* x8=[0-9-]+' | sort | uniq -c | sort -rn
```
