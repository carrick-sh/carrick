# Handoff — Go runtime bring-up on carrick (2026-05-24, continued)

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
