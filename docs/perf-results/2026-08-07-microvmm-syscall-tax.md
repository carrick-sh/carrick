# The micro-vmm syscall tax, measured — Route A's decisive experiment

**Date:** 2026-08-07
**Question:** the ET_EXEC options paper
([`../superpowers/specs/2026-08-07-et-exec-direct-execution-options.md`](../superpowers/specs/2026-08-07-et-exec-direct-execution-options.md) §7)
gates Route A — the HVF stage-1 micro-vmm, the only route that removes both
translation and bias for the arm64 canonical (`go build`) lane — on one
number: does `(svc-exit + IPC hand-off) × guest-syscall-count` exceed the
translation+bias CPU the route would remove?
**Answer up front:** **no — the syscall tax is small. Route A is VIABLE on
this term.** The measured floor is **5.9 µs per guest syscall** (0.68 µs
`hv_vcpu_run` round trip + 5.2 µs cross-process `__ulock` hand-off), i.e.
**≈0.52 s on the cold build's 88,462 guest syscalls**, against **1.4–5.4
CPU-s** of removable translation-side cost. The sign flips only at
**≥15.8 µs/syscall vs the most conservative removal band (≥44.7 µs vs the
central band)** — 2.7x (7.6x) above the measured floor. A second, unplanned
result: **host-built stage-1 page tables add no measurable per-exit cost**
(MMU-off and stage-1 arms are byte-identical at p50 625 ns), and the probe
re-proves host-built stage-1 tables drive an EL0 guest.
**Scope honesty, also up front:** viable ≠ transformative. Even a full
translation+bias unlock is worth at most ~5.4 CPU-s of 19.795 (~1.4x CPU)
on this lane — the ablation ladder's rung-5 sizing note ("a full unlock
lands near the PIE tier-D residual, 8.0x") stands. And this experiment
prices the **syscall path only**; the per-process costs (stage-1 PT
construction per fork/exec, ASID/TLB maintenance, shared-VM contention) are
Route A's remaining unmeasured terms.

---

## 1. What was measured

Probe: [`crates/carrick-vmm-hvf/src/bin/hvf_svc_tax_probe.rs`](../../crates/carrick-vmm-hvf/src/bin/hvf_svc_tax_probe.rs)
(committed as a durable probe, precedent `hvf_fork_probe.rs`). It reuses the
**production** guest plumbing rather than a synthetic mock:

- guest enters at carrick's EL0 trampoline (`el0_trampoline_bytes`), drops
  to EL0 at a low VA (`0x400000` — Go's ET_EXEC class), loops `svc #0`;
- the production EL1 vector page (`el1_vectors_bytes`) forwards each `svc`
  via `hvc #2`, exactly the trap path in `carrick-vmm-hvf/src/trap.rs`;
- the stage-1 arm maps `stage1_identity_page_tables()` and programs
  TTBR0/TTBR1/TCR/MAIR/SCTLR from `carrick_mem::arch_sysregs` — the
  micro-vmm's actual address model (§7 step 2 of the options paper);
- the IPC arm forks a real child process and ping-pongs over a `MAP_SHARED`
  page using carrick's production SHARED futex primitive
  (`carrick_host::ulock::wait`/`wake`, `os_sync_wait_on_address`) — the
  mailbox hand-off a shared-VM design pays per syscall, both directions.

One timed `hv_vcpu_run` brackets exactly one complete guest-syscall cycle
(`eret` → EL0 → `svc` → EL1 vector → `hvc #2` → exit → host loop). The
probe fails closed: any exit whose syndrome is not EC=0x16 (HVC64) aborts
with the full syndrome, and the unexpected-exit case never produces an
empty summary.

## 2. Provenance

- Host: Mac16,12 (Apple M4, 4P+6E), macOS 27.0 (26A5388g), uptime 12 d.
  1-minute load 1.57–1.71 at the recorded probe runs (an earlier identical
  round at load 3.2–3.5 gave the same distributions). No Docker process
  running at any point; no guest and probe ever concurrent.
- Probe binary SHA-256 (signed with the hypervisor entitlement):
  `611c2e8bf2c0a952e3839bfdf68e5c47eda226a2a7b91e9435532e008f0e577d`.
- **Entitlement control, settled first** (the options paper §8 loose end
  about unsigned probes): a byte-identical copy of the probe re-signed
  plain ad-hoc **without** the entitlement fails `hv_vm_create` with
  `HV_DENIED(0xfae94007)` and exits 2; the binary signed with
  `scripts/entitlements.plist` (`com.apple.security.hypervisor`) succeeds
  on every HVF call. An unentitled probe's HVF failure is therefore
  indistinguishable from a real denial — Rule 0 applies to probes, and this
  probe's negative-control line prints the warning explicitly.
- Raw distributions: `target/perf/microvmm-tax/svc-tax-run{1,2,3}.jsonl`
  (3 independent process runs × 5 batches × 20,000 exits per svc arm;
  × 10,000 round trips per IPC batch; 1,000-iteration warmups excluded).
- Working tree during the runs: HEAD `41d3e2f0` plus **another agent's
  uncommitted edits** (`AGENTS.md`, `crates/carrick-dsr/src/identity_memory.rs`,
  `crates/carrick-runtime/src/dtrace_consumer.rs`, assorted docs). None of
  those files is in `carrick-vmm-hvf`'s dependency closure (checked:
  abi/aarch64/hal/guest-mem/host/kernel/mem/observability/signal-core/
  timer-core/thread/host-bsd), so the probe binary is unaffected by them.
- Syscall-count verification binary: the ablation ladder's preserved
  default-features binary `target/perf/ablation/carrick-default-81d915b0`
  (SHA-256 `2a5a69062049076701fb765d868f9a52680851108b12f6aabf2e05ce5d849714`).
  Every commit in `81d915b0..HEAD` is docs/tests/feature-gated-ablation
  only, so its default-lane runtime behaviour is HEAD's. Run id
  `microvmmtax81840`, reaped via `scripts/sudo/kill.sh` (0 leftovers),
  guest output `BUILD_OK`, `WORKLOAD_NS=8,088 ms` (consistent with the
  official 8,175 ms), stderr captured to
  `target/perf/microvmm-tax/count-verify.{out,err}`.

## 3. Measured distributions

### 3a. `hv_vcpu_run` round trip per EL0 `svc` (ns; 15 batches over 3 runs)

| arm | p50 (min–max of batch p50s) | p95 med | p99 med | mean med | aggregate* |
|---|---|---:|---:|---:|---:|
| floor (MMU off) | **625–666** | 667 | 708 | 652 | 642–644 |
| **stage-1 (host-built identity tables)** | **625–666** | 667 | 667 | 650 | 635–645 |
| stage-1 + dispatch regs (7 get + 1 set) | **667** (667–708) | 709 | 709 | 680 | 667–675 |

\* whole-batch wall ÷ iterations, bounding per-iteration timer overhead at
≲10 ns. Worst single-iteration outliers 7.6–20.6 µs (scheduler preemption;
≤0.1% of samples).

Two results here:

1. **The exit round trip is ~0.65 µs**, not the multi-µs the native lane's
   design discussions assumed. Even with syscall-ABI register traffic it is
   **0.68 µs**.
2. **The stage-1 MMU arm is indistinguishable from MMU-off** — walking the
   host-built identity tables adds nothing measurable per exit, and the
   guest demonstrably executed at EL0 under `stage1_identity_page_tables`
   with `SCTLR_EL1.M=1` (the probe fails closed if the `svc` path breaks).
   That answers the options paper's second open question for free.

### 3b. Cross-process `__ulock` hand-off round trip (15 batches over 3 runs)

The distribution is **bimodal by batch**, and both modes are real
micro-vmm regimes:

| regime | batches | batch p50s | p99s |
|---|---:|---|---|
| parked path (peer blocked in `os_sync_wait`) | 10/15 | **3.5–5.3 µs** | 7.5–8.4 µs |
| running path (peer still on-CPU, no park) | 5/15 | 0.46–0.67 µs | ≤7 µs |

p999 10.0–22.5 µs, single-iteration max 13–49 µs (E-core wake +
preemption tails; ≤0.1% weight).
A parked servicing thread is the conservative steady state; a busy
servicing thread that polls its mailbox before parking gets the 0.5 µs
mode. **The tax arithmetic below uses the parked path.**

## 4. The syscall count, re-verified at HEAD

The Move-3 §0 figure (88,174 guest syscalls per cold build, from the
`attr36` C1OFF counters) re-verifies at HEAD behaviour as **88,462**
(+0.33%): sum of `exit_syscall` over all 460 `NATIVEPERF1` thread records
(460/460 `complete=1`) from one cold `go build` under
`CARRICK_DSR_PROFILE=1`. Gateway exits in the same run: **1,838,685**
(C1OFF: 1,846,656) — the micro-vmm deletes all of these except the 88,462
real syscalls, because there is no JIT to exit from.

## 5. The arithmetic

### Tax side (X): what Route A adds per cold build

| estimate | per-syscall | × 88,462 |
|---|---:|---:|
| measured floor (exit-with-regs 0.68 µs + parked IPC 5.2 µs) | 5.9 µs | **0.52 s** |
| p99 build (0.7 µs + 8.3 µs) | 9.0 µs | 0.80 s |
| realistic estimate (3× floor: mailbox copies, guest-state hygiene, cache pollution of the vCPU pool, scheduling under real load) | ~18 µs | **~1.6 s** |

These are wall-serialized costs on the syscall path; as CPU they are
bounded above by ~2× (both processes active through the hand-off
transitions) and realistically ~1×. The native lane's current in-process
dispatch entry (~0.3 µs) nets off the exit term almost exactly once.

### Removal side (Y): what Route A deletes, at the official 19.795 CPU-s

| band | CPU-s | source and transfer assumption |
|---|---:|---|
| conservative — translation machinery alone | **1.394** | W1OFF share 7.0440% ([36x attribution](2026-08-06-live-arena-36x-attribution.md)); transfers with no assumptions |
| central — + emitted-code inflation | **≈3.95** | + 52.4% (shape-census DSR-overhead floor, an **instruction-share** applied to a CPU share — CPI assumed ≈1:1) of translated-guest 24.6405% = 4.878 CPU-s |
| upper — + gateway round-trip host bookkeeping | **≈5.4** | + ~1.43 CPU-s (1.84 M exits × ~0.7–0.85 µs untraced, bounded by the whole `other-carrick` category 7.2116%) |

**PIE-fixture transfer, stated explicitly:** the ablation ladder's 2.76x /
−54.2% CPU translation ceiling was measured on a compute-heavy PIE fixture
where translated execution dominates. On the build lane
translation+translated-guest is only **31.7% of CPU**, so Route A can never
be a 2.76x there — the bands above are the honest build-lane transfer, and
even the upper band is a **~1.37x CPU lever** (19.795 → ~14.4 CPU-s). The
bias term (rung 2's 13.6%, PIE per-access family) lives inside the emitted
code and is contained in the inflation band, not additive to it.

### Net

| | vs Y conservative (1.39) | vs Y central (3.95) | vs Y upper (5.4) |
|---|---:|---:|---:|
| X floor (0.52) | +0.87 s | +3.43 s | +4.9 s |
| X realistic (1.6) | −0.2 s (wash) | **+2.35 s** | +3.8 s |

## 6. Verdict

**A micro-vmm architecture would cost ≈0.52 s (measured floor; ≈1.6 s
realistic) in syscall exits + IPC on the cold build, against ≈1.4–5.4 CPU-s
of translation+bias cost removed — the route is VIABLE on the syscall-tax
term.** The verdict rests on the realistic estimate against the central
removal band (1.6 vs 3.95, a 2.5x margin), not on the floor: a bare
`svc`-exit loop is a floor, and the 3× multiple for a real dispatch is a
judgment, not a measurement. The floor alone clears even the most
conservative band (0.52 vs 1.39).

**Sensitivity — where the sign flips:** the tax equals the removal at
**15.8 µs/syscall** (conservative band), **44.7 µs** (central),
**60.8 µs** (upper). The measured floor is 5.9 µs and the realistic
estimate 18 µs; the route dies on this term only if a real per-syscall
round trip costs ≥2.7x the measured floor against the most pessimistic
removal reading, or ≥7.6x against the central one. The tail does not
change this: even pricing every syscall at the parked path's p99 (9.1 µs)
leaves 0.80 s.

**What the verdict does NOT say:** Route A is now worth a design spike,
not a green light. The syscall tax was the named kill-condition and it did
not fire; the remaining unknowns are per-process (fork/exec) costs and the
shared-VM machinery, and the total prize on the canonical lane is bounded
at ~1.4x CPU — real, the largest single lever the lane has, but not the
2.76x the PIE ladder number suggests if transferred naively, and not a
route to the 2x product bar by itself (rung 5's sizing note stands).

## 7. What could not be measured (and what would measure it)

- **The combined pipeline** — exit in a vCPU-server process + hand-off to a
  *different* owning process + resume. The two terms were measured
  separately in one process tree and summed; a two-process harness with a
  real shared mailbox would price the sum directly (expected ≈ the sum;
  the hand-off memory is shared either way).
- **Per-process costs**: stage-1 page-table construction per fork/exec,
  ASID assignment and TLB maintenance (`hvc #1` exits per mprotect/munmap),
  COW of PT trees at fork, and the 127-VM-ceiling dodge actually working
  with N processes on one VM. These are Route A's next gate; the build is
  process-bound (61 execs), so they can be sized as `exec-cost × 61` the
  same way this experiment sized `syscall-cost × 88,462`.
- **Fault traffic under a shared VM.** Expected unchanged — HVF demand-
  zeroes touched pages of `hv_vm_map`ed regions kernel-side without a VM
  exit (the VMM lane's mmap arena relies on exactly this,
  `carrick-mem/src/memory.rs` LINUX_MMAP comment) — but not measured here.
- **Multi-vCPU contention** on one VM (per-VM HVF locks): single vCPU only.
- **Scheduling under real build load**: the probe ran at ambient load
  1.6–3.5 on a 4P+6E part with nothing pinned (macOS offers no affinity);
  the parked-path p999/max (10–22.5 / 13–49 µs) shows what an E-core wake
  + preemption costs when it happens, and a loaded build will sample that
  tail more often than 0.1%.
