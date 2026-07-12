# Native DSR correctness campaign — 2026-07-11

This is the current evidence ledger for the opt-in Darwin-native AArch64
dynamic syscall rewriter. Linux is the semantic oracle. The legacy native
executor is neither a control lane nor part of this campaign.

## Provenance and supported surface

- Host: `Mac16,12`, Darwin arm64, macOS 27.0.
- Guest: Linux AArch64, `native16k` page profile.
- Mode: `--exec-backend native --native-page-profile native16k
  --native-code-mode dsr`.
- Full LTP artifact:
  `target/conformance/native-dsr-ltp-b5178a99.jsonl` at documentation HEAD
  `b5178a99`, using runtime `cba2eb9c`.
- Focused post-campaign fixes: `d5fd9e00` rejects host PCs during phase-zero
  kicks; `10bebc42` removes the last ordinary indirect-target transit through
  physical `x18`; `cba2eb9c` validates target generations in target blocks.
- Current signed binary SHA-256 after those runtime fixes:
  `d7df4fa70656edc449afea7656b8c5e1e9f092797db587a3b40d67715514de86`.

This is a current-runtime full run. Docker supplied 1,492 cached oracle rows in
a separate phase; no Carrick and Docker guests overlapped.

## Strict LTP result

The selected corpus contains 1,492 rows. The fresh DSR/Linux differential is:

| Classification | Rows |
| --- | ---: |
| match | 1,331 |
| diff | 58 |
| new | 12 |
| regression | 90 |
| timeout | 1 |
| gating regressions plus timeout | 91 |
| no-assertion rows on both sides | 227 |

Carrick produced 1,129 successful, 359 failed, three empty, and one missing
result. These are differential harness classifications, not a claim that DSR
implements 1,331 Linux syscalls or that all matching rows pass on Linux.

The run contains no DSR cache-PC or cache-policy exit; the earlier PC-zero and
host-PC kick failures are absent. Five typed DSR instruction-read errors target
addresses outside guest memory. Three are differential regressions
(`ltp-profil01`, `ltp-timer_settime01`, and `ltp-timer_settime03`); two occur in
rows whose overall result matches Linux (`ltp-epoll-ltp` and
`ltp-perf_event_open02`). They are explicit signal/control-flow limitations,
not crashes or silent execution fallbacks, and remain narrowing work.

`CLONE_PARENT` remains a typed runtime limitation. The other LTP regressions
are syscall-emulation and process-model work until minimized evidence shows a
DSR mechanism failure. They are not excused, but the full count alone cannot
attribute them to translation.

## Static, dynamic, JIT, and process proof points

- Static musl: 376/376 authoritative probes byte-identical with Docker; see
  `docs/native-dsr-static-campaign.md`.
- Dynamic glibc: `/bin/true` exits zero under DSR.
- Rust static PIE: the trap-floor corpus runs; `perf_fork_exec` completes
  200/200 fork+exec iterations after the current x17-only indirect-target fix.
- Rust dynamic PIE: the glibc-linked trap-floor probe runs under DSR.
- Go PIE: the minimized PIE fixture prints `go-pie-ok` and exits zero.
- Go non-PIE: rejected because its `0x10000..0x594000` load range conflicts
  with Darwin's Mach-O low-address reservation. The current proof obligation is
  Go static/PIE, not preserving non-PIE low mappings.
- Node/V8: the direct generated-code fixture passes 12/12 after the current
  x17-only fix (and 37/37 before it). The official image wrapper still aborts
  in its `timeout` fork/exec wrapper; that wrapper topology is a process-model
  limitation, while the direct fixture is the JIT/code-generation proof.
- CPython threads: 21/21 matches Linux, taking 20.983 s versus 1.457 s.
- CPython multiprocessing/fork: times out at 300.224 s; Linux completes 317/317
  in 55.609 s. This remains an unclosed fork/process-performance gate.

## Architecture result

The current design reserves physical `x28` for `DsrContext`, virtualizes guest
`x18` and `x28`, and uses physical `x17` for internal entries and edges. No
ordinary translated target now transits physical `x18`. Original executable
pages are non-executable in DSR mode, and generation, publication, fork, exec,
kick, and stale-code oracle tests pass.

The opt-in profile identified a false-miss mechanism: the indirect hit path
compared a cached target page generation with the current source block's
generation. Removing that cross-domain comparison is safe because every target
block begins with its own atomic stale-generation guard. It reduced V8 gateway
entries from 3,232,605 to 1,036,636 (67.9%), indirect resolver exits from
2,615,150 to 418,019 (84.0%), and p50 wall time from 8.61 s to 7.73 s (10.2%).
Translations remained flat near 123,800, confirming that avoiding false Rust
round trips—not faster translation—created the win.

A separate experiment mixed high address bits and quadrupled the direct-mapped
target table. It reduced resolver exits by only 8.4% and moved p50 from 8.61 s
to 8.54 s, within noise, so it was discarded. More elaborate target caches,
lock-free publication, and reclamation remain unjustified without a stronger
profile. Fork/exec lifecycle attribution is still separate because its 60.7x
Linux gap is not explained by V8. Exact counters are in
`docs/perf-results/native-dsr-profile.jsonl`.

Published p50 DSR/Linux latency ratios are 4.336 for the syscall floor, 60.665
for Rust static-PIE fork+exec, 1.020 for TCP round-trip, 5.168 for metadata, and
38.65 for the post-fix direct Node/V8 generated-code process. The V8 wall measurement
includes Carrick and image startup on both sides; it is a branch/JIT workload
distribution, not a per-branch cost. Exact samples and caveats are in
`docs/perf-results/native-dsr.jsonl`.

## Current decision

DSR remains an opt-in experiment: the default-mode gate is **NO-GO**. It has
crossed the important mechanism thresholds—static parity, dynamic PIE
execution, direct V8 generated code, Go PIE, and correct Rust static-PIE
fork+exec—but it has not crossed the workload or performance threshold. The 91
gating LTP rows, three DSR control-flow regressions, official Node wrapper
failure, CPython multiprocessing timeout, and 60.7x fork+exec latency gap are
specific blockers. The next proof points are narrowing the three DSR target
errors, fork-heavy CPython completion, and fork lifecycle attribution.

The final workspace gate, `just ci`, passes. One first-attempt failure in the
unrelated epoll edge-trigger host test passed five immediate focused reruns; a
complete second `just ci` then passed all formatting, lint, dependency, matrix,
build, documentation, host-test, and integration-test stages.
