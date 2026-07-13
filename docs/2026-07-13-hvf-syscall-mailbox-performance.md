# HVF syscall mailbox performance decision

**Date:** 2026-07-13  
**Target:** macOS 27.0, Apple Silicon (`Mac16,12`), HVF/AArch64  
**Verdict:** **reject as the production default; retain as an internal opt-in comparator**

## Decision

The shared mailbox removes the intended Hypervisor.framework register traffic,
but it did not clear the frozen boundary-promotion threshold. The authoritative
trap-floor comparison was exactly `1.000` with a seeded 95% interval of
`[1.000, 1.000]`; promotion required an estimate at most `0.90` and an upper
bound below `1.00`.

The mailbox does improve several syscall-heavy end-to-end cases, most notably
`stdio_burst` by about 9.5%, but that is not a universal VMM speedup and does
not justify making the more complex transport the default under the approved
decision rule. `--exec-backend vmm` therefore defaults to the legacy register
transport. `CARRICK_HVF_SYSCALL_TRANSPORT=mailbox` remains available as a
private diagnostic/experimental selector; it is not public container policy.

## Provenance and method

Raw evidence: [`perf-results/2026-07-13-hvf-syscall-mailbox.jsonl`](perf-results/2026-07-13-hvf-syscall-mailbox.jsonl).

- Git commit sampled: `74df5fa309e40df84c4557263237bb7ac4653077`
- Signed Carrick SHA-256: `44dc4b76fe753421640f7902c8975965839545b38ef4453c7fdd2edda72821de`
- Host: `Mac16,12`, four performance cores, six efficiency cores, macOS 27.0
- Power: AC, battery at 100%
- Schedule: fixed `[legacy, mailbox, mailbox, legacy]`
- Warmup: ten ABBA blocks (twenty legs per transport)
- Measurement: thirty ABBA blocks (sixty samples per transport)
- Bootstrap: 10,000 seeded resamples, seed `5634344305327363654`
- Cooldown: zero seconds; ABBA order supplies the drift control
- Both legs used the same signed Carrick binary, explicit
  `--exec-backend vmm`, identical native-PIE probe bytes and arguments, and four
  exposed CPUs. Only `CARRICK_HVF_SYSCALL_TRANSPORT` changed.

The trap row uses the probe's 16-syscall batched trimmed mean. The historical
single-syscall p50 quantizes to one 24 MHz guest-counter tick (`0.042 us`) and
cannot distinguish these transports.

## Results

All ratios are mailbox divided by legacy; lower is better.

| Workload | Legacy p50 | Mailbox p50 | Ratio | Seeded 95% interval | Guard | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| trap floor | 0.027 us | 0.027 us | 1.0000 | [1.0000, 1.0000] | estimate <= 0.90 and upper < 1.00 | fail |
| stdio burst | 8011.750 us | 7253.500 us | 0.9055 | [0.8959, 0.9158] | upper < 1.00 | pass |
| writev burst | 20052.583 us | 19412.000 us | 0.9676 | [0.9590, 0.9754] | upper < 1.00 | pass |
| pipe handoff | 42.583 us | 41.375 us | 0.9716 | [0.9657, 0.9774] | upper <= 1.02 | pass |
| epoll pipe loop | 55.917 us | 54.916 us | 0.9825 | [0.9759, 0.9888] | upper <= 1.02 | pass |
| direct compute | 12196.208 us | 12163.708 us | 0.9972 | [0.9890, 1.0028] | upper <= 1.02 | pass |
| fork | 2187.625 us | 2197.375 us | 1.0036 | [0.9890, 1.0130] | upper <= 1.05 | pass |
| fork plus exec | 6614.625 us | 6590.083 us | 0.9967 | [0.9871, 1.0044] | upper <= 1.05 | pass |

The compute and process intervals include parity, as expected for work whose
cost is mostly outside the ordinary syscall frame transfer. No threshold was
moved after observing results.

## Register-call attribution

The maintained
[`scripts/dtrace/hvf-syscall-transport.d`](../scripts/dtrace/hvf-syscall-transport.d)
consumer ran against the same `perf_trap_floor` artifact in both explicit
modes. DTrace was used for attribution only, not timing.

| Transport | Captured decode boundaries | GPR reads | sysreg reads | Captured returns | GPR writes |
| --- | ---: | ---: | ---: | ---: | ---: |
| legacy | 72 | 648 | 288 | 71 | 71 |
| mailbox | 72 | 0 | 0 | 71 | 0 |

That is nine GPR reads and four sysreg reads per captured legacy decode, plus
one x0 write per ordinary legacy return. The mailbox ordinary path performs
none of those API operations. No DTrace error/drop record was emitted. The
one decode without an ordinary return is process termination, not a missing
mailbox completion.

## Correctness evidence

- The `mailboxregs` witness was red-first: intentionally removing x16/x17
  restoration produced `mismatch_mask=0x00018000`; the restored mailbox and
  legacy paths both report zero mismatch and preserved SP.
- The arm64-musl Docker differential lane reports
  `PASS arm64:musl:mailboxregs`.
- Signed focused probes passed for signal delivery/restart, clone, fork FP
  state and reclaim, threaded exec, permit churn, ptrace signal stops, and
  trace/exec stops.
- Mailbox lifecycle, malformed-state, rebind, reclaim, register-preservation,
  and explicit-invalid-selector tests pass.
- The full campaign contains no `invalid` row and its scoped cleanup reported
  zero remaining Carrick processes.
- Representative explicit-HVF language suites matched their cached native
  arm64 Docker oracles: Go runtime `52/52`, Node/V8 success, and CPython
  threading `193/193`. A post-run process audit found no remaining guest.
- `just ci` passed after the measured rejection was enacted, including format,
  clippy, typed-domain lint, dependency, matrix, build, docs, unit, and
  integration gates.

## Invalid preliminary campaign

One earlier full attempt was stopped and discarded after six provisional rows
when three stale `forkfpreclaim` Carrick processes (27-32 minutes old) were
found consuming HVF resources. They retained executable-form argv rather than
rewritten `carrick:<run-id>:` titles, so the original preflight missed them.
That attempt notably reported a false 4.8% epoll regression. After scoped reap
and a committed preflight fix, the complete clean campaign reported a 1.8%
epoll improvement. The invalid attempt was not used to replace individual
rows; the clean campaign reran every workload from the beginning.

## Limitations

- These results cover one Apple Silicon/macOS host and the HVF/AArch64 lane.
- The production USDT counters prove register-call removal, but a separate
  synthetic same-VM boundary helper was not built. Because the frozen
  production gate already rejects the candidate, that additional helper would
  not change the promotion decision.
- The trap metric is printed to nanosecond precision and the authoritative
  medians are equal at that resolution. A finer timer might resolve a smaller
  difference, but it cannot retroactively satisfy the frozen 10% requirement.
- Syscall-heavy burst gains do not imply similar gains for arbitrary programs;
  direct compute, fork, and fork/exec were statistically consistent with
  parity.
