# Atomic Exec-to-Terminal Handoff Performance Receipt

## Artifact identity

- Baseline source: `e3ac9b8db119df4b4a1a6c2358b18b952083728c`
  - Release test executable: `carrick_runtime-d84348e87b2d541e`
  - SHA-256: `bc56e20aa170c3474585ef515205eb57d9143699197d09875c8b865c5e2cc0b7`
  - Mach-O UUID: `5C5DD823-08D0-33DD-A395-CCAD27DBF855`
- Candidate source: `4341c6b75c561d3d05a6854b38489ec3704c02f7`
  - Release test executable: `carrick_runtime-d84348e87b2d541e`
  - SHA-256: `6c5e946e64d0334a6606451d6e8fc870eebab9ff274d6be787c582bddf579f6a`
  - Mach-O UUID: `5D0E88AA-C936-3D84-82B8-064F0985C2B9`
- Runner corrections: `cf393239e238312d7f28b0a832e520797d7793eb` and
  `e9e3c0121` (the receipt runner used here).
- Host: Apple M4, macOS 27.0 arm64; Rust `1.96.0 (ac68faa20 2026-05-25)`;
  Python `3.14.6`.

The runner built each ref in one retained detached temporary worktree and used
the same identified executable for that ref's two arms. The temporary paths
were removed after the receipt; the recorded SHA-256 and UUIDs bind it.

## Method

```text
python3 scripts/perf/atomic_exec_terminal_handoff_abba.py \
  --baseline e3ac9b8db119df4b4a1a6c2358b18b952083728c \
  --candidate 4341c6b75c561d3d05a6854b38489ec3704c02f7 \
  --iterations 100000 --warmups 5 --samples 30 \
  --output docs/perf-results/2026-09-01-atomic-exec-terminal-handoff.json
```

The runner executed the release reducer
`vcpu_loop::tests::clone_admission_terminal_claim_cost_receipt --ignored
--nocapture --exact` in exact ABBA order A1, B1, B2, A2. Each arm ran
`cargo test --release -p carrick-runtime --lib --no-run --message-format=json`,
with quiet-host checks before build, before reducer, and after the arm, plus a
continuous census of build and reducer children. Before/after arm power state
was AC power, low-power mode `0`, with no thermal, performance, or CPU-power
warning.

## Correctness observations

The receipt records 240 raw rows: 60 per arm, split evenly into 30
`generic_exit_claim` and 30 `exec_error_to_terminal` samples. Every sample
contains 100,000 transitions; each operation therefore has 120 rows across
the receipt and 60 per ref, and each ref has 120 rows. The runner accepted every exact row schema, sample
index, finite derived timing, same-ref identity, power snapshot, and census.

No foreign workload appeared in any census. There were zero successful
contender admissions. All eight build and reducer child groups—one of each for
every A1/B1/B2/A2 arm—were reaped with no termination or escalation.

## Timing result

All values are nanoseconds per transition. P95 uses nearest rank.

| Operation | Baseline median | Candidate median | Baseline p95 | Candidate p95 |
| --- | ---: | ---: | ---: | ---: |
| `generic_exit_claim` | 3.699165 | 3.329790 | 3.917500 | 3.447910 |
| `exec_error_to_terminal` | 8.057290 | 6.827290 | 8.466670 | 7.042080 |

The generic-claim candidate/baseline median ratio is `0.9001463844`; the p95
ratio is `0.8801301851`.

## Acceptance

Accepted. The JSON records `accepted: true`: the generic median ratio is at
most `1.05`, the generic p95 ratio is at most `1.10`, and contender admissions
are zero. The adjacent JSON is the authoritative machine-readable receipt for
raw rows, commands, per-arm census evidence, host/toolchain identity, power
state, executable identities, aggregates, and thresholds.

## Non-claims

This is release host state-machine micro-reducer evidence only. It is not
signed-HVF guest proof, Docker-oracle proof, conformance proof, ecosystem
workload proof, shipped-binary proof, cross-VMM proof, or a Carrick `<=2x`
workload-performance claim. It establishes neither general runtime performance
nor a hardened security boundary.
