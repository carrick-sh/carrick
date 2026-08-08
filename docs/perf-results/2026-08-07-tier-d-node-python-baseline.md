# Tier D Node and Python Baseline

**Date:** 2026-08-07

**Status:** pre-fix Wave-1 authority

**Backend:** Darwin/AArch64 native DSR, forced Tier D, native16k

**Source:** `3e88dd8a95940fc8467d4f58c7bb30e1a1b1c47f`

**Signed binary SHA-256:**
`287faa2572ce0671a982be8623e30c35f0ac0603527a4002a8b5b1dcf202be8a`

This document binds the current Tier-D Node/CPython campaign to the exact
pre-fix result. It is correctness and blocker-selection evidence. The elapsed
times below are conformance-wrapper measurements, not the canonical product
scoreboard described in the campaign design.

## Provenance and method

- Host: Apple arm64, macOS 27.0 build `26A5388g`.
- Carrick image execution: `--exec-backend native --native-page-profile
  native16k`, with `CARRICK_NATIVE_DIRECT=1`.
- Node image:
  `localhost:5005/carrick-nodejs-conformance:24.16.0-26.2.0`.
- CPython image: `localhost:5050/cpython-test:3.12.13`.
- Carrick cases ran serially. Docker oracle records came from the committed
  native-arm64 cache, so Carrick and Docker did not overlap.
- Raw results:
  `target/conformance/tierd-node-python-fast-baseline-20260807.jsonl` and
  `target/conformance/tierd-cpython-process-thread-baseline-20260807.jsonl`.
- `codesign --verify --verbose=2 target/release/carrick` passed. The binary
  carried the `com.apple.security.hypervisor` entitlement; Tier D itself does
  not require HVF, but this records the standard signed product artifact.

The focused invocations were:

```sh
CARRICK_RUN_ID=tierd-node-python-fast-baseline-20260807 \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-node-python-baseline.census.log \
just conformance-native smoke --workers 1 \
  --suite node-app-smoke \
  --suite node-v8-smoke \
  --suite cpython-fcntl \
  --suite cpython-glob \
  --suite cpython-json \
  --suite cpython-math \
  --jsonl target/conformance/tierd-node-python-fast-baseline-20260807.jsonl

CARRICK_RUN_ID=tierd-cpython-process-thread-baseline-20260807 \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=target/conformance/tierd-cpython-process-thread-baseline.census.log \
just conformance-native smoke --workers 1 \
  --suite cpython-subprocess \
  --suite cpython-threading \
  --jsonl target/conformance/tierd-cpython-process-thread-baseline-20260807.jsonl
```

## Current result

| gate | Carrick | Docker | wrapper ratio / first blocker |
|---|---:|---:|---|
| `node-app-smoke` | MATCH (7,911 ms) | MATCH (402 ms) | **19.68x**; Node main scan-refused `0x38764d52` |
| `node-v8-smoke` | MATCH (9,607 ms) | MATCH (403 ms) | **23.84x**; Node main scan-refused `0x38764d52` |
| `cpython-fcntl` | CARRICK_CRASH, 4/4 (6,991 ms) | 8/8 (603 ms) | **11.59x**; named `BlockingRecordLock` leave |
| `cpython-glob` | MATCH 15/15 (3,852 ms) | 15/15 (611 ms) | **6.30x**, direct |
| `cpython-json` | MATCH 173/173 (20,532 ms) | 173/173 (19,472 ms) | **1.05x**, direct |
| `cpython-math` | MATCH 76/76 (3,023 ms) | 76/76 (1,231 ms) | **2.46x**, direct |
| `cpython-subprocess` | Empty, 0/0 (2,804 ms) | 278/278 (20,895 ms) | regression; libcrypto window refusal `0x38764d52` |
| `cpython-threading` | Empty, 0/0 (2,609 ms) | 193/193 (13,682 ms) | regression; libcrypto window refusal `0x38764d52` |

The sub-1 elapsed ratios on the Empty rows are invalid as performance results:
the workload never ran. Likewise, the Node MATCH rows do not measure Tier-D
Node because the Node main binary was refused and ran through Tier T.

## Shared scanner blocker

The exact raw word is present in both ecosystems:

- `/opt/node-src/v24/out/Release/node`, virtual address `0x1c44b84`;
- stripped `/usr/lib/aarch64-linux-gnu/libcrypto.so.3`, executable file-window
  offset `0x281478`.

The bytes spell the ASCII substring `RMv8` in an OpenSSL assembler banner after
a `ret`. The unstripped Node executable gives independent data-range evidence:
the AArch64 mapping symbol `$d` begins at `0x1c44b70` and `$x` resumes at
`0x1c44bc0`. The shipped libcrypto is stripped, so that symbol proof is not a
general solution.

The architecture proof is general enough for both files. In the AArch64
load/store register-offset family, bits 11:10 are fixed to `0b10` for allocated
encodings. `0x38764d52` has `0b11`, so it is architecturally unallocated and
cannot access x18 if executed. Its nearest allocated neighbor, `0x38764952`,
disassembles as:

```text
ldrb w18, [x10, w22, uxtw]
```

Wave 1 therefore adds a family-mask validity proof, not a word whitelist and
not a blanket decoder-failure exemption. The scanner must continue to reject
unproven undecodable words and must continue to patch allocated instructions
that name x18.

## Historical mechanism evidence

The controlled `ablation-pie-fixture-v2` comparison on the pinned CPython
3.12.13 fixture measured:

| tier | workload wall | ratio to Docker |
|---|---:|---:|
| Tier T | 4,097.9 ms | 22.1x |
| Tier D | 1,484.4 ms | 8.0x |

Removing same-ISA translation removed 63.8% of Tier-T wall (a 2.76x
improvement). That proves Tier D is the correct architectural direction, while
also proving that direct execution alone is insufficient: the measured
post-translation residual was still 8.0x. The active product gate remains no
more than 2.0x Docker on both canonical Node and CPython workloads, with 1.0x
the stretch outcome.

## Wave-1 decision

1. Admit decoder failures only when an independent, source-bound AArch64
   family mask proves the word unallocated.
2. Rebuild the signed product and recensus these exact eight suites.
3. Service the already observed `BlockingRecordLock` outcome using the shared
   native DSR blocking driver after dispatch locks have been released.
4. Let the signed recensus name Wave 2; do not pre-implement an assumed Node
   JIT or CPython process/thread blocker.

Governing design:
[`2026-08-07-tier-d-node-python-default-design.md`](../superpowers/specs/2026-08-07-tier-d-node-python-default-design.md).
Execution plan:
[`2026-08-07-tier-d-node-python-default.md`](../superpowers/plans/2026-08-07-tier-d-node-python-default.md).
