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

## 2026-08-07 signed encoding recensus

The first scanner change landed as `75cb2b15cc3275b99cf56b36e7f875597bc3527e`.
`just build` produced a codesign-verified release binary with SHA-256:

```text
4c1505a7cef8e2ac6fa058b551c7ee9f31ed792468e907e5455277c02fbc7881
```

The Tier-D marker was present in the linked product. The recensus used the same
images and serial method as the baseline, with an absolute census path:

```sh
CARRICK_RUN_ID=tierd-wave1-encoding-fast \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=/Volumes/CaseSensitive/carrick/target/conformance/tierd-wave1-encoding-census.log \
just conformance-native smoke --workers 1 \
  --suite node-app-smoke \
  --suite node-v8-smoke \
  --suite cpython-fcntl \
  --suite cpython-glob \
  --suite cpython-json \
  --suite cpython-math \
  --jsonl target/conformance/tierd-wave1-encoding-fast.jsonl

CARRICK_RUN_ID=tierd-wave1-encoding-process \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=/Volumes/CaseSensitive/carrick/target/conformance/tierd-wave1-encoding-census.log \
just conformance-native smoke --workers 1 \
  --suite cpython-subprocess \
  --suite cpython-threading \
  --jsonl target/conformance/tierd-wave1-encoding-process.jsonl
```

### What closed

There is no remaining `0x38764d52` scan refusal. The family-mask proof is live
at both scanner boundaries:

- Node advanced from `0x38764d52` at `0x1c44b84` to a later word at
  `0x1c4a76c`.
- CPython's libcrypto executable-window scan advanced from `0x38764d52` at
  `0x281478` to a later word at `0x2ce8b0`.
- `cpython-fcntl` still enters directly and reaches the independently known
  `BlockingRecordLock`; this is the expected Task-4 red state.
- `cpython-glob`, `cpython-json`, and `cpython-math` remained MATCH under
  direct execution.

The wrapper results were:

| gate | result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | MATCH, Node main still scan-refused | 13,676 / 402 ms = 34.02x |
| `node-v8-smoke` | MATCH, Node main still scan-refused | 9,480 / 403 ms = 23.52x |
| `cpython-fcntl` | CARRICK_CRASH 4/4 vs 8/8, `BlockingRecordLock` | 6,789 / 603 ms = 11.26x |
| `cpython-glob` | MATCH 15/15 | 3,857 / 611 ms = 6.31x |
| `cpython-json` | MATCH 173/173 | 20,540 / 19,472 ms = 1.05x |
| `cpython-math` | MATCH 76/76 | 3,229 / 1,231 ms = 2.62x |
| `cpython-subprocess` | Empty vs 278/278 | invalid performance row |
| `cpython-threading` | Empty vs 193/193 | invalid performance row |

These are still harness diagnostics, not the canonical product scoreboard.

### The next shared scanner word

All four formerly blocked Node/CPython paths now stop on `0x61206272`:

- Node main: virtual address `0x1c4a76c`;
- libcrypto executable file window: offset `0x2ce8b0`.

Both locations are the ASCII bytes `rb a` within the same OpenSSL banner:
`Keccak-1600 absorb and squeeze for ARMv8, CRYPTOGAMS by
<appro@openssl.org>`. In the unstripped Node executable the preceding function
returns at `0x1c4a758`, mapping symbol `$d` starts at `0x1c4a75c`, and `$x`
resumes at `0x1c4a7c0`. The stripped libcrypto has no static symbol table, but
the same banner starts at file offset `0x2ce8a0` after its `ret` at `0x2ce89c`.

GNU AArch64 binutils 2.45 also decodes the isolated raw word as undefined. That
is supporting diagnosis, not yet sufficient authority for code: Wave 2 must
bind an Arm-encoding family mask, valid-neighbor mutations, and both real
corpus regressions before allowing the word through the scanner. A banner-word
whitelist remains forbidden.

## Wave-1 closeout

Wave 1 closed on source `2fcf390624ea4742e539d76a68918ba56f494774`.
The codesign-verified release binary SHA-256 was:

```text
a10ff9dec776a22c4eace2f9080d85280580f81a618f987122bca510506e3639
```

The final eight-suite command was the Task-5 command in the implementation
plan, with census
`target/conformance/tierd-wave1-final.census.log` and results
`target/conformance/tierd-wave1-final.jsonl`.

| gate | Wave-1 final result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | MATCH, Node main refused only on new `0x61206272` | 8,486 / 402 ms = 21.11x |
| `node-v8-smoke` | MATCH, Node main refused only on new `0x61206272` | 9,459 / 403 ms = 23.47x |
| `cpython-fcntl` | **MATCH 8/8**, direct, no record-lock leave | 7,411 / 603 ms = 12.29x |
| `cpython-glob` | MATCH 15/15, direct | 3,648 / 611 ms = 5.97x |
| `cpython-json` | MATCH 173/173, direct | 20,766 / 19,472 ms = 1.07x |
| `cpython-math` | MATCH 76/76, direct | 3,207 / 1,231 ms = 2.61x |
| `cpython-subprocess` | Empty vs 278/278, only new `0x61206272` | invalid performance row |
| `cpython-threading` | Empty vs 193/193, only new `0x61206272` | invalid performance row |

The record-lock implementation was separately accepted at 8/8 MATCH with
3,743 / 603 ms = 6.21x wrapper elapsed. The Wave-1 final value above is a
single later diagnostic sample and shows the expected host-noise spread; it is
not a canonical performance regression. No controlled scoreboard comparison
has yet been run.

Closure checks:

- no `0x38764d52` refusal in the final census;
- no `BlockingRecordLock` leave in the final census;
- every workload produced tier events;
- the only two red verdicts were the already recorded `0x61206272` scanner
  boundary;
- `RUST_TEST_THREADS=1 just ci` passed in full at `2fcf3906`;
- the exact Wave-1 range contained only the baseline, encoding proof,
  recensus, and record-lock commits; unrelated `proposed-plan.md` stayed
  untouched.

Wave 1 is therefore complete, not the product goal. Wave 2 begins with the
source-bound top-level reserved A64 encoding group in Task 6 of the plan.

## 2026-08-07 signed reserved-major recensus

Task 6 landed as source `01f60b2982c8e217eed5b5f1d17e47d80d064a8d`.
`just build` produced a codesign-verified release binary with SHA-256:

```text
2773d1070f3e41e0154488dd72523a5d03f2e56451fa4bffc8a0f9f2094f3ea1
```

The serial eight-suite run used the exact Task-6 command, census
`target/conformance/tierd-wave2-reserved-major.census.log`, and results
`target/conformance/tierd-wave2-reserved-major.jsonl`. It retained every
Wave-1 closure: neither prior raw word appears, `cpython-fcntl` remains 8/8
MATCH, and there is no `BlockingRecordLock` leave.

| gate | Task-6 result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | MATCH, Node main still scan-refused | 7,740 / 402 ms = 19.25x |
| `node-v8-smoke` | MATCH, Node main still scan-refused | 9,685 / 403 ms = 24.03x |
| `cpython-fcntl` | MATCH 8/8, direct | 7,621 / 603 ms = 12.64x |
| `cpython-glob` | MATCH 15/15, direct | 3,636 / 611 ms = 5.95x |
| `cpython-json` | MATCH 173/173, direct | 20,533 / 19,472 ms = 1.05x |
| `cpython-math` | MATCH 76/76, direct | 3,222 / 1,231 ms = 2.62x |
| `cpython-subprocess` | Empty vs 278/278 | invalid performance row |
| `cpython-threading` | Empty vs 193/193 | invalid performance row |

The Node MATCH rows still run the refused Node main through Tier T, and the
two Empty CPython rows did not execute their tests. None is a product
performance result.

### Next exact scanner boundary

All four scanner-blocked paths now name `0x6f406f72` in the same OpenSSL
`Keccak-1600` banner:

- Node load-time scan: virtual address `0x1c4a798`;
- CPython syscall 222 `mmap(PROT_EXEC, fd)` window scan: file offset
  `0x2ce8dc` in libcrypto.

The reserved-major word `0x61206272` is absent. An audit of every 32-bit word
in the banner found this is the final word for which `bad64` rejects the word
while the conservative raw-field test can name x18.

The Arm encoding tree places `0x6f406f72` in "Advanced SIMD shift by
immediate": bit 31=`0`, bits 28:23=`0b011110`, bit 10=`1`, and nonzero `immh`
bits 22:19. Within that class its opcode has bit 15=`0`, bit 11=`1`, the
architecturally unallocated opcode subspace. Two one-bit falsification
controls are allocated:

- clear bit 11: `0x6f406772`, `sqshlu v18.2d, v27.2d, #0`;
- clear bit 10: `0x6f406b72`, an Advanced SIMD element multiply-long
  instruction.

Task 7 binds the exact class and unallocated opcode masks plus both allocated
neighbors. It remains an architectural proof, not a banner-word whitelist.
