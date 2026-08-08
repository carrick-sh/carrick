# Tier D Node and Python Baseline

**Date:** 2026-08-07

**Status:** living campaign authority; Python correctness closed, Node dynamic
RWX open, clean product performance open

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

## 2026-08-07 signed SIMD-shift recensus

Task 7 landed as source `d2eb3998474738151e3f6a8bd96189778bbca50c`.
`just build` produced a codesign-verified release binary with SHA-256:

```text
d1b02b06825ce76bb290ec6de227ea88967ec70dd3c49bf28dd7a6ca66f7a612
```

The serial eight-suite run used census
`target/conformance/tierd-wave2-simd-shift.census.log` and results
`target/conformance/tierd-wave2-simd-shift.jsonl`. The previous banner word is
absent, as are `0x61206272`, `0x38764d52`, and `BlockingRecordLock`.

| gate | Task-7 result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | MATCH, Node main still scan-refused | 7,653 / 402 ms = 19.04x |
| `node-v8-smoke` | MATCH, Node main still scan-refused | 9,686 / 403 ms = 24.03x |
| `cpython-fcntl` | MATCH 8/8, direct | 7,377 / 603 ms = 12.23x |
| `cpython-glob` | MATCH 15/15, direct | 3,641 / 611 ms = 5.96x |
| `cpython-json` | MATCH 173/173, direct | 20,360 / 19,472 ms = 1.05x |
| `cpython-math` | MATCH 76/76, direct | 3,245 / 1,231 ms = 2.64x |
| `cpython-subprocess` | Empty vs 278/278 | invalid performance row |
| `cpython-threading` | Empty vs 193/193 | invalid performance row |

The Node rows still fall back to Tier T and the Empty Python rows still did
not execute their tests. These elapsed values remain diagnostics only.

### Next exact scanner boundary and reserved-mask correction

All four blocked paths now refuse `0xbcc3cad1`:

- Node load-time scan: virtual address `0x1c53e64`;
- CPython syscall 222 executable-window scan: libcrypto file offset
  `0x2e4be4`.

The unstripped Node executable identifies the enclosing range as the 272-byte
local object `_vpsm4_ex_consts` at `0x1c53e00`. Stripped libcrypto contains a
byte-identical range at `0x2e4b80`; both range hashes are
`ab0963561f345b19c2db922b349d5960763ef10175c5ab391061006b46424cb0`.

Arm's "Load/store register (unprivileged)" class fixes bits 29:27=`0b111`,
bits 25:24=`0b00`, and bits 11:10=`0b10`. The class has no SIMD/FP forms, so
`V` bit 26=`1` is unallocated for the entire class. That is the measured word;
its raw bits 14:10 resemble x18 only because they are not a register operand
in this encoding. One-bit control `0x9cc3cad1` is allocated `ldr q17,
<literal>` and lies outside the proof.

The constant-range audit also found a later SME-shaped word and exposed that
Task 6 had omitted bit 31 from its top-level mask. Source `7501cfa0` adds an
allocated SME falsification control (`0x80800012`, `fmops`) and narrows the
mask from `0x1e000000` to `0x9e000000`: only bit 31=`0` plus bits
28:25=`0b0000` is the reserved major group. The Task-7 measured paths did not
reach that later word, but every subsequent build must carry this correction.

## 2026-08-07 signed SIMD-unprivileged recensus

Task 8 landed as source `379d25544ff55188811296a4ac743f938365f233`.
The codesign-verified release binary SHA-256 was:

```text
5fc847f82b270a420ed003a5ac2955cdb55fda787cf8ed0857375100b964fff7
```

The serial eight-suite run used census
`target/conformance/tierd-wave2-simd-unprivileged.census.log` and results
`target/conformance/tierd-wave2-simd-unprivileged.jsonl`. It contains none of
the four prior scanner words or the record-lock leave.

| gate | Task-8 result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | MATCH, Node main still scan-refused | 7,925 / 402 ms = 19.71x |
| `node-v8-smoke` | MATCH, Node main still scan-refused | 9,900 / 403 ms = 24.57x |
| `cpython-fcntl` | MATCH 8/8, direct | 7,195 / 603 ms = 11.93x |
| `cpython-glob` | MATCH 15/15, direct | 3,668 / 611 ms = 6.00x |
| `cpython-json` | MATCH 173/173, direct | 19,916 / 19,472 ms = 1.02x |
| `cpython-math` | MATCH 76/76, direct | 3,224 / 1,231 ms = 2.62x |
| `cpython-subprocess` | Empty vs 278/278 | invalid performance row |
| `cpython-threading` | Empty vs 193/193 | invalid performance row |

Node still falls back to Tier T and the two Empty rows still did not execute
their Python tests. The table remains diagnostic, not a product scoreboard.

### Next exact scanner boundary

The shared next refusal is `0x02783a40`:

- Node load-time scan: virtual address `0x1c53ec8`;
- CPython syscall 222 executable-window scan: libcrypto file offset
  `0x2e4c48`.

It is byte `0xc8` of the same byte-identical `_vpsm4_ex_consts` range. Arm's
root A64 table marks top-level `op1` values satisfying
`(bits28:25 & 0b1101) == 0b0001` unallocated. The measured word has
`op1=0b0001`. Toggling bit 27 gives allocated `0x0a783a40`,
`bic w0, w18, w24, lsr #14`; that one-bit control must remain on the decoded
x18 refusal path. Task 9 binds only this root-table mask.

## 2026-08-07 signed top-level-op1 recensus

Task 9 landed as source `44cc69d44f0611ce76231ca975d77da37b503e79`.
The codesign-verified release binary SHA-256 was:

```text
33c3b18e8f86fa049324e7f340b1c4481bd3a26461eca8a1cfe11c148c5434d6
```

The serial eight-suite run used census
`target/conformance/tierd-wave2-top-level-op1.census.log` and results
`target/conformance/tierd-wave2-top-level-op1.jsonl`. It retained every prior
scanner and record-lock closure.

| gate | Task-9 result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | MATCH, Node main still scan-refused | 9,781 / 402 ms = 24.33x |
| `node-v8-smoke` | MATCH, Node main still scan-refused | 10,119 / 403 ms = 25.11x |
| `cpython-fcntl` | MATCH 8/8, direct | 7,812 / 603 ms = 12.96x |
| `cpython-glob` | MATCH 15/15, direct | 3,863 / 611 ms = 6.32x |
| `cpython-json` | MATCH 173/173, direct | 20,765 / 19,472 ms = 1.07x |
| `cpython-math` | MATCH 76/76, direct | 3,461 / 1,231 ms = 2.81x |
| `cpython-subprocess` | Empty vs 278/278 | invalid performance row |
| `cpython-threading` | Empty vs 193/193 | invalid performance row |

The Node rows remain Tier-T fallback diagnostics and the Empty Python rows
remain invalid for performance.

### Next boundary is allocated, x18-free SME2

All four paths now refuse `0xc1d21300` at Node `0x1c53ee0` and libcrypto
`0x2e4c60`, byte `0xe0` of `_vpsm4_ex_consts`. LLDB at the generated decoder
proves it reaches `decode_iclass_mortlach_multi2_mla_long_idx`, then the Arm
XML encoding `SMLAL ZA, Z, Z[index]` two-vector form. The word matches exact
mask/value `0xfff09038/0xc1d01000`.

This word is allocated. `bad64` returns `ErrorOperands` because its operand
formatter has no case for the new encoding, not because Arm reserves it. Its
only general-register operand is the ZA row selector constrained to W8-W11;
the remaining operands are ZA/Z registers and immediates. It cannot name GPR
x18. The one-bit control `0xe1d21300` is allocated
`ld1q z0h.q[w12], p4/z, [x24, x18, lsl #4]` and must remain outside the proof.
Task 10 therefore adds a separately named x18-free decoder-failure proof; it
must not broaden or mislabel `word_is_proven_unallocated`.

## 2026-08-07 signed allocated-SME2 recensus

Task 10 landed as source `49c80f8917bc4d01beab563049088820cb3109c6`.
The codesign-verified release binary SHA-256 was:

```text
5e9e8823a5838f7676ad429dced4c23562dcd3dad1f46d2f5a8514587e008f1d
```

The serial eight-suite run used census
`target/conformance/tierd-wave2-allocated-sme2.census.log` and results
`target/conformance/tierd-wave2-allocated-sme2.jsonl`. It contains no scanner
refusal: both Node and CPython main processes now record `direct-enter`.

| gate | Task-10 result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | REGRESSION, Node rc 139 after direct entry | 10,792 / 402 ms = 26.85x |
| `node-v8-smoke` | REGRESSION, Node rc 139 after direct entry | 12,405 / 403 ms = 30.78x |
| `cpython-fcntl` | MATCH 8/8, direct | 7,386 / 603 ms = 12.25x |
| `cpython-glob` | MATCH 15/15, direct | 3,652 / 611 ms = 5.98x |
| `cpython-json` | MATCH 173/173, direct | 19,714 / 19,472 ms = 1.01x |
| `cpython-math` | MATCH 76/76, direct | 3,243 / 1,231 ms = 2.63x |
| `cpython-subprocess` | CRASH at first active test, 0/278 | invalid performance row |
| `cpython-threading` | CRASH after 139 pass, 1 fail, 1 skip | invalid performance row |

These are conformance-wrapper diagnostics, not canonical performance results.
In particular, the failed Node rows and incomplete Python rows cannot enter the
product scoreboard.

### Scanner closed; first real workload blockers

`cpython-subprocess` reaches
`ContextManagerTests.test_broken_pipe_cleanup`, after successfully executing
`/usr/bin/uname` and `/usr/bin/true` children, then leaves at syscall 64 with:

```text
BlockingHostWrite { host_fd: 17, bytes_len: 4194305, offset: 65536,
                    tid: ThreadId(29781), sigpipe_on_epipe: true }
```

The shared native driver already services this typed continuation without
re-dispatching its written prefix. Task 11 adds the same adapter to the Tier-D
runner, preserving partial progress, interrupt semantics, and SIGPIPE
publication.

`cpython-threading` reaches the fork-from-thread portion of the suite. One
exec child exits 134, `test_3_join_in_forked_from_thread` fails, and both an
exec child and the main process later leave at syscall 220 with
`multithreaded fork on tier D (no sibling quiesce)`. This remains the next
structural Python boundary; Task 11 does not alter fork semantics.

Both Node suites now enter Tier D and their Node main process exits by signal
139 without a scanner refusal or typed Tier-D leave. The outer smoke wrappers
report only `rc=139`; the Node fault therefore requires a reproducible core or
live LLDB capture and event-ring inspection before any fix. Another scanner
exception is not authorized by this result.

## 2026-08-07 signed blocking-host-write recensus

Task 11 landed as source `3a4b8da4fad54d46cf4161ae3aabe33a7dfb2b7f`.
The codesign-verified release binary SHA-256 was:

```text
e57f2ddf09efa203f0bc2d73a8a8f5390108fe61b1600480cc4d83ee92391fcc
```

The serial eight-suite run used census
`target/conformance/tierd-wave2-blocking-host-write.census.log` and results
`target/conformance/tierd-wave2-blocking-host-write.jsonl`.

| gate | Task-11 result | diagnostic elapsed |
|---|---|---:|
| `node-app-smoke` | REGRESSION, Node rc 139 after direct entry | 8,934 / 402 ms = 22.22x |
| `node-v8-smoke` | REGRESSION, Node rc 139 after direct entry | 12,584 / 403 ms = 31.23x |
| `cpython-fcntl` | MATCH 8/8, direct | 7,407 / 603 ms = 12.28x |
| `cpython-glob` | MATCH 15/15, direct | 3,659 / 611 ms = 5.99x |
| `cpython-json` | MATCH 173/173, direct | 19,713 / 19,472 ms = 1.01x |
| `cpython-math` | MATCH 76/76, direct | 3,252 / 1,231 ms = 2.64x |
| `cpython-subprocess` | CRASH after 112 pass, 2 fail, 7 skip | invalid performance row |
| `cpython-threading` | CRASH after 139 pass, 1 fail, 1 skip | invalid performance row |

The focused red/green proof is stronger than absence alone:
`test_broken_pipe_cleanup`, the exact test that previously stopped on
`BlockingHostWrite`, now passes. `cpython-subprocess` advances from zero
completed tests to 112 passes. Its new terminal event is the same syscall-220
`multithreaded fork on tier D (no sibling quiesce)` boundary as
`cpython-threading`; no `BlockingHostWrite` event remains. The deterministic
4 MiB+ draining-pipe test passed, all 1,190 runnable serialized
`carrick-runtime` library tests passed (five ignored), and formatting plus
workspace clippy were green before the narrow code commit.

Both Node wrappers still report rc 139 after their Node main process records
direct entry, with no `direct-exit`, scanner refusal, or typed leave. Task 12
therefore selects the Node debugger track: reduce the image wrapper to the
exact Node argv, capture the real guest process under LLDB, read the always-on
event ring, and bind the fault PC/registers to one mechanism before changing
code. Python's now-shared multithreaded-fork boundary remains measured and
queued; it is not being treated as fixed or as a performance result.

## 2026-08-07 signed Python lifecycle closeout

The complete Tier-D Python process/thread lifecycle landed as source
`a8b98318f7c2162630fb2d7ca37177ca2292fbe0`. `just build` produced a
codesign-verified release binary with SHA-256:

```text
05ebff444f5dd57fda9c88ecd692e43d4226014cad322ca9c7bbecf118c6a340
```

The implementation adds the missing semantics rather than weakening a gate:

- process-creating fork quiesces every live Tier-D sibling at a lock-safe
  syscall/wait boundary, holds the shared pause mutex across `fork(2)`, and
  repairs the child copy before guest execution resumes;
- process teardown wakes both futex and `ThreadWaiter` parks, while internal
  fork-quiesce wakes preserve the guest's original sleep deadline;
- default fatal signals retain `WIFSIGNALED` wait status instead of becoming a
  normal `128 + signal` exit;
- the live Tier-D thread registry is published to `/proc/self/task` consumers
  and replaced after fork, so CPython sees the correct surviving main thread.

The canonical serial gate was:

```sh
CARRICK_RUN_ID=tierd-python-canonical-green \
CARRICK_NATIVE_DIRECT=1 \
CARRICK_TIER_CENSUS=/Volumes/CaseSensitive/carrick/target/conformance/tierd-python-canonical-green.census.log \
just conformance-native smoke --workers 1 \
  --suite cpython-subprocess --suite cpython-threading \
  --jsonl target/conformance/tierd-python-canonical-green.jsonl
```

Docker results came from the committed native-arm64 oracle cache; Carrick and
Docker did not overlap. Both suites are exact matches with no new or known
diffs:

| gate | shipped-default Tier-D result | diagnostic elapsed |
|---|---|---:|
| `cpython-subprocess` | MATCH 278/278 (42 matching skips) | 112,919 / 20,895 ms = **5.40x** |
| `cpython-threading` | MATCH 193/193 (2 matching skips) | 27,900 / 13,682 ms = **2.04x** |

These results close the measured Python correctness boundary: 471/471 active
tests match the oracle. The elapsed ratios remain conformance-wrapper
diagnostics, not the clean canonical product scoreboard. They nevertheless
make the next selection unambiguous: threading is at the edge of the 2x bar,
while subprocess still needs mechanism attribution and a material reduction.

Focused red/green evidence also covered the two previously misreported fatal
signal cases (`test_run_abort`, `test_terminate`) and all four CPython
fork-from-foreign/non-main-thread cases. The deterministic runtime regression
parks a live sibling in a 60-second guest sleep, forks and reaps a process
child, then proves `exit_group` wakes and retires the sibling promptly. The
post-change `RUST_TEST_THREADS=1 just ci` gate passed in full, including 1,191
serialized `carrick-runtime` library tests (five ignored) and every integration,
lint, documentation, dependency-policy, and support-matrix gate.

Python is therefore correct for the named Tier-D suites but is not performance
complete. Node remains correctness-incomplete at the later dynamic
`mprotect(PROT_READ|PROT_WRITE|PROT_EXEC)` transition; the static x18 faults
are already closed, and no blanket RWX exemption is authorized.
