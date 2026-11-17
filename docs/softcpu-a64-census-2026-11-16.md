# A64 EL1 census — 2026-11-16

This is a dated informational measurement for slice 0a of #1236. It is not
an instruction inventory or a conformance receipt. No test or lint compares
this snapshot with a fresh run. Regenerate measurements after image/compiler
changes with:

```sh
carrick debug a64-census /path/to/linked/carrick-el1 > report.json
```

The input is the production `aarch64-unknown-none-softfloat` EL1 ELF built by
`carrick-el1-image` under the `el1-image` profile. ELF mapping symbols exclude
data and literal pools. Loader maintenance and all vector-builder configurations
are separate spans; their multiplicity is retained in these aggregate counts.
Static presence is an upper bound, not dynamic reachability or a minimum CPU
subset. EL0 fixture closure belongs to slice 0b.

Per the director's amendment, default measurement mode exits 0 with unknowns;
`--strict` rejects any unknown word. No production-image strict CI gate is wired
by this slice. Diagnostic cause labels never promote an Unknown word to a
recognized instruction and do not validate its operands.

Tool package version: 0.1.0. The current ELF contains no `.comment`
producer strings, so input compiler provenance is unavailable in the report.

## Class counts

| Class | Words |
|---|---:|
| AcquireRelease | 4110 |
| Address | 4510 |
| Arithmetic | 70509 |
| Barrier | 1156 |
| Bitfield | 5806 |
| Branch | 52582 |
| Call | 17303 |
| ConditionalCompare | 285 |
| ConditionalSelect | 4694 |
| Divide | 19 |
| Eret | 598 |
| Exclusive | 5201 |
| Hint | 105356 |
| Hvc | 387 |
| Logical | 39758 |
| LseAtomic | 4 |
| MoveWide | 29726 |
| Mrs | 709 |
| Msr | 492 |
| Multiply | 2311 |
| PairLoadStore | 31001 |
| Pstate | 4 |
| Return | 3956 |
| ScalarLoadStore | 72159 |
| SimdFpLoadStore | 32 |
| Tlbi | 75 |
| Unknown | 1373 |
| Wfi | 1 |

## Known gaps for A1

Unknown words: **1373**, across 309 distinct encodings.

| Diagnostic cause | Words |
|---|---:|
| at | 6 |
| brk | 62 |
| clrex | 529 |
| clz_rbit | 196 |
| others | 0 |
| tlbi | 1 |
| variable_shifts | 579 |

AT covers S1E0R/S1E0W; the observed unknown TLBI is VAE1. Wider SIMD/FP
computation and unchecked extensions also remain Unknown; this softfloat EL1
image does not exercise those families. Counts are not a decoder support claim.

## System-register encodings observed

These count MRS/MSR instructions, not backend-initialized register state.

| Encoding (name) | Accesses |
|---|---:|
| `S3_0_C0_C0_5 (MPIDR_EL1)` | 1 |
| `S3_0_C12_C11_5 (ICC_SGI1R_EL1)` | 7 |
| `S3_0_C12_C12_0 (ICC_IAR1_EL1)` | 5 |
| `S3_0_C12_C12_1 (ICC_EOIR1_EL1)` | 3 |
| `S3_0_C13_C0_1 (CONTEXTIDR_EL1)` | 2 |
| `S3_0_C13_C0_4 (TPIDR_EL1)` | 254 |
| `S3_0_C2_C0_0 (TTBR0_EL1)` | 59 |
| `S3_0_C2_C0_1 (TTBR1_EL1)` | 14 |
| `S3_0_C4_C0_0 (SPSR_EL1)` | 204 |
| `S3_0_C4_C0_1 (ELR_EL1)` | 268 |
| `S3_0_C4_C1_0 (SP_EL0)` | 31 |
| `S3_0_C5_C2_0 (ESR_EL1)` | 177 |
| `S3_0_C6_C0_0 (FAR_EL1)` | 92 |
| `S3_0_C7_C4_0 (PAR_EL1)` | 6 |
| `S3_3_C13_C0_2 (TPIDR_EL0)` | 2 |
| `S3_3_C13_C0_3 (TPIDRRO_EL0)` | 2 |
| `S3_3_C14_C0_0 (CNTFRQ_EL0)` | 16 |
| `S3_3_C14_C0_2 (CNTVCT_EL0)` | 31 |
| `S3_3_C14_C3_1 (CNTV_CTL_EL0)` | 7 |
| `S3_3_C14_C3_2 (CNTV_CVAL_EL0)` | 4 |
| `S3_3_C4_C2_1 (DAIF)` | 12 |
| `S3_3_C4_C4_0 (FPCR)` | 2 |
| `S3_3_C4_C4_1 (FPSR)` | 2 |

## Rebase measurement: most frequent unknown encodings

The rebuilt production image has **1,373 unknown words** across
310 distinct encodings. The table records the twenty most frequent words,
sorted by count and then encoding, with the first encountered address as an
example. It is informational; no test compares it with a fresh measurement.
Regenerate with the command above. The class and register tables above retain
the original baseline measurement. Diagnostic causes do not validate operands
or promote an Unknown word to a recognized instruction.

| Hex word | Diagnostic cause | Count | Example address |
|---|---|---:|---|
| `0xd5033f5f` | clrex | 529 | `0x2d040018e0` |
| `0x9ac82428` | variable shifts | 65 | `0x2d04000cf8` |
| `0xd4200020` | brk | 62 | `0x2d0402d350` |
| `0xdac01108` | CLZ | 53 | `0x2d04004c78` |
| `0x9ac82129` | variable shifts | 51 | `0x2d0400766c` |
| `0x9ac82128` | variable shifts | 21 | `0x2d0401a83c` |
| `0xdac01129` | CLZ | 16 | `0x2d04008dd0` |
| `0x1ac92109` | variable shifts | 14 | `0x2d0402b1bc` |
| `0x9ac9254a` | variable shifts | 13 | `0x2d0400a1d4` |
| `0xdac0114a` | CLZ | 13 | `0x2d04040dec` |
| `0x9ac92149` | variable shifts | 12 | `0x2d0400748c` |
| `0xdac002c8` | RBIT | 12 | `0x2d04094af0` |
| `0x1ac82128` | variable shifts | 11 | `0x2d04072698` |
| `0xdac00268` | RBIT | 10 | `0x2d04004f18` |
| `0x9ac82528` | variable shifts | 9 | `0x2d04020ac4` |
| `0xdac00308` | RBIT | 9 | `0x2d040853d4` |
| `0x1ac92508` | variable shifts | 8 | `0x2d0404b34c` |
| `0x9acd21cd` | variable shifts | 8 | `0x2d04129e58` |
| `0x1ac82528` | variable shifts | 7 | `0x2d0402bc9c` |
| `0x9ada2108` | variable shifts | 7 | `0x2d0408f290` |

## Hosted decode gate (#2454)

`just a64-census-gate` builds the production ELF through the CLI's
`carrick-el1-image` dependency on Linux. Cargo build-script JSON identifies the
fresh image's output directory. The gate runs the production census with
`--strict`, then all ignored softcpu integration witnesses, including both
real-image tests and the LLVM operand differentials (#2470). It sets
`CARRICK_A64_ELF` and uses the pinned Rust sysroot's `llvm-objdump` through
`CARRICK_LLVM_OBJDUMP` (an explicit override is accepted). No guest VM boots.
The toolchain must include `aarch64-unknown-none-softfloat` and LLVM tools;
`jq` is required. Build metadata and the census report remain under
`$CARGO_TARGET_DIR/a64-census-gate` (default `target/a64-census-gate`).

The report includes `typed_undecoded_count` and `typed_undecoded`, retaining
span, address, encoding and classifier class for each word the typed decoder
rejects. Classifier unknowns remain a separate population; the two populations
may overlap. Report mode exits zero; strict mode rejects either population.
These are static decoding checks, not evidence of instruction execution.

For a known-answer negative run, pass a copy of the ELF with an executable
mapping-symbol word replaced by `0xffffffff` to
`just a64-census-gate /path/to/corrupted.elf`. The override affects the census
and both real-image witnesses. To check the LLVM harness fails closed, run with
`CARRICK_LLVM_OBJDUMP=/bin/false`; the differentials must fail.

The director-supplied hosted job is advisory initially. Its stable check name
is `A64 census gate` (job id `a64-census-gate`); do not add it to `ci-ok` or
branch-protection requirements until the director promotes it.

## Round 2: loader/vector typed gaps

After #2455 merged, the loader/vector subset still contains **2,081**
typed-undecoded words: 10 in `loader-maintenance`, 2,071 across the 28 vector
builder configurations. These are synthesized by `carrick-mem::memory`, not
ELF sections or linker symbols. The production ELF's mapping-symbol spans are
an independent population (the subject of #2471).

| Class | Words | LLVM mnemonic cross-check |
|---|---:|---|
| Mrs | 616 | `mrs` (ELR, ESR, FAR, SPSR, SP_EL0, TPIDR, TTBR0) |
| Msr | 427 | `msr` (ELR, ESR, FAR, SPSR, TPIDR) |
| Eret | 598 | `eret` |
| Hvc | 357 | `hvc #1/#2/#3/#4/#5/#7` |
| Barrier | 78 | `dsb sy/ish/ishst`, `isb` |
| LseAtomic | 4 | `ldaddal x17, xzr, [x16]` |
| Tlbi | 1 | `tlbi vmalle1is` |

All rejected words are real emitted instructions. No rejected word is a
literal, zero/UDF word, NOP padding, or `.balign` filler. The builders fill
unused vector and maintenance space explicitly with NOPs, which already decode.
The four LSE words occur in clock transport code; LLVM notes that destination
XZR drops acquire semantics. A future typed implementation must preserve that
operand-dependent behavior.

The 16 KiB maintenance span includes the initial maintenance/service-return
sequence and the ASID maintenance sequence at offset `0x100`. The vector spans
cover the 16-slot table plus identity/fstat, mailbox, clock, current-EL sync,
EL1 vector, EL0 IRQ/signal/fault and resume-invalidation handlers. Multiplicity
across configurations is intentional. Excluding these words as data would hide
real decode gaps; no span fix is proposed. The detailed region/configuration
breakdown and reproduction commands are in the round 2 PR evidence comment.

The rebased production CLI run reports 2,600 spans, 458,467 words, zero
classifier unknowns and 3,363 typed-undecoded words (1,282 in ELF `.text`,
2,081 in synthesized loader/vector pages). Strict exits 1. Every synthesized
span's SHA-256 and every rejected word's span/offset/encoding match the
independent diagnostic above. These are measurements before #2471 lands,
not a claim that the remaining decode work is closed.
