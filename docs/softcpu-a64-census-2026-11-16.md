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
