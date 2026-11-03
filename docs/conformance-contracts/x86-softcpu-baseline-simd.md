# Baseline SIMD execution before CPUID advertisement

Issue #1532 extends `x86.softcpu.level0`, on the x87/CX16 implementation
from #1469/#1489. Intel SDM Volume 2 instruction semantics and native x86
execution are the authorities. No software CPUID default changes in this slice.

`advertised_sse_census_matches_native` executes the requested SSE/SSE2
encodings, including legal memory variants, through `SoftCpu::step_block`.
Three input patterns compare XMM registers, sized GPR results, modified
arithmetic flags, MXCSR and memory against independently executed native
instructions. The first SHUFPS failed with #UD before implementation. The standalone
`advertised_sse2_pcmpgtb_uses_signed_lanes` likewise failed with #UD on
the admitted pre-fix sources and now checks signed lane comparisons.
`advertised_mmx_uses_virtual_x87_image` failed with #UD on MOVQ before the
fix; it now loads, adds, stores and empties the shared x87 tags with EMMS.
`advertised_clflush_checks_guest_translation` likewise failed with #UD,
and now executes CLFLUSH on authenticated RAM and raises guest #PF for an
unmapped byte. The fault/revocation witness checks #XM without flag
publication, aligned packed operand #GP, #PF, cross-page MMX fault atomicity,
and revocation of already executed MMX/CLFLUSH after replacing guest CPUID.

The SSE/SSE2 additions reuse the checked legacy-vector executor. Native
exceptions remain masked; guest MXCSR controls publication. The private
operand is at most 16 bytes, hence spans at most two guest pages. Legacy
operations preserve YMM upper halves. Non-temporal stores drain with SFENCE
before copying the private result into guest memory. MOVNTI is an integer
store: CR0.EM/TS and CR4.OSFXSR do not gate it. MMX uses the existing cached
single-instruction FXSAVE leaf, retaining virtual x87 metadata, with no GPR
operands admitted to that leaf. Every operation has constant-sized work;
leaf allocation remains cached per normalized encoding rather than per step.
CLFLUSH qualifies the host CLFSH capability before preparing execution,
validates one guest byte and flushes only the translated RAM line;
device MMIO has no host cache line to flush.

`advertised_bit_allowlist_executes_through_step_block` enumerates every set
bit in the architectural instruction/control feature registers of both
currently enabled software profiles, including XSAVE subleaf 1. Missing
mappings, host errors, #UD, other faults and unhandled sensitive exits fail.
Control capability bits use representative control-register/MSR operations;
this witness proves execution admission, not complete semantics of every
capability or every encoding within a family. Topology, address widths,
cache descriptors, timing ratios and XCR0 component masks are value fields,
not instruction feature registers.

Run the identical witness against the proposed shared view with:

```
CARRICK_CPUID_WITNESS_SHARED=1 cargo test -p carrick-softcpu-x86 \
  --test softcpu_level0 advertised_bit_allowlist -- --nocapture
```

This is deliberately a failing diagnostic until the remaining advertised
families execute. This slice reports seven #UD families: PCLMULQDQ, FMA,
MOVBE, AES-NI, F16C, BMI1 and BMI2. They need follow-up implementation and
semantic witnesses before #1472 switches to the shared view. No failure is
accepted as execution and no known-gap list suppresses the diagnostic.

The obscure SSE/SSE2 tail also remains unproved: e.g. COMISS, RSQRTPS/SS,
RCPSS, other packed/scalar conversion variants, packed saturating arithmetic,
other shifts and packed comparisons. MMX beyond MOVQ/PADDB/EMMS is not
admitted here. A representative feature witness is not full family coverage.
Native differential and VM-free tests do not supply signed HVF, Docker,
KVM workload integration, ecosystem performance or release acceptance.
