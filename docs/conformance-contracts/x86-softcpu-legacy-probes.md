# Legacy instructions in x86 musl probes

Issue #1487 extends `x86.softcpu.level0` for PMOVMSKB and PINSRW
(SSE2 XMM forms), memory BT/BTC/BTR/BTS, and the F3 BSF encoding.
The semantic authority is the [Intel SDM, Volume 2](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf),
with independent native x86 execution in `softcpu_level0::legacy_probe_*`.
MMX remains unadmitted because the soft CPU has no MMX execution state.

The first four witnesses failed with guest #UD before implementation:
`legacy_probe_pmovmskb_matches_native`, `legacy_probe_btr_memory_matches_native`,
`legacy_probe_pinsrw_matches_native`, and
`legacy_probe_tzcnt_without_bmi1_is_bsf`. Expanded witnesses cover signed indexes,
16/32/64-bit bit strings, LOCK, cross-page fault atomicity, PINSRW's two-byte
memory input, immediate lane masking, and guest BMI1 authority replacement.
Native fault qualification independently confirms that a cross-page BTR fault
sets the page-fault write bit. RMW slow paths now validate reads as write
accesses, including on the second page, before modifying guest bytes.

Memory bit indexes select a signed word offset before translation. The emitted
native operation uses only the index modulo the operand bit width. RCX is an
emitter scratch register restored without changing carry. The effective word
passes through the existing soft TLB and page-crossing bounce path; no native
instruction can use the original unbounded index against a translated host
pointer. Address arithmetic uses a fixed instruction sequence, independent of
index magnitude; each operation touches at most one operand-sized word and two
pages. Same-page LOCK uses the existing native atomic path. Cross-page LOCK
atomicity remains the level0 contract's existing unresolved #626 limitation.

TZCNT executes in the checked helper. Guest CPUID leaf 7 EBX bit 3 selects
TZCNT semantics; without BMI1 the encoding has BSF semantics, regardless of host
features. Zero-input BSF leaves its architecturally undefined destination
unchanged. Nonzero BSF updates ZF and the sized destination; TZCNT sets CF for
zero input and ZF for a zero result. No feature is newly advertised.

## Static admission census

`cargo run -p carrick-softcpu-x86 --example scan_unsupported -- --expect-files 552 ELF...`
linearly decodes executable ELF sections through the production classifier.
It reports every unsupported encoding, its occurrence count, and affected ELF
count, sorted by encoding. Inline data and deliberate UD2 traps remain visible:
this is a static census, not a reachability claim or a runtime stop count.
Wrong ISA, empty/missing executable sections, duplicate inputs, and population
mismatches fail closed. Supply only the admitted probe binaries, never a broad
release-directory glob containing dependency artifacts.

Without `--baseline`, any residue returns failure while printing the census.
With `--baseline residue.tsv`, every current encoding must have both counts
less than or equal to its reviewed ceiling; new encodings fail. An empty
baseline requires zero residue. Compare only identical probe input identities
and compiler settings; inventory and hash binaries separately before accepting
a census. A smaller fixture set cannot stand in for the 530-probe population.

The admitted checkout builds 552 musl binaries with Rust 1.96.0, rather than
the earlier assessment's 530. A fresh `cargo build --manifest-path
conformance-probes/Cargo.toml --release --target x86_64-unknown-linux-musl
--keep-going --jobs 4` produced all 552; eight source bins remain unbuildable
on x86 (`ctrel0`, `forkfpregs`, `inzonetcp`, `mmapv8align`, `nativeetexecfork`,
`ptracepoketext`, `tlsswitch`, `windowcoherence`). These build failures are
explicit exclusions, not successful probes. No stale binaries were present.
The final census decoded 47,050,390 instructions and found 51 unsupported encodings
(down from 54 before the extended legacy SIMD addition).
The ceiling is `conformance-contracts/softcpu-x86-musl-residue.tsv`; counts may
only decrease for this input population. The newly served PMOVMSKB, PINSRW,
BTR memory and TZCNT encodings are absent from the residue. Highest remaining
non-trap counts are PCMPGTB (26,496), PSRLQ immediate (11,040), and x87 FSTP
(9,384). UD2 (32,156) remains visible as an intentional architectural #UD.
This is not a runtime conformance verdict for those binaries.

## Owner scope addition: extended legacy SIMD

The checked vector executor now also serves the XMM forms of SSE3, SSSE3,
SSE4.1 and SSE4.2. It reuses its existing private operand, masked exception,
and transactional destination publication protocol. Legacy leaves use FXSAVE
for XMM state and never touch YMM upper halves or require guest AVX/XCR0.
Full-width legacy arithmetic retains its alignment requirement; LDDQU and
PCMP*STR* accept unaligned operands. Integer widening/extraction/insertion
uses the exact decoded memory width. Explicit GPRs are remapped with their
8/16/32/64-bit width, and string comparisons publish implicit ECX/XMM0 and
architectural flags. x87 FISTTP remains refused while CPUID.FPU is clear.

Cpl0CpuidView now advertises leaf-1 ECX bits 0, 9, 19, 20 and 23. Admission
checks the installed guest authority before memory or register changes;
Level0CpuidView continues to omit those features. A native differential
census covers 182 register/memory encodings at three input patterns and
repeats each with the feature absent to prove refusal before mutation.
Separate witnesses cover alignment, cross-page faults, feature replacement,
and sized scalar destinations. The initial SSE3 witness failed with #UD.

POPCNT and SSE4.2 CRC32 execute as bounded scalar operations without vector
leaves or FXSAVE. F3 BSR now follows the guest LZCNT bit, falling back to BSR
when absent; its first production-path witness failed before implementation.
TZCNT/LZCNT also remain scalar. CRC32 uses the SDM's reflected Castagnoli
polynomial, independently compared against native results by the census.

The owner's #1469 review describes BMI/MOVBE/AES/PCLMUL implementations that
are absent from admitted main. Their encodings remain refused here, with an
explicit regression witness under Level0CpuidView. There is no scalar BMI or
MOVBE vector leaf to optimize on this base. Integrating those implementations
must preserve guest-feature admission and the scalar execution split; this
slice cannot qualify absent code. No CPUID bits for those extensions are added.
