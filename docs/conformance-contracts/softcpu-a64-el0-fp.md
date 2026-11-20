# AArch64 soft EL0 floating-point execution

`softcpu.a64.el0-fp` covers the A64 software translator's guest FP
instruction admission. Arm ARM DDI0487 C4.1 and C7 specify allocation and
register semantics. A checked register-only instruction stays inside the
current block as one host instruction. An undefined encoding exits to
the architectural handler without running the word on the host.

## R3 instruction inventory

Before R3, the interpreter copied ordinary integer data-processing words,
DUP (general) and UMOV. It already routed SIMD/FP single-register, literal
and pair memory forms through Rust. The [production EL1 census](../softcpu-a64-census-2026-11-16.md)
records only 32 SIMD/FP memory words and no SIMD/FP computation in its
softfloat image. The generated loader/vector spans include four LDADD
instructions used by the EL1 clock path.

| Arm encoding group | R3 execution |
| --- | --- |
| Scalar FP compare, conversion, immediate, conditional and one/two/three source | Baseline FP copy-through |
| AdvSIMD scalar and vector data processing | Baseline copy, extract, table, permutation, immediate, reduction, pairwise, shift, indexed element, and one/two/three-register families |
| AdvSIMD/FP memory | Existing single-register, pair and literal handling plus multiple structures, selected lanes and replicated loads |
| CRC32 and CRC32C | Scalar Rust exit, independent of host CRC support |
| Extension families (crypto, FP16 arithmetic, dot product, RDM and later features) | Undefined exit |
| LSE | Undefined at EL0. Existing EL1 loader LDADD remains admitted. |

Blocks that use SIMD/FP preserve host vector and floating-point controls and
publish guest FPCR and FPSR across exits. This profile treats FP exception
enable bits as RAZ/WI. The Rust vector memory path translates the touched
span before publishing loaded registers or base writeback. It stages at most
64 bytes per structure instruction and consumes a single handler exit.
Prefetch is an architecturally permitted no-op.

The soft probe writes both capability words from `GuestCpuProfile` before
calling the shared Linux initial-stack builder. The baseline advertises
FP, ASIMD, CRC32 and CPUID. The software dispatcher uses that profile for
EL0 instruction admission and virtual ID-register reads. Its report counts
EL0 undefined-instruction exceptions delivered during each bounded run.

## R3b baseline census

Directory mode in `carrick debug a64-census` measures code intervals in
executable ELF sections. AArch64 mapping symbols distinguish instructions
from embedded data. In the absence of mappings, sized functions and
`.eh_frame` FDEs bound the measured intervals. These bounds can still include
inline data when mapping symbols have been stripped. The report gives the
number of measured words by source and the number of uncovered executable
section bytes.

The baseline decoder rejects optional SVE, crypto, LSE and MOPS instructions
and the profile withholds the corresponding capabilities. The census reports
rejections in known extension encoding spaces separately from unidentified
words. CHKFEAT executes as a plain NOP in this profile, as specified for
CPUs without FEAT_CHK, and never queries native host features.
