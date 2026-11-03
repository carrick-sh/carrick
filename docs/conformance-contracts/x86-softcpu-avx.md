# Soft CPU AVX and AVX2 execution (#1435)

Contract `x86.softcpu.level0` covers the production `SoftCpu::step_block`
entry. The original AVX slice added execution and state; #1439 extends it with
v3 integer/FP and cryptographic instructions. The installed CPL0 fixtures retain
`Cpl0CpuidView`; v3 execution tests explicitly install a synthetic shared view.
The production shared-view switch is a separate draft layer (Refs #1472),
blocked on the MMX, CLFLUSH and SSE/SSE2 execution gaps in #1532.
The minimal Level0 profile remains available. Installed-view admission gates each checked
extension before vector controls, memory or destination publication. TZCNT
and LZCNT use the shared bit-scan helper, including BSF/BSR fallback when their
feature is absent. Existing x87, CX16 and legacy SIMD admission remains intact.

The semantic authority is Intel SDM Vol. 1 chapter 13 (XSAVE state), Vol. 2
VEX instruction definitions and exception classes, and a native x86 oracle.
Component 2 uses the shared CPUID geometry: 256 YMM upper-half bytes starting
at byte 576. The SDM authority is
[Volume 1](https://cdrdv2-public.intel.com/789574/253665-sdm-vol-1.pdf) and
[Volume 2](https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf). Save masks, initialization on restore, compacted headers and
MXCSR requests include AVX. Restore commits only after validating the image.

Iced decodes two- and three-byte VEX prefixes. Admission is restricted to
instructions whose feature requirements are AVX, AVX2, BMI1, BMI2, FMA,
F16C, LZCNT, MOVBE, AES or PCLMULQDQ in legacy or VEX encodings. Every admitted
instruction goes through a checked helper; none reaches unchecked block
copy-through. EVEX, FMA4, VAES-256 and VPCLMUL-256 remain refused.
VEX MXCSR instructions use the existing checked sensitive-instruction path.

Register and ordinary memory instructions use an immutable per-encoding
native leaf on the same-ISA AVX2 host. Construction and view replacement refuse advertised native capabilities when
the host lacks them, including AVX/AVX2. The checked leaf also refuses unavailable
host capabilities as a host translation error, never a silent test skip.
The leaf remaps explicit GPRs and memory operands to private storage and
loads implicit string-compare lengths separately. It preserves host FP controls and masks floating-point exceptions before
native execution. SysV vector registers are caller-saved; after capturing
guest state it returns with `vzeroupper`, without reloading host YMM registers.
Guest destination, arithmetic flags and memory publish only after checking
guest MXCSR exception masks. When underflow is unmasked, a second private
FTZ evaluation detects exact tiny intermediates, even if the final sum is
zero. Only its underflow status is used; it never accesses guest memory. Legacy SSE leaves YMM upper halves intact;
VEX.128 clears the architectural destination's upper half.

Masked memory and VSIB gathers resolve guest addresses through the existing
software MMU. Inactive lanes never access their addresses. Gather preserves
completed destination lanes and cleared mask elements across a later fault,
so resumption cannot replay completed reads. No guest address reaches a
native leaf. Ordinary stores validate the full span before publishing bytes.

Work is bounded by the architecture: at most 32 operand bytes or eight
four-byte gather lanes per instruction, and sixteen fixed vector registers
in the checked native transition, with at most two native evaluations when
underflow is unmasked. There is no polling or retry loop. Leaf
allocation is once per normalized encoding per CPU, independent of guest
address, and replay reuses RX code. Memory access uses the existing bounded
page-span walker. These are structural claims, not a throughput claim.

The register oracle enumerates VEX map/prefix/L/W/operand encodings and
compares whole XMM/YMM state, MXCSR, GPR outputs and arithmetic flags against
an independent native XSAVE/XRSTOR thunk. A separate memory-form oracle
compares operand bytes too (480 register forms and 482 ordinary memory
forms). Hand-written SDM witnesses cover distinct vvvv
sources, high registers, cross-page faults, masked-off absent pages, gather
fault progress, disabled controls, upper-half preservation and exact
unmasked underflow. The initial component-2 restore and VEX VPADDD witnesses
both failed on admitted main before implementation.

The worker's focused native and KVM results do not constitute signed HVF,
Docker differential, ecosystem-ratio or whole-stack acceptance. Those gates
remain explicit director/CI responsibilities on their supported hosts.

The minimal Level0 view retains a component bitmap of 3 and refuses XSETBV(7).
Explicit AVX test views expose component 2. Dynamic shared-profile CPUID
geometry follows the switch layer. KVM equality and the shared profile's
advertisement witness move with the switch layer; this slice makes no claim
that the installed restricted profile equals KVM. Construction and view replacement refuse unavailable native host
features before changing CPU state. Cached leaves obey replacement views.

BMI/LZCNT/MOVBE bypass vector controls, including TS/EM and disabled AVX state.
Legacy crypto obeys EM/TS/OSFXSR and aligned m128 requirements; VEX crypto obeys
AVX controls. F16C's exception class 11 suppresses #AC even for m64 operands.
Private GPR remapping preserves 16-bit destinations and register aliases,
including MULX's implicit RDX input and overlapping outputs.

The v3 witnesses cover integer results and defined flags, FMA fused cancellation
and rounding, F16C immediate/MXCSR rounding, [FIPS-197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) encryption/decryption and
key-assist answers, and all four carryless-multiply lane selectors. The initial
seven family witnesses failed at the production block entry before admission;
the native-return witness failed because the leaf ended in VMOVDQU rather than
VZEROUPPER. Native leaves retain the existing fixed per-instruction state and
operand bounds and immutable encoding cache; none adds polling or host services.

Tests clear individual installed
feature bits after warming a cached encoding and require #UD before #NM or
memory faults, with unchanged GPR and vector state. The default
`SoftCpu::new` retains the minimal Level0 profile.

With XCR0=7, VAES-256, VPCLMULQDQ-256, AVX-VNNI, SHA and ADX must produce
architectural #UD without advancing RIP or changing GPRs. A deliberate
allow-list widening to all five families fails every case (exit 101), since
host translation errors cannot substitute for guest #UD. F16C immediate
rounding is tested against a deliberately different MXCSR rounding mode;
imm8 bit 2 separately selects MXCSR.

Host admission also requires advertised SSE3, SSSE3, SSE4.1 and SSE4.2 before
constructing a CPU or replacing its view, because their checked legacy leaf
executes native instructions. POPCNT, LZCNT and CRC32 remain software operations.
The missing-feature constructor/replacement witness covers each requirement.
