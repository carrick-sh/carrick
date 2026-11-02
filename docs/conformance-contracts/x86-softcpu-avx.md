# Soft CPU AVX and AVX2 execution (#1435)

Contract `x86.softcpu.level0` covers the production `SoftCpu::step_block`
entry. This slice adds execution and state without switching either default
soft CPUID view. The admitted shared v3 authority can enable XCR0 bit 2;
XSETBV retains its existing privilege, dependency and feature-mask checks.

The semantic authority is Intel SDM Vol. 1 chapter 13 (XSAVE state), Vol. 2
VEX instruction definitions and exception classes, and a native x86 oracle.
Component 2 uses the shared CPUID geometry: 256 YMM upper-half bytes starting
at byte 576. The SDM authority is
[Volume 1](https://cdrdv2-public.intel.com/789574/253665-sdm-vol-1.pdf) and
[Volume 2](https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf). Save masks, initialization on restore, compacted headers and
MXCSR requests include AVX. Restore commits only after validating the image.

Iced decodes two- and three-byte VEX prefixes. Admission is restricted to
instructions whose feature requirements are AVX or AVX2. Every admitted
instruction goes through a checked helper; none reaches unchecked block
copy-through. FMA, F16C, BMI and the CPUID switch remain the subsequent slice.
VEX MXCSR instructions use the existing checked sensitive-instruction path.

Register and ordinary memory instructions use an immutable per-encoding
native leaf on the same-ISA AVX2 host. Missing host AVX2 is an explicit host
translation error, not a guest instruction fault or silent test skip.
The leaf remaps explicit GPRs and memory operands to private storage and
loads implicit string-compare lengths separately. It saves/restores host
vector state and masks floating-point exceptions before native execution.
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

The refusal witnesses also cover both default CPUID views: leaf 0xD keeps
its component bitmap at 3 and CPL0 XSETBV(7) raises #GP with OSXSAVE enabled.
Gather and masked moves each raise #UD with either XCR0=3 or OSXSAVE clear,
without changing vector state. With vector state enabled, valid FMA, F16C,
BMI1, BMI2, VEX AES, VEX PCLMULQDQ and EVEX encodings remain refused.
Mutation checks independently changed each default bitmap to 7, moved each
software memory dispatch before the control checks, and removed the iced
feature filter. Each mutation failed its production-entry witness; restoring
the implementation restored the passes.
