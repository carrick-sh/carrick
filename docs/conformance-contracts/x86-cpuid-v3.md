# x86-64-v3 guest CPUID view (`x86.cpuid.v3`)

Authority: System V AMD64 psABI §3.1.2 (`x86-64-v3` microarchitecture level) and
Intel SDM volume 2A `CPUID` / `XGETBV` specification (order 325383), clean-room
architectural rules without host kernel or emulator implementation source.

`carrick_x86::GuestCpuidView` defines the single 11-entry `CPUID` and `XCR0 = 0x7`
(`x87 | SSE | AVX`, 832-byte legacy+header+YMM XSAVE frame) contract shared between
the KVM lane and the x86 soft-CPU lane (#578, owner decision 3):

- **Exact `x86-64-v3` feature set**: `CMOV`, `CX8`, `FPU`, `FXSR`, `MMX`, `SYSCALL`,
  `SSE`, `SSE2`, `CX16`, `LAHF_LM`, `POPCNT`, `SSE3`, `SSE4_1`, `SSE4_2`, `SSSE3`,
  `AVX`, `AVX2`, `BMI1`, `BMI2`, `F16C`, `FMA`, `LZCNT`, `MOVBE`, `XSAVE`/`OSXSAVE`,
  plus the IA-32e / CPL0 baseline Carrick programs (`LM`, `NX`, `PGE`, `PAT`, `TSC`,
  `MSR`, `PAE`, `APIC`, `CLFSH`, `SMEP`, `SMAP`, `INVTSC`).
- **Zero non-v3 or host-identity leakage**: `AVX-512`, `AMX`, `SHA`, `AES`,
  `PCLMULQDQ`, `RDRAND`, `RDSEED`, `ADX`, `FSGSBASE`, `PKU`, `LA57`, `UMIP`,
  `XSAVEOPT`/`XSAVEC`/`XSAVES`, `TSC_DEADLINE`, `HYPERVISOR` (`CPUID.01H:ECX[31]`),
  `0x4000_0000..0x4000_ffff` hypervisor leaves, `RDTSCP`, `PDPE1GB`, processor brand
  strings, and AMD SEV leaves are never advertised. Leaf `0x16` is installed as an
  all-zero maximum basic leaf so out-of-range basic, hypervisor, and extended probes
  return `(0, 0, 0, 0)` under Intel SDM `CPUID.00H:EAX` fallback rules.
- **Host qualification and coherent TSC**: `GuestCpuidView::qualify_supported`
  validates host `KVM_GET_SUPPORTED_CPUID` once per VM in bounded time, refuses hosts
  missing any required `x86-64-v3` or CPL0 capability (`ENOTSUP`), clamps
  `MAXPHYADDR` to `min(host_max_phy_addr, 48)` (requiring `>= 36`), stamps each
  vCPU's `APIC ID` into `CPUID.01H:EBX[31:24]`, and binds `CPUID.15H` (`1`, `tsc_khz`,
  `1000 Hz`) to the exact `KVM_GET_TSC_KHZ` rate published to `KvmVm::x86_tsc_hz()`
  and guest vDSO `CLOCK_MONOTONIC`.

VM-free proofs live in `carrick_x86::cpuid::tests` (including the red-first raw host
pass-through negative control and host qualification refusal/scrubbing suites). Live
KVM guest execution proofs live in `carrick_vmm_kvm::kvm::x86_tests` and
`crates/carrick-vmm-kvm/tests/cpuid_v3_kvm.rs` (`Cpl0Carrier` 2-vCPU ring-3 `CPUID` +
`XGETBV(0)` + `AVX2`/`BMI1`/`BMI2`/`LZCNT`/`POPCNT` and `carrick-vmm-kvm run-elf`
including `MOVBE`) and are gated on real `/dev/kvm` in the merge-queue `kvm-tests`
lane (`NEW=[]`).

The table test and both KVM fixtures assert architectural feature bit values
independently of the production masks. Comparing observations only with
`GuestCpuidView` would allow a mistakenly expanded mask to bless itself in both
the installed table and its expected answer. The live fixtures additionally
check the pinned processor signature.

The raw-host negative control is a passing test that expects rejection; it is
not itself a red execution of the pinned-table test. Record a failing run and
its implementation variant separately from the subsequent green run. A
compile-only KVM fixture result is also not a live verdict: acceptance still
requires the merge queue's `kvm-tests` and `kvm-gate` receipt with `NEW=[]`.
