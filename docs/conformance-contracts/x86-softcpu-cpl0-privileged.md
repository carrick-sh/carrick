# Software vCPU CPL0 privileged instructions (`x86.softcpu.cpl0-privileged`, #668)

Surface: `carrick-softcpu-x86` (`MsrFile`, `GuestCpuidView`, `Level0CpuidView`,
`Cpl0CpuidView`, `privileged`, `SoftMachine`, and sensitive-exit wiring in
`context`, `cpu`, `decode`, and `mmu`). Authority: Intel SDM Vol. 2A/2B, Vol. 3A
Ch. 2/4/5/6/7, Vol. 4, AMD APM Vol. 2, and `carrick-x86` / `carrick-hal` CPL0
bringup (`X8664GuestArch::bootstrap_sysregs`, `BringupLayout`,
`write_fault_tables_with`, `FaultDoorbellRecord`, `check_vmx_guest_segments`).

Ring-0 instructions (`MOV CR0/CR2/CR3/CR4/CR8`, `MOV DR0..DR7`, `RDMSR`/`WRMSR`,
`LGDT`/`LIDT`/`LTR`, `SWAPGS`, `SYSRETQ`, `IRETQ`, `HLT`, `INVLPG`, `CLI`/`STI`,
`CLAC`/`STAC`, `XGETBV`/`XSETBV`, `CR4.TSD`-gated `RDTSC`, and `CPUID`) execute
against `MsrFile`, `GuestCpuidView`, and `SoftMmuMemory` without leaking host
registers or host `CPUID`; 32-bit compatibility-mode (`CS.L = 0`) returns fail
closed with `#GP` before mutating state. Each TLB-invalidating operation issues
at most one local `SoftTlb` flush (`flush_all` or `evict_va`). VM-free bindings
in `crates/carrick-softcpu-x86/tests/softcpu_cpl0.rs` cover `#GP`/`#UD`/`#PF`
ordering and `SoftMachine` CPL0 bootstrap parity with KVM; carrier and Docker
layers follow in later #578 slices.
