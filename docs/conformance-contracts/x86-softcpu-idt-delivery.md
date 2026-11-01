# Software vCPU 64-bit IDT exception and interrupt delivery (`x86.softcpu.idt-delivery`, #669)

Surface: `carrick-softcpu-x86` (`SoftMachine`, `SoftCpu`, `SoftCpuContext`,
`privileged`, `mmu`, and `build.rs` CPL0 image build). Authority: Intel SDM
Vol. 3A Ch. 4/6/11/18, Vol. 2A/2B (`INT n`, `IRETQ`, `STI`, `POPFQ`, `HLT`),
and `carrick-x86` / `carrick-x86-cpl0` (`write_fault_tables_with`,
`FaultDoorbellRecord`, `IRQ_HEADER_GPA`, `carrick_x86_page_fault_fixup`,
`carrick_x86_user_page_fault`).

`SoftMachine` delivers `#DE` (0), `#DB` (1), `#UD` (6), `#DF` (8), `#GP` (13),
`#PF` (14), `#AC` (17), and external interrupts (`32..=255`) through the guest's
64-bit `IDT` with SDM gate types (`0x0e` interrupt vs `0x0f` trap), 16-byte
stack alignment, `TSS` `RSP0` and `IST1..7` stack switching, VMX-valid NULL `SS`
loads, target-`CPL` stack push permissions, `CR2` and error-code bits, `RFLAGS.AC`
clearing on gate entry, `DR0..DR3`/`DR6`/`DR7`/`RF` debug semantics, `CR8`/`IF`
and one-instruction `STI` shadow masking, `HLT` wakeup, Table 6-5 `#DF`/triple-fault
escalation, and identical fault/IRQ execution on the compiled CPL0 fixture image
in `crates/carrick-softcpu-x86/tests/softcpu_idt_delivery.rs`.
