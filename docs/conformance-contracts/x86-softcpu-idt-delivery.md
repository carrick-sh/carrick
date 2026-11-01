# Software vCPU 64-bit IDT exception delivery (`x86.softcpu.idt-delivery`, #669 slice 1)

Surface: `carrick-softcpu-x86` (`SoftMachine`, `SoftCpu`, `SoftCpuContext`,
`block`, `privileged`, and `mmu`). Authority: Intel SDM Vol. 3A Ch. 4/6/17/18,
Vol. 2A/2B (`INT n`, `IRETQ`, `POPFQ`, `CLTS`), and Vol. 3C §27.3.1.2 (VMX
guest segment-state checks).

`SoftMachine` delivers `#DE` (0), `#DB` (1), `#BP` (3), `#OF` (4), `#UD` (6),
`#NM` (7), `#DF` (8), `#TS` (10), `#NP` (11), `#SS` (12), `#GP` (13), `#PF` (14),
and `#AC` (17) through the guest's 64-bit `IDT` with SDM gate types (`0x0e`
interrupt vs `0x0f` trap), descriptor type/present/`DPL` checks (`INT n`/`INT3`
vs `ICEBP` and hardware exceptions), 16-byte stack alignment, unconditional
`SS:RSP` frame pushes, `TSS` `RSP0..RSP2` and `IST1..IST7` stack switching,
VMX-valid NULL `SS` loads, target-`CPL` stack push permissions, architectural
error-code presence, `#PF` `CR2` and `P`/`W/R`/`U/S`/`RSVD`/`I/D` bits,
`RFLAGS.AC` clearing on gate entry, `DR0..DR3`/`DR6`/`DR7`/`RF` debug state,
`CR0.EM`/`CR0.TS` `#UD`/`#NM` + `CLTS` recovery, and Table 6-5 `#PF`-then-`#PF`
`#DF` / triple-fault escalation in `crates/carrick-softcpu-x86/tests/softcpu_idt_delivery.rs`.
External interrupt delivery and recorded CPL0 fixture parity follow in slice 2 of #669.
