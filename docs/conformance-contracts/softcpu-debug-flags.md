# Software x86 debug and flags images (#1272)

Existing contracts `x86.softcpu.cpl0-privileged` and
`x86.softcpu.idt-delivery` own these true x86 ISA mechanics. Production
SoftCpu step_block and SoftMachine run witnesses cover fault RF, DR7
configuration admission, ICEBP DR6, and PUSHF/POPF images. Intel SDM Vol. 3B
§17.2.4 and §17.3.1.1 (chapter 18 in newer editions), and Vol. 2B PUSHF/POPF
are the authority. Only our code and Intel specifications were consulted.

All five issue1272 witnesses failed on GitHub main 87abfe9c5 before the fix.
Unsupported DR7 R/W or LEN fields raise #GP(0) without changing DR7, even
when a slot is disabled. This explicit software-CPU restriction avoids a
second memory-access instrumentation path. Instruction breakpoints remain
supported. Admission checks four fixed-size fields (one mask), independent
of guest memory size; exception-frame work and existing budgets are unchanged.

General-detect #DB carries its cause from instruction emulation to delivery;
sticky DR6 bits cannot classify a subsequent instruction-breakpoint fault.
RF is explicitly cleared in event images and forced only for faults except
instruction breakpoints. PUSHF clears RF in its image. POPF uses the old IOPL to decide
whether IF is writable and cannot raise IOPL outside CPL0.

Item 4 already has production witnesses: e81335785 added
`idt_error_code_presence_and_pf_cr2_bits_match_sdm` (TS/#NM/CLTS recovery),
06068282d added `advertised_mmx_em_precedes_ts_and_operand_faults`, and
e8ad4cedf added `legacy_crypto_control_and_alignment_faults_are_atomic`.
No EM/TS or CLTS implementation changes are needed.

The existing contracts retain explicit unresolved software-carrier embed
and differential layers. This mechanical slice claims VM-free instruction
execution and real IDT delivery, not signed carrier promotion or performance.

Review fix round (#2442): the shared IDT frame writer masks incoming RF before
applying the fault classification. This boundary also covers APIC interrupts
accepted before any instruction retires and double-fault escalation; clearing
RF only in retiring instruction paths would miss both. Frame construction and
its bounded work are otherwise unchanged.

Production run_to_vec_port witnesses start with RF=1 for INT3, INT n through
both interrupt and trap gates, TF single-step, ICEBP, external APIC delivery,
and #PF-to-#DF escalation. INT n, TF and ICEBP already clear RF upstream and
are non-regression witnesses rather than red witnesses on the reviewed head.
Fault/GD/instruction-breakpoint witnesses remain unchanged.

The decoder is hardwired to 64-bit mode: INTO is invalid (no #OF production
path), and 32-bit PUSHFD is unencodable. There is no NMI injection/delivery
entry point. No synthetic exception/helper calls stand in for those missing
paths. PUSHF's supported 16-bit and 64-bit encodings are witnessed with both
RF and VM on entry; those images already pass on the reviewed head. This
round makes no claim of 32-bit execution support. The CPL>0 POPF NT omission
is tracked separately in #2444.
