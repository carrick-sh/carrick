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
RF is preserved in event images and forced for faults except instruction
breakpoints. PUSHF clears RF in its image. POPF uses the old IOPL to decide
whether IF is writable and cannot raise IOPL outside CPL0.

Item 4 already has production witnesses: e81335785 added
`idt_error_code_presence_and_pf_cr2_bits_match_sdm` (TS/#NM/CLTS recovery),
06068282d added `advertised_mmx_em_precedes_ts_and_operand_faults`, and
e8ad4cedf added `legacy_crypto_control_and_alignment_faults_are_atomic`.
No EM/TS or CLTS implementation changes are needed.

The existing contracts retain explicit unresolved software-carrier embed
and differential layers. This mechanical slice claims VM-free instruction
execution and real IDT delivery, not signed carrier promotion or performance.
