# AArch64 soft EL0 floating-point execution

`softcpu.a64.el0-fp` covers the A64 software translator's guest FP
instruction admission. Arm ARM DDI0487 C4.1 and C7 specify allocation and
register semantics. A checked register-only instruction stays inside the
current block as one host instruction. An undefined encoding exits to
the architectural handler without running the word on the host.
