# x86 signal FP state custody

`signal.x86.fp-custody` owns signal XSAVE save/restore for the admitted
XCR0=7 native lane. Authority: sigreturn(2), signal(7), and the existing
clean-room Linux XSAVE wire records in `carrick-abi`. The native/KVM SSE
witness failed before correction; it compares preservation across a handler
that overwrites XMM0 and checks both FP_XSTATE_MAGIC markers.

Entry, fault and IRQ captures initialize their 832-byte storage before XSAVE.
Delivery copies one bounded XSAVE image and emits the Linux software extent
descriptor. Restore validates lengths, feature bits, compact/reserved header
words, trailing magic and MXCSR before publishing the FP image or GPRs.
No wait, retry or allocation occurs. The deterministic bound is one fixed
832-byte capture initialization plus at most 836 FP wire bytes per delivery
or restore; the ucontext and GPR-frame copies are independently fixed-size.
ARM delivery remains host-owned; this does not enable an ARM signal frame.
The shared wire crate now builds for `x86_64-unknown-none`; host and ring
signal records refer to that one definition. Signed ARM acceptance and
runtime-ratio measurement remain outstanding.
