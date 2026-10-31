# x86 VMX segment entry (`x86.vmx.segment-entry`)

Authority: Intel SDM volume 3, §§26.3.1.1–26.3.1.4 (order 325384),
clean-room architectural checks, not host kernel source. Every long-mode
entry and restore must publish representable segment limits and matching
access rights, including a busy 64-bit TSS with byte limit 0x67 and G=0.
The VM-free validator visits exactly eight descriptors once; constructors
perform constant work and no I/O. Kernel and user entry/restore bindings
must pass the same checks. The red witness is a TR Granularity violation
on both shared states and the grouped KVM restore builder. Capability
fixed masks and interrupt injection remain backend responsibilities.
Intel live acceptance belongs to #253's GCP lane; AMD and signed HVF
runtime receipts are separate evidence and are not inferred from unit tests.
