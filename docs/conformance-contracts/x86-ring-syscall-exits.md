# `kernel.x86.ring-syscall-exits`

A syscall the x86 CPL0 ring serves runs entirely in the guest kernel, so it
must cost the host no VM exit. #2679 found every ring syscall on an AMD (SVM)
host taking about 100 us, ~250x native: each guarded user access read CR4
before STAC and before CLAC, the MMU's live-root check read it again, and SVM
intercepts every guest CR4 read. A nested host without decode assists (the hz
worker and CI KVM lanes) also decodes each intercepted read in software.

## Invariant

CR4 is read from hardware at most once per CPU binding
(`carrick_el1::isa::x86::control::Cr4`, stored in `CpuBinding::cr4_snapshot`).
The stopped host programs CR4 before a vCPU's first instruction (production
SMEP/SMAP, the fixture's `enable_smap`), and the guest kernel never writes it.

## Witness

`carrick-vmm-kvm/tests/cpl0_syscall_exits.rs` boots the production carrier,
binds a census of its two vCPUs' in-kernel KVM statistics
(`Cpl0Carrier::kernel_stats`, `KVM_GET_STATS_FD`), and runs the root fixture
`native_root_syscall_exits.S` at 256, 2048 and 16384 rounds of `getppid` and an
`rt_sigprocmask` copy-out. Fixed boot work cancels between scale points; the
slope budgets are:

- `exits(n) - exits(256) <= (syscalls(n) - syscalls(256)) / 64` (host-timer and
  preemption exits scale with time, not calls);
- `insn_emulation(n) - insn_emulation(256) <= (syscalls(n) - syscalls(256)) / 1024`.

The red is SVM-only. VMX returns CR4 reads from its read shadow without an
exit, so an Intel host passes before and after the fix.

`CARRICK_KVM_STATS=1` on any `carrick run` also prints the summed in-kernel
counters of every vCPU the process created
(`[carrick-kvm-kernel-stats ...]`), beside the existing userspace exit counts.
