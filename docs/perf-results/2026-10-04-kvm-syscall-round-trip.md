# Nested KVM syscall round trip — 2026-10-04

Planning evidence for the [KVM carrier plan](../superpowers/plans/2026-10-04-kvm-hvpatch-carrier.md).
This measures transport controls, not Linux conformance, an OCI carrier,
bare-metal KVM, or the ≤2x Docker gate. No production code changed.

## Host and method

Willow VM 210 is itself a Proxmox/KVM guest: **nested KVM**, Debian 12,
`6.1.0-49-cloud-amd64`, 12 vCPU, AMD Ryzen 7 7840HS, `/dev/kvm` accessible.
The AMD machine uses nested paging rather than Intel EPT. Outer-host load,
CPU scheduling and virtualization configuration were not controlled. The
first capture had a 21.386 µs engine median; do not pool it with the final
four-arm capture. These observations suggest the exit floor matters here;
they cannot establish a bare-metal floor or a workload speedup. Use nested
numbers as conservative planning upper estimates for correctness work, not
as a guaranteed upper bound on every future machine or workload.

Source base: `00cd94614`. Benchmark:
`crates/carrick-vmm-kvm/examples/syscall_round_trip.rs`. Source SHA-256:
`7bf7981721221b29023975baf6f106bdffe008db7dd830e4aaa19dbeb2a566a1`.
Release executable SHA-256:
`97b575edefd70f0939c9ae2b95a02bac7b304441138014dc8dc5b9fd6685d450`.

The example reuses `load_x86_elf_image` (`bringup_fns.rs:625`) and
`kvm_x86_engine::bring_up` (`:1395`). Each arm has one declared warmup and
nine serial, interleaved batches of 50,000 calls, pinned to willow CPU 2.
ELF/VM construction is outside timing; the final exit/checksum is inside.
Reported medians are **medians of batch means**, not per-call percentiles.
There is a 45 s fail-closed watchdog. Missing KVM, unexpected exits, incomplete
call counts or wrong checksums fail; no skips or retry-to-green.

| Arm | Measured path | Median batch ns/call | Min–max batch ns/call |
| --- | --- | ---: | ---: |
| Native | Raw `libc::syscall(SYS_getpid)`; no cached libc getpid | 294.5 | 291.0–317.9 |
| Exit control | CPL3 SYSCALL → CPL0 OUT → KVM_EXIT_IO → userspace → KVM_RUN → constant return/SYSRET; direct `X86Vcpu::run`, no SET_REGS or engine CPU accounting | 18,491.6 | 18,319.4–18,735.1 |
| Host synthetic identity | Existing `SyscallTrap::next_syscall/complete_syscall`; native-to-canonical decode, CPU accounting and register completion; returns synthetic 123 | 19,729.9 | 19,529.8–19,889.6 |
| CPL0 synthetic identity | Benchmark-only LSTAR stub returns 123 without an exit for each getpid; one final exit_group doorbell | 23.5 | 20.4–25.3 |

The host arm is about 67x native raw getpid on this host. The exit control
alone is about 63x. Neither performs full kernel dispatch. The CPL0 control
has no task graph, permission checks, fault handling, scheduler, signal gate
or real identity policy: it is a mechanism experiment, not an implementation.
It uses the same guest loop/checksum as the host arm. Native uses a Rust loop
and real host PID; no empty-loop subtraction was made.

Final raw output (committed to preserve the sample population):

```text
calls_per_batch=50000 batches=9 warmup_batches=1
arm=native_raw_getpid samples_ns_per_call=[299.0, 294.5, 296.5, 296.5, 291.0, 317.9, 291.9, 293.3, 294.4]
arm=kvm_exit_control samples_ns_per_call=[18440.3, 18590.4, 18491.6, 18403.5, 18319.4, 18396.8, 18497.7, 18493.4, 18735.1]
arm=kvm_host_synthetic_identity samples_ns_per_call=[19626.2, 19889.6, 19813.1, 19802.5, 19637.2, 19729.9, 19793.1, 19667.3, 19529.8]
arm=kvm_cpl0_synthetic_identity samples_ns_per_call=[25.3, 24.7, 25.2, 24.8, 20.7, 20.4, 23.0, 23.5, 23.2]
checksums=pass host_getpid_forwards_per_batch=50000 cpl0_getpid_forwards_per_batch=0
```

## Verification

```sh
cargo build --release -p carrick-vmm-kvm --example syscall_round_trip > target/kvm-carrier-plan/build-benchmark.log 2>&1
CARRICK_RUN_ID=kvm-carrier-plan-20261004-final taskset -c 2 target/release/examples/syscall_round_trip > target/kvm-carrier-plan/round-trip-final.out 2> target/kvm-carrier-plan/round-trip-final.err
cargo clippy -p carrick-vmm-kvm --example syscall_round_trip -- -D warnings > target/kvm-carrier-plan/benchmark-clippy.log 2>&1
```

All exit zero; benchmark stderr is empty. Clippy still reports existing
workspace warnings; no warnings-free workspace claim. The foreground
benchmark terminates and destroys its own VMs; its temporary ELF is removed
by an owned guard. No child processes are created. This is green baseline
characterization, **not red-first proof of a carrier implementation**.
The separate carrier milestones must supply their own red witnesses.

Clean-room references: existing Carrick byte emitters and the
[Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
Volume 2 instruction encodings; KVM ioctl fields/numbers from installed
`/usr/include/linux/kvm.h` definitions, with
[ioctl(2)](https://man7.org/linux/man-pages/man2/ioctl.2.html) and
[mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html).
No kernel implementation source, copied KVM API prose or Docker was used.
