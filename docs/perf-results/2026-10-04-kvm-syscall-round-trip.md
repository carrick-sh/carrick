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
`52e0fcae214f0e80514f307cb2fd1288a4e451630e602ca000a147ddaf7d4f17`.
Release executable SHA-256:
`137022155c8ee75e9b49f4f3fa56f50c23269d1011a0997394745ed917242670`.

The example reuses `load_x86_elf_image` (`bringup_fns.rs:625`) and
`kvm_x86_engine::bring_up` (`:1395`). Each arm has one declared warmup and
nine serial, interleaved batches of 50,000 calls, pinned to willow CPU 2.
ELF/VM construction is outside timing; the final exit/checksum is inside.
Reported medians are **medians of batch means**, not per-call percentiles.
There is a 45 s fail-closed watchdog. Missing KVM, unexpected exits, incomplete
call counts or wrong checksums fail; no skips or retry-to-green.

| Arm | Measured path | Median batch ns/call | Min–max batch ns/call |
| --- | --- | ---: | ---: |
| Native | Cataloged `libc::getpid()`; verified uncached syscall in this glibc | 296.1 | 291.1–325.7 |
| Exit control | CPL3 SYSCALL → CPL0 OUT → KVM_EXIT_IO → userspace → KVM_RUN → constant return/SYSRET; direct `X86Vcpu::run`, no SET_REGS or engine CPU accounting | 19,959.3 | 18,424.7–20,138.8 |
| Host synthetic identity | Existing `SyscallTrap::next_syscall/complete_syscall`; native-to-canonical decode, CPU accounting and register completion; returns synthetic 123 | 21,432.9 | 19,607.1–21,651.1 |
| CPL0 synthetic identity | Benchmark-only LSTAR stub returns 123 without an exit for each getpid; one final exit_group doorbell | 24.2 | 21.1–27.5 |

The native control uses the cataloged libc identity operation rather than a raw
host-syscall escape. `objdump -d --disassemble=__getpid /lib/x86_64-linux-gnu/libc.so.6` shows `mov $0x27,%eax; syscall; ret`;
`objdump -T` confirms `getpid` aliases it on this installed glibc.

The host arm is about 72x native getpid on this host. The exit control
alone is about 67x. Neither performs full kernel dispatch. The CPL0 control
has no task graph, permission checks, fault handling, scheduler, signal gate
or real identity policy: it is a mechanism experiment, not an implementation.
It uses the same guest loop/checksum as the host arm. Native uses a Rust loop
and real host PID; no empty-loop subtraction was made.

Final raw output (committed to preserve the sample population):

```text
calls_per_batch=50000 batches=9 warmup_batches=1
arm=native_getpid samples_ns_per_call=[291.6, 291.4, 291.1, 293.5, 301.2, 325.7, 308.4, 312.3, 296.1]
arm=native_getpid min_ns=291.1 median_batch_ns=296.1 max_ns=325.7
arm=kvm_exit_control samples_ns_per_call=[18441.8, 18424.7, 18447.4, 20138.8, 19992.0, 19685.9, 20035.0, 20111.2, 19959.3]
arm=kvm_exit_control min_ns=18424.7 median_batch_ns=19959.3 max_ns=20138.8
arm=kvm_host_synthetic_identity samples_ns_per_call=[19646.5, 19607.1, 21651.1, 21229.4, 21453.8, 21432.9, 21474.2, 21226.5, 21514.5]
arm=kvm_host_synthetic_identity min_ns=19607.1 median_batch_ns=21432.9 max_ns=21651.1
arm=kvm_cpl0_synthetic_identity samples_ns_per_call=[22.0, 24.2, 21.1, 23.9, 26.8, 26.7, 24.2, 23.8, 27.5]
arm=kvm_cpl0_synthetic_identity min_ns=21.1 median_batch_ns=24.2 max_ns=27.5
checksums=pass host_getpid_forwards_per_batch=50000 cpl0_getpid_forwards_per_batch=0
```

## Verification

```sh
cargo build --release -p carrick-vmm-kvm --example syscall_round_trip > target/kvm-carrier-plan/build-benchmark.log 2>&1
CARRICK_RUN_ID=kvm-carrier-plan-20261004-libc taskset -c 2 target/release/examples/syscall_round_trip > target/kvm-carrier-plan/round-trip-libc.out 2> target/kvm-carrier-plan/round-trip-libc.err
cargo clippy -p carrick-vmm-kvm --example syscall_round_trip -- -D warnings > target/kvm-carrier-plan/benchmark-clippy-libc.log 2>&1
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
