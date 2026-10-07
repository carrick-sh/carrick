# Standalone x86 KVM run-elf retirement

The production x86 Linux CLI lane uses the shared `carrick-el1` kernel at
CPL0, with receipt backend `kvm-x86-cpl0`. The former per-process `KvmVmm`
and its host `Pml4Manager` editor are removed. KVM register ioctl marshalling
moves unchanged into `vcpu_x86`; this adapter owns no RAM or page tables.
The bhyve/NVMM engines and their shared `carrick-x86` behavior are retained.

The applicable production contract is `x86.carrier.cli-run`. Native Linux
execution of each exact ELF supplies output and exit-status authority. The
retirement invariant is zero standalone KVM x86 service-loop callers and
zero host PTE editors in the deleted engine. The standalone polling contract
`x86.run-elf.poll` continues to cover bhyve/NVMM and its existing VM-free
budgets; KVM's migrated live binding belongs to the production contract.

## Removed executable surfaces

| Surface | Disposition |
| --- | --- |
| `carrick-vmm-kvm run-elf <x86-elf>` | Removed execution entry. The executable remains for byte-identical ARM run-elf; its x86 main exits 1 and names `carrick run --platform linux/amd64` and the shared CPL0 kernel. |
| `examples/syscall_round_trip.rs` | Deleted. It benchmarks the retired two-instruction LSTAR/host-service boundary; that ratio does not describe shared-kernel execution. No replacement performance claim. |
| `src/run_elf_x86.rs` | Deleted; no KVM caller of the shared standalone service loop remains. |
| `src/kvm_x86_engine.rs` | Deleted per-process VM, RAM, host PTE authoring, host-fork rebuild and bring-up. Register-only functions retained in `src/vcpu_x86.rs` for carrier custody and boot. |
| `src/guest_setup_x86.rs` | Deleted identity-layout RAM builder, layout-only constants and hand-coded blob. Stopped-CPU layout lives with its register adapter; CPL0 boot owns production layout. |

## Every removed or migrated test

| Previous test | Replacement or reason |
| --- | --- |
| `live_vcpu_x86::test_m01_syscall_round_trip` | CLI `x86_kvm_run::mounted_static_x86_elf_writes_hello_and_exits_seven_through_shared_kernel`: exact hello output and exit status, native ELF authority, production CPL0 receipt and shared-kernel entries/forwards. It also proves nonzero guest exit propagation. |
| `live_vcpu_x86::test_m2_musl_static_hello` | CLI `x86_kvm_run::musl_static_hello_runs_through_shared_kernel`: same Rust/std musl source and committed expected bytes, rebuilt in a private temporary directory, native execution plus production CPL0 receipt. Missing fixture build is a failure rather than a silent skip. |
| `guest_setup_x86::tests::gdt_selector_encoding` | Moved to `vcpu_x86::tests`; preserves STAR-derived selector checks. |
| `guest_setup_x86::tests::segment_type_accessed_bits` | Moved to `vcpu_x86::tests`; asserts the actual shared segment-state values used by the adapter, including accessed bits. |
| `guest_setup_x86::tests::cr0_cr4_efer_bit_patterns` | Moved to `vcpu_x86::tests`; preserves bootstrap control-register checks. |
| `guest_setup_x86::tests::sfmask_masks_interrupts` | Moved to `vcpu_x86::tests`; preserves syscall-entry IF masking check. |
| `guest_setup_x86::tests::high_region_window_covers_full_mmap_arena` | Dropped with the private identity-layout RAM builder it tested. Production carrier memory uses typed custody/backing registration, already covered by `carrier_memory` and `cpl0_initial_mm`. |
| `guest_setup_x86::tests::high_region_window_preserves_shared_aperture_kind` | Dropped with the same deleted RAM builder; its standalone host `WindowKind` projection is not a CPL0 interface. Carrier-memory ownership/alias tests remain. |
| `guest_setup_x86::tests::m01_blob_msg_offset` | Dropped with the hand-coded blob; the CLI fixture is executed natively and through CPL0 with exact output checks, which proves its message addressing. |

No tests were defined in `kvm_x86_engine.rs`, `run_elf_x86.rs` or the deleted
example. Existing carrier CPU readback, two-context VM-free custody and CPL0
entry/lifecycle/progress/MM tests remain. A new
`retired_x86_entry::standalone_x86_entry_names_shared_kernel_replacement`
checks the old executable's precise refusal and replacement message.

## Evidence

On pre-retirement `afd08480f`, the refusal regression exits 127 after trying
to load `missing.elf`, versus required retirement exit 1. The structural red
audit finds the legacy `edit_page_tables` implementation, its six mutation
call sites, `impl X86Vmm for KvmVmm`, bring-up callers and run-elf entry.
Logs are under `target/x86-legacy-retire/` on the worker host.

Final focused gate results and source revision are recorded in the draft PR.
Linux worker scope excludes Docker and signed HVF acceptance; the director
owns those higher-layer gates and full stacked-batch acceptance. This
retirement does not claim full x86 conformance or production readiness.

The final rebase preserves shared-kernel `7cfff5918`'s separate initial-image
alias and typed kernel region. The shared production-backing census correction
is cherry-picked from `1eed7075e`: four retained slots, exact fixed supervisor
bytes, and variable initial bytes checked at three sizes. Rebase testing also
caught TLS GET copyout walking initial-MM tables through the old direct alias
(`CR2=0xffffffff94002000`, fatal page-fault fixup). The x86 permission walker
now reads those tables through the retained initial-image alias, preserving its
four-level permission checks and the bootstrap fixtures' direct window. The
same live TLS test is green after rebuilding; musl still fails at `poll` (7).
Fresh focused logs and the gate manifest are in
`target/x86-legacy-retire/final/` on `carrick-vm`.

The standalone table-alias correction shares typed `FrameGpa`/`KernelVa`
resolution between initial-MM construction and user permission validation.
Its VM-free four-table walk was red through the old alias, then green with
read-only intermediate descriptors, write refusal and a four-load bound.
The syscall declarations now live in the shared `carrick-syscall-abi` crate,
adapted from `1127a5eff`; host ABI and guest personality re-export that one
table. The fork branch's absent process/MM implementations are not imported.

## TLS prerequisite found by the migration

The migrated musl test first refused native syscall 158 (`arch_prctl`) on
PR #81 head `6fade63a8`; native execution succeeded. Linux policy now lives
in `personality/x86_native`, classified through the same no_std syscall-table
source used by `carrick-abi` and the guest personality. Neutral x86 context
leaves provide typed TLS reads and edits through a task-bound authority.
FS/GS SET edits the typed parked-context TLS projection and writes FS_BASE
or the user KERNEL_GS_BASE before the same task resumes. GET uses the existing
exact-task guarded copyout. CPL0's GS binding stays active during handling.

The [arch_prctl manual](https://man7.org/linux/man-pages/man2/arch_prctl.2.html)
and native Linux are the semantic authority. On this host, invalid GET
pointers return errno 14, supervisor SET addresses return errno 1, and unknown
operations return errno 22. Native CPUID GET returns 1 and SET returns errno
19; the CPL0 lane keeps native CPUID enabled and lacks CPUID faulting.
The live TLS fixture checks FS/GS loads and GETs, failed SET preservation,
GET errno 14 and unknown errno 22, with exactly two host forwards (write and
exit). The VM-free context edit was red before the leaf existed.

The production initial lane still lacks `ZoneRecord` custody. Its private
TLS projection never becomes a runnable scheduler context; full production
scheduler custody remains an x86-run open item. This change does not invent
another task-context registry.

The personality boundary gate was red for eight Linux facade references in
the neutral context module. Moving Linux operation/errno handling and GET
copyout into the personality made the unchanged boundary check green.

## Preserved red dependency

With TLS implemented, the same musl fixture exposed native `set_tid_address`
(218). The shared personality now registers the typed user pointer in the
calling thread's existing lifecycle control slot and returns its Linux-visible
TID, as specified by [set_tid_address(2)](https://man7.org/linux/man-pages/man2/set_tid_address.2.html).
It authenticates a born-in-zone pool entry and incarnation separately
from that visible TID. A VM-free red-first test registers after clone without
`CLONE_CHILD_CLEARTID`, then exercises existing shared `serve_exit`: clear
before one wake and retirement, with another MM untouched. The ARM entry
routing remains unchanged.

A second red-first test caught an adapter return bypassing pending-work
completion. The x86 setup call now routes through the same shared dispatcher
admission/completion owner, counts once and retains its original argument when
host work is pending; ARM's ordinal routing stays unchanged.

The migrated musl CLI test is explicitly ignored with a PR #81 dependency
reason; it remains a nonblocking tracked red, and the pre-translation receipt
records the first refusal at native `poll` (7). Poll now selects the canonical
ppoll handler with an integer-timeout shape tag and shared conversion; this
alone cannot make musl run before the production host dispatcher is bound.

The complete lost standalone startup/service surface belongs to
[PR #81 and the x86-run follow-up](https://github.com/carrick-sh/carrick/pull/81):
read, writev, close; brk; anonymous mmap, munmap and mprotect; rt_sigaction,
rt_sigprocmask and sigaltstack; poll/ppoll; tkill (the former abort path exits
134); vDSO publication and `AT_SYSINFO_EHDR`; and terminal clear-tid custody.
Rust/std musl startup also reaches rt_sigaction(13), mmap(9), mprotect(10)
and sigaltstack. It always registers set_tid_address, so initial host exit
currently refuses rather than pretending to clear/wake a pointer without
scheduler/futex custody. These shared families are not implemented here.

`decode_x86_64` must retain argument and output shapes when dispatch is bound:
x86 `epoll_event` is packed into 12 bytes, unlike ARM's layout; poll(7) carries
signed integer milliseconds, unlike ppoll(271)'s timespec pointer. A direct
poll-to-ppoll number mapping is invalid. The remaining legacy shape audit is
[x86-legacy-syscall-audit.md](x86-legacy-syscall-audit.md).

The required `just test-kvm` gate runs CLI hello and TLS, refuses a missing or
inaccessible `/dev/kvm`, and is wired into linux-portable acceptance and both
KVM workflows. The musl ignore is deliberate and names PR #81.
