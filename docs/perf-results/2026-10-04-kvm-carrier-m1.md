# KVM carrier M1 — architecture seam and stopped CPU custody

2026-10-04; willow VM 210, nested KVM, Linux 6.1.0-49-cloud-amd64,
x86_64, 12 vCPU; rustc 1.96.0. No Docker or guest instruction execution.
Code snapshot: `5b52357d6f55d3e23704d8f5afec8612533e0c0e`.
Plan revision: `e921a36bf`; behavioral red: `25a697d76`.

## Scope and contracts

- `carrick-guest-arch/src/lib.rs:264`, `:339`, `:377`: no_std KernelArch,
  four sealed projections on Arch<Backend>, explicit hardware hooks, typed
  native entry/return, root/context, interrupt and owned crossing contracts.
  Completion tokens retain a backend-owned ticket. No Linux policy body.
- `carrick-hal/src/guest_arch_binding.rs:11`, `:29`: exact task/carrier/
  execution, MM/context generation and page-aligned CR3 data binding;
  inconsistent RSP/GPR images are rejected. Values confer no graph/MM rights.
- `carrick-x86/src/arch_context.rs:13`, `:61`: immutable checked V1 state;
  one snapshot converter shared with the existing engine. Resume payload
  preserves native/canonical syscall numbers and pending return/fork metadata.
- `carrick-vmm-kvm/src/carrier_cpu.rs:58`, `:96`, `:109`: owns a fresh stopped
  VM/vCPU; exact-task save, neutral reset and physical readback precede detach.
  Failed save/restore/audit poisons custody. Reuses grouped KVM restore;
  there is no exposed VM/vCPU handle or KVM_RUN. Unknown descriptor walks are
  diagnostics, never authenticated translation proof.
- `carrick-el1/src/sched/aarch64_context.rs:5`, `:17`, `:84`: extracted ARM
  frame/system-register/FP leaf. Same ABI, instruction bodies and audited FP
  symbol names. Hardware and fake backend share the frame helpers.

Witnesses refine `kernel.el1.task-load-entry` and
`kernel.syscall.captured-stack`: two distinct saved task contexts, exact
execution generation, SP/TLS/vector/root/restart preservation. M1 is a CPU
custody seam, not live Linux process or exhausted-pool acceptance. Those
executing contracts remain required in M2/M5; no new runtime is wired here.

## Red and mutation evidence

```
cargo test -p carrick-vmm-kvm --lib two_task_contexts_preserve_registers_tls_xsave_and_resume
cargo test -p carrick-el1 --lib arm_fake_backend_context_trace_is_unchanged
```

At `25a697d76`, both compile and exit 101: x86 refuses load(A); the existing
ARM FP-loss control saves zero vectors instead of A's tags. The latter is an
injected fault, not a claimed pre-existing ARM defect.

On the green implementation, separately mutate the TestIo write to corrupt
CR3 (`^= 0x1000`), FS base (`^= 8`) or YMM upper byte (`^= 1` at XSAVE_AVX_OFFSET).
The same x86 two-context command exits 101 in all three cases at load readback.
Remove each mutation; run the full gates below. Durable FaultIo tests also
inject root/FS/GS/FP corruption and partial failure at both load and neutral
reset (ten combinations); none can advertise idle or accept another task.
No retry, pool enlargement or timeout change.

Logs: `target/kvm-carrier-m1/{red-x86,red-arm,mutation-root,mutation-tls,mutation-fp}.log`.

## Verification on the restored implementation

| Command | Result |
| --- | --- |
| `cargo test -p carrick-guest-arch` | PASS: 1 unit, 1 private-seal compile-fail doctest |
| `cargo test -p carrick-el1 -p carrick-x86 --lib` | PASS: 185 EL1, 39 x86 |
| `cargo test -p carrick-vmm-kvm --lib` | PASS: 24 |
| `cargo test -p carrick-vmm-kvm --test carrier_cpu` | PASS: required /dev/kvm, full hardware readback A/B/A, 1 test |
| `cargo test -p carrick-hal --lib` | PASS: 150 |
| `just fmt-check` | PASS |
| `cargo clippy -p carrick-guest-arch -p carrick-hal -p carrick-x86 -p carrick-vmm-kvm -p carrick-el1 --all-targets --no-deps -- -D warnings` | PASS; pre-existing Linux config diagnostic for unreachable libc::proc_listallpids remains |
| `scripts/lint-domains.sh` | PASS: Semgrep, escape boundary and carrier-only process audits |
| `cargo build -p carrick-cli --no-default-features --features platform-linux` | PASS; existing Linux CLI warnings remain |
| `cargo check -p carrick-guest-arch --target aarch64-unknown-none-softfloat` | PASS: freestanding, no std/dependencies |
| `cargo build -p carrick-el1 --bin carrick-el1 --target aarch64-unknown-none-softfloat --release` | PASS |
| `cargo test -p carrick-el1-image --lib` | PASS: rebuilt packed image, FP instruction audit, embedded ABI/header |

The real KVM gate requires /dev/kvm and fails if absent; it is separate from
VM-free lib tests. It sets/reads registers only. Valid XSAVE state tags XMM
and AVX upper halves; the current V1 ABI is 832 bytes, not arbitrary extended
XSAVE. Every VM/vCPU is dropped by owned scope; no guest processes survive.

Artifact SHA-256 at the code snapshot:

| Artifact | SHA-256 |
| --- | --- |
| `target/debug/deps/carrier_cpu-5d336d3b00278e6d` | `4c1f35811e39aa91e9173f17a53b410b4ead93219f9f329baee83a50b7acb880` |
| `target/aarch64-unknown-none-softfloat/release/carrick-el1` | `8f5ae190a2800a14ea84c95acbbc37b422ad82682812c3087854ac12084e1c3b` |
| `target/debug/carrick` (compile-check only) | `d5ad210c9c540ace634179e769f464c5044a56706d0243c51d495c22865c1589` |

## Hand-off and exclusions

After `git fetch origin`, `git diff --name-only ad3e127a9 origin/work/n1`
was read fully at `8d5df2d2e0f235f9ad82ec2cd59dac13efcfb832`.
Existing ARM `sched.rs`, `sched/hw.rs`, `sched/tests.rs` and KVM's restore
helper are file-disjoint. No runtime, N1 owner/router/ABI, lifecycle, EL1
Cargo/lib or scheduler policy edits.

N1-touched mechanical merge points: `Cargo.lock`, HAL Cargo.toml/lib.rs new
interface dependency/export, and **one added path line each** in
`.semgrep/host-authority-escape-hatches.yml` and
`scripts/migrate/check-host-authority-escape-hatches.py`. The director
explicitly approved both audit registrations; adjacent entries are unchanged.

M2 takes the narrow common-entry/export/ISA-selection hand-off, binds the
four backend hooks into the common kernel and implements CPL0 native frames,
entry/return and exit retirement. ARM timer/TLBI/GIC/user-copy leaves remain
in their existing audited hw.rs/file.rs; N1-touched fault/memory/entry work is
deferred. The legacy ThreadedEngine audit still refuses x86; this stopped
seam is not a claim that runtime detach or OCI works. M3 supplies authenticated
physical/MM ownership and a maintenance root; M5 supplies issued execution
claims/leases. No CPL0 GS shadow/TSS/APIC context or full-XSAVE feature-policy
claim is made for the current V1 image.

M2's first shared call is set_robust_list(head,24), approved by the director:
observe two stored heads through the common kernel and EINVAL(22) without
state change for invalid length. lseek follows N1 cursor hand-off. A later
post-N2 common-kernel package rename is already in the plan.

Signed ARM runtime, KVM executing bindings, OCI, exhausted-pool and ≤2x
Docker workload acceptance belong to later milestones; none is inferred from
these CPU readback tests.

## Broader host acceptance remains red

`just accept --phase host --receipt target/kvm-carrier-m1/accept-host.json`
exits 1 at clean `5b52357d6`; overall FAIL, six failed steps. Raw step logs:
`target/el1-gate/5b52357d6/`. These are not waived or folded into M1's greens.

| Step | Failure |
| --- | --- |
| just test-kernel | 2300 pass; eight failures, names exactly equal to the earlier `682a30d6d` planning receipt (seek/backing, ICMP/Unix metadata, edge/host-I/O windows); one existing ignored test |
| just test | Unchanged carrick-vfs tests fail to compile: HostFsBackend/host_backend absent on Linux |
| HVF lib | Unchanged macOS dependencies/imports and siginfo API do not compile on Linux |
| just clippy | Unchanged carrick-vfs host_open/mode/dead-code Linux diagnostics |
| just lint-domains | Existing vcpu-loop.json fingerprint drift at binding.rs ProductionHvpatchLoopJob::service_outcome #1; the narrower escape/domain source audits pass |
| closure-probe-inventory | Existing default platform-macos CLI build refuses Linux; feature-closed platform-linux build passes |

The four build/test failures above also occur in the earlier planning receipt;
the runtime fingerprint drift was recorded before M1. No excluded file was
changed to make a broad gate green. The receipt is review-ready evidence for
the fenced M1 landing, not whole-repository acceptance.
