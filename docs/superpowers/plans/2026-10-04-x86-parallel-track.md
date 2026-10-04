# x86/CPL0 work parallel to N1

Planning audit, 2026-10-04. **Dispatch I1–I3 below from main now as bounded
hardware/adapter witness improvements. Hold production M3, shared M4, M5 and
M6 at the N1 owner boundary.** There are not three independent production
milestones available: the useful parallel work strengthens already-landed
x86 leaves without creating another Linux personality or memory owner.
No implementation, new test execution, carrier acceptance or cost improvement
is claimed by this document.

## Evidence and scope

- Main/worktree source is frozen at `b1167c6e1` (`work/x86-audit`). All bare
  `path:line` citations below refer to that commit; paths are repo-relative.
- Fetched with `git fetch github pull/7/head:pr7`; read the body, comments,
  source and plan of [draft PR #7](https://github.com/carrick-sh/carrick/pull/7),
  head `786f6f4b3cd001e28d89d15b81e0c3cb8c04de34`. Its GitHub base is `main`,
  but its implementation stack starts from N1 `09fff7bfa`. `PR7:path:line`
  means `git show pr7:path | nl -ba`, not the file on main.
- `P7` below abbreviates
  `PR7:docs/superpowers/plans/2026-10-04-kvm-hvpatch-carrier.md`.
  The latest x86 handoff is in this **kvm-named** plan, especially lines
  546–655; searching only filenames containing `x86` misses it.
- Read the root rulebook, conformance-contract skill,
  [contracts](../../conformance-contracts.md),
  [native-owner plan](2026-10-02-el1-native-ownership.md), and active
  [controller](2026-09-26-el1-completion.md). The older controller's deferred-x86
  language is superseded for this task by the owner's explicit coalesced,
  CPL0-first ruling, recorded at P7:12–25. Keep the existing common kernel
  package during N1/N2; no second personality, host-dispatch-first carrier or
  per-call semantic fallback.
- The director supplied and confirmed the reservation authority during this
  audit: `/Volumes/carrick/dev/n1-audit-report.md:64–77`, particularly line 75.
  It audits N1 `4f459db98e99ac1c7faa2395be8aa6f399bf0263`, a different snapshot
  from PR7. Report SHA-256:
  `7c8e1cee576ee12596b21a0c0cceeea1aa704e274729cade35a8db263c9e96e9`.
  Its reservation list is reproduced below so this plan does not require
  access to that machine-local report. Its historical test claims are not
  fresh N1 acceptance evidence.

`INDEPENDENT` means a narrowly specified change can be reviewed and landed on
main without importing N1; it still needs its own red/green and landing gates.
`N1-DEPENDENT` includes work that can be explored on a stack but cannot land as
an independent production conversion. `NEEDS-OWNER-DECISION` identifies scope,
platform or interface choices for which this audit supplies no authorization.

## N1 exclusion fence

Reserve the following for the N1 driver/integrator (brace groups enumerate
files, not permission to edit neighboring files):

- `crates/carrick-aarch64/src/{engine,stage1_authority,user_transfer,vmm}.rs`;
  the owner ABI in `crates/carrick-el1-abi/src/`.
- `crates/carrick-el1/src/personality/mm_portal/{production,tests}.rs`;
  `crates/carrick-guest-mem/src/{lib,prepared}.rs`.
- `crates/carrick-vmm-hvf/src/trap/{foreign_mm,sparse_materialization,user_transfer,carrier_custody}.rs`
  and `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`.
- `crates/carrick-kernel/src/dispatch/mem/{anonymous,mmap,delegated_tests}.rs`;
  the driver's edited kernel buffer/network/continuation files;
  `crates/carrick-mem/src/memory.rs`.
- Runtime binding/signal/wrapper files, shared scheduler wait files, embed
  copyout fixtures, and inventories. The report names those last categories
  without a complete path expansion: their exact expanded list is **UNKNOWN**.
  Exclude the entire runtime, kernel, shared scheduler, embed and inventory
  surfaces from this parallel dispatch instead of guessing the missing paths.

The director additionally confirmed that anything shared with these files or
with the arch-neutral owner seam is N1-dependent. This plan therefore also
excludes all EL1 common exports, allocator, fault, reservations, fork portal,
object-wait code, common ABI/architecture traits, and ARM MMU implementations.
No independent worker changes Cargo/module exports or contract registries as
an incidental dependency. Any newly discovered need to do so returns to the
integrator. This stronger fence also avoids N1's P1–P4 leaf packages.

## Source inventory: present code versus production reachability

| Surface | File:line evidence and what it establishes | Limit |
| --- | --- | --- |
| Shared x86 engine | `crates/carrick-x86/src/engine.rs:175` defines `X86EngineCore<V>`; `:1040–1069` receives VMM syscall exits, normalizes the native frame and returns calls to host dispatch. `crates/carrick-x86/src/vmm.rs:224` supplies the backend trait. | This existing host trap path is not the CPL0-first carrier. `engine.rs:1498–1501` explicitly refuses executor-boundary audit authority. Do not turn that refusal into success to enable OCI. |
| x86 CPU custody | `crates/carrick-x86/src/arch_context.rs:13–39` binds native state to `GuestArchBinding`; `crates/carrick-vmm-kvm/src/carrier_cpu.rs:48–55,96–134` implements Idle/Loaded/Poisoned custody with write/readback and exact-task detach. `tests/carrier_cpu.rs:60–72` round-trips two stopped task images. | `carrier_cpu.rs:64–66` explicitly calls this a stopped hardware witness. No guest instruction, persistent executor or task scheduling is proved by that test. |
| Native CPL0 ABI | `crates/carrick-x86/src/cpl0_entry.rs:18–37` is the native frame; `:40–50` maps only native 273 to canonical 99; `:55–62` validates user return targets/flags. | Every other ordinal remains unported. This is not a general Linux syscall decoder or fake ARM frame. |
| Thin CPL0 image | `crates/carrick-x86-cpl0/src/entry.rs:8–23` rejects allocations; `:41–89` supplies SYSCALL/SWAPGS/IRETQ; `:108–159` invokes the common route, counts completion, and separates forward/control/work exits. `build.rs` and `link.ld` package this image. | `:145–147` forwards then halts on an unported call. Shared production MM and allocator paths are not enabled by this image. |
| M2 common helper | `crates/carrick-el1/src/personality/common_entry.rs:35–76` admits an issued task and calls the existing `thread_setup::set_robust_list`. `thread_setup.rs:44–46,87–92,123–136` checks the setup gate, validates full-width length 24 and publishes the head once without dereferencing it. `personality/lifecycle.rs:169` calls the same helper from ARM. | Main contains the M2 series through `097559be9`; its tip reviews bootstrap authorities, while earlier commits implement serving. The shared helper is reusable code already landed, not permission for parallel edits to EL1. |
| KVM CPL0 binding | `crates/carrick-vmm-kvm/src/cpl0_boot.rs:99–119` owns two stopped/run-controlled vCPUs, one VM and retained RAM; `:422–495` observes serving/control events. `tests/cpl0_entry.rs:45` and `:116` test two tasks and kicks. | Bounded fixture, not OCI or production MM ownership (`cpl0_boot.rs:1–3`). Tests are Linux/x86-gated (`tests/cpl0_entry.rs:8`); a macOS zero-test result is not execution. |
| KVM existing x86 engine | `crates/carrick-vmm-kvm/src/kvm_x86_engine.rs:450,484` rebuilds after host fork/vfork; `:1002` completes SYSRET; `:1212,1229` handles XSAVE; `:1249` decodes exits; `:1395` constructs the shared engine. | Hardware hooks are useful; per-process RAM/root ownership and host-fork rebuilding are not the new carrier architecture. KVM crate is empty off Linux (`src/lib.rs:13`). |
| M3 preparation on main | `crates/carrick-mmu-core/src/x86/descriptor_txn.rs:1–5,49–77,131` provides four-level/4 KiB Map/Publish/Protect/COW/Unmap/Coalesce transactions using existing common identity/journal types; `:692` is a read-only hardware walk. `crates/carrick-vmm-kvm/src/carrier_memory.rs:113–139,384,539` joins slot publication, rollback and drain/retirement callbacks. | No reservation/permit owner lives here. `carrier_memory.rs:649` has a deliberately empty invalidation hook; the owner must perform the trailing CPL0 drain before re-entry. `tests/carrier_memory.rs:37,70,85,106,133,161` proves hardware cases, not owner integration. |
| M4 preparation on main | `crates/carrick-x86/src/cpl0_scheduler.rs:34–47,89–122` binds native contexts to existing scheduler records; `interrupts.rs:38–100` supplies interrupt masking, park, LAPIC timer/EOI/wake. `crates/carrick-x86-cpl0/src/progress.rs:104–114,155–229` uses the shared queue/space authority around native context changes. `crates/carrick-vmm-kvm/src/carrier_interrupts.rs:110–117` runs both contexts on one CPU. | `tests/cpl0_progress.rs:40–158` proves two private roots, syscall-free compute, TLS/YMM preservation, one wake, timer/kick counts and zero semantic forwards. This is not production pipe/futex exhaustion, timer policy or M5 pool integration. |
| bhyve x86 | `crates/carrick-vmm-bhyve/src/bhyve_x86_engine.rs:378,689,1559,2398` implements `X86Vcpu`, exit decoding, `X86Vmm`, and shared-engine bring-up; `:633–685` handles XSAVE through its native/stub mechanism. | No CPL0 carrier binding found in this crate. The entire crate is gated to FreeBSD/x86_64 (`src/lib.rs:26`); KVM/cloudmac results do not qualify it. |
| NVMM x86 | `crates/carrick-vmm-nvmm/src/nvmm_x86_engine.rs:615,833,1138,1290,1482` implements VM/host-fork rebuild/CPU/exit/shared-engine entry. `:1275–1287` provides legacy FP access. | No CPL0 carrier binding or XSAVE override found. It inherits `crates/carrick-x86/src/vmm.rs:783–793`, which pads/extracts legacy FP; whether a target enables AVX must be qualified, not inferred as a bug. NetBSD/x86-only gate is documented in `src/lib.rs:21–30`. |
| PR7 owner checkpoint | `PR7:crates/carrick-mmu-core/src/owner_mmu.rs:21–54` defines `OwnerMmu`/`OwnerForkMmu`; `PR7:crates/carrick-el1/src/personality/mm_portal/production.rs:21,186,483` parameterizes the existing portal with an ARM default. P7:552–577 describes shared Fork and exact physical `TransferPin` custody. | These are proposed common-seam changes (`faf667c81`, `166067b62`) for n1f, not main APIs or independently accepted M3. P7:640–655 explicitly separates native-owner/KVM evidence from production CPL0 owner serving. |

PR7's broad failures and absent acceptance receipts are recorded in its PR
body. This audit neither reattributes nor reruns them. A direct comparison
`git diff b1167c6e1 pr7 -- crates/carrick-x86/src/cpl0_entry.rs` also shows that
PR7 lacks main's `scheduler_witness` field: preserve main's M4 preparation
when integrating; never replace current main files with the stacked versions.

## Candidate classification

This is the candidate worklist for M1–M7 continuation and the requested other
x86 engines; it is not a claim to enumerate every possible x86 enhancement.

| ID / candidate | Classification | Exact boundary / reason |
| --- | --- | --- |
| I1 — M2 full-width head/length and two-slot hardware witnesses | **INDEPENDENT** | Existing common behavior and entry ABI; only x86 adapter and KVM test files below. No additional admitted syscall. |
| I2 — KVM CPU read-error custody matrix | **INDEPENDENT** | Existing sealed `CarrierCpuIo` and local Idle/Loaded/Poisoned state; no shared runtime integration. |
| I3 — CPL0 x87/MXCSR isolation across timer preemption | **INDEPENDENT** | Existing x87/SSE/AVX mode and M4 hardware fixture; no scheduler/wait policy or shared layout change. |
| I4 — x86 ancestor-permission walk matrix | **INDEPENDENT** | Existing x86 descriptor backend and its local tests only; no owner hooks or ARM descriptor changes. Secondary queue after I1–I3. |
| Apply PR7 `OwnerMmu` / `OwnerForkMmu` and production transfer binding | **N1-DEPENDENT** | N1 rows 1–5, 7, 10–12 and 29; `mm_portal/{production,fork}.rs`, common `owner_mmu` exports and prepared permit/physical-pin seam. Driver integrates once. |
| Complete M3 fault/grant publication, first touch and COW | **N1-DEPENDENT** | N1 rows 12–15 and 20; `serve_grant`, `PortalGrantSlot`, `PreparedPageResolver`, `CowResolver`, physical readiness and exact receipt settlement (detailed below). |
| M3 Exec/Capacity/HostBacking, root-arena reuse | **N1-DEPENDENT** | N1 rows 2, 13–15, 21–23, 28–29; owner Exec transaction, VA-free extent grants, lifetime/drain proofs. A memslot delete or local CR3 reload alone cannot authorize reuse. |
| Foreign/stopped-MM transfer with all default leases occupied | **N1-DEPENDENT** | N1 rows 4–9, 22–24, 30 and M5 executor service/continuation binding; no spare helper CPU or private transfer cursor. |
| More CPL0 calls: lseek/read/write, non-NULL sigmask, get_robust_list, memory calls | **N1-DEPENDENT** | N1 UserTransfer/permission rows 3–9, 16–19; lseek additionally needs the shared OFD cursor handoff at P7:181–187,363. Pointer-free serving must not be generalized into pointer access. |
| Pointer-free gettid/set_tid_address or NULL-only sigmask route | **NEEDS-OWNER-DECISION** | Potential small semantic slice, but changing `common_entry`/`thread_setup`/lifecycle and routing is outside the confirmed fence; N2/Phase B owns identity/setup. Need explicit leaf handoff and one shared implementation, not an x86-only syscall shortcut. |
| Full M4 shared IPC/futex/park/cancel/timer policy | **N1-DEPENDENT** | N1 rows 3–9, 22–23 and `alloc`, `sched/object_wait`, `space_access`/`deliver_completion`; shared N2 lifecycle/wait hooks. Existing timer hardware proof does not close owned waits or partial-I/O continuation. |
| M5 persistent carrier / allow executor audit / remove runtime refusal | **N1-DEPENDENT** | N1 rows 1–2, 22–23, 28–29 plus Phase B, runtime executor/backend/binding/quantum and root-retirement proofs (P7:687–714). Do not import the old host-fork engine as a carrier. |
| M6 clone/exec/signals/OCI shell | **N1-DEPENDENT** | N1 rows 10–11, 21, 27–29 plus landed N2 graph/fd/signal/loader transactions; runtime prepare/lib and page-profile selection (P7:716–742). |
| New bhyve/NVMM CPL0 boot/CPU/interrupt hardware adapters | **NEEDS-OWNER-DECISION** | Hardware leaves may be independent once fenced, but no selected BSD host, current capability receipt or commissioned carrier slice was found. Qualify native BSD execution first. Production memory/runtime binding still depends on N1 rows 1–15,22–23,28–29. |
| PCID/INVPCID, global pages, larger XSAVE components or new ISA mode | **NEEDS-OWNER-DECISION** | Current fixture explicitly admits no-PCID/no-global and x87/SSE/AVX only (`carrier_interrupts.rs:268–270`). New capability/retirement/layout contract needs an owner-approved scope. |
| Rename the common kernel package / widen shared `KernelArch` ABI | **NEEDS-OWNER-DECISION** | P7:105–112 defers the neutral package rename until post-N2; shared ABI/export edits are integrator-owned now. |
| M7 required KVM carrier gate and end-to-end performance closure | **N1-DEPENDENT** | M1–M6 composition, executing contract bindings and exact artifact provenance (P7:745–769). The willow pilot is a hardware test runner, not a replacement acceptance gate. |
| Expand willow automation, scaler policy or automatic trigger | **NEEDS-OWNER-DECISION** | Existing `.github/workflows/willow-pilot.yml:3–11` is manual and runner-scoped. Do not widen infrastructure scope merely to run the four focused packages. |

## Exact M3 handoff required from N1

P7:579–638 names the blocker more precisely than “wait for N1”:

1. Keep `MmPortal::select`, `prepare_transfer` and `serve_transfer` as the
   single reservation, permission, prepared-operation and completion policy.
   PR7 already parameterizes their hardware interpretation; this does not
   make the grant service generic.
2. `serve_grant` still takes the ARM-default portal and returns an ARM
   descriptor receipt (`PR7:crates/carrick-el1/src/personality/mm_portal/production.rs:1238`).
   `PortalGrantSlot` embeds ARM `DescriptorTxnSlot`. Retired-leaf recognition,
   Prepare encoding, table grants, outcome and settlement need one coordinated
   backend/wire seam. Existing x86 Map/Publish must form **one rollback-capable
   owner publication**, not two separately accepted edits. Preserve reservation
   fault-window authentication, residency identity, inventory readiness and
   N1 extent/retained-byte/compound budgets (rows 12–15,20).
3. Supply x86 implementations for `PreparedPageResolver::commit_prepared`
   and `CowResolver::{resolve_cow_outcome,executable_publication,take_cow_completion}`.
   Do not copy reservation/supply policy into those implementations.
4. Replace only the hardware transport of `select_transfer_hw`,
   `serve_transfer_hw`, `serve_grant_hw`, `bind_transfer_hw`, `serve_fork_hw`
   and `finish_fork_hw`: today they take ARM `TrapFrame` and use ARM
   stack/TTBR/HVC hooks. CPL0 needs normalized entry/root identities and the
   existing permit/receipt protocol, plus real x86 allocator and scheduler
   hooks for `space_access`/`deliver_completion`. `host-test` exports are not
   production implementation.
5. Bind real owner inventory callbacks, Fork/Exec/Capacity, exhausted-pool
   transfer progress and root retirement. Preparation callbacks, physical
   pins and successful hardware walks confer no semantic VA authority.
   Complete shared ARM regression/signed acceptance through the integrator.

The transfer/Fork tests in PR7 use real N1 owner state, with reported
16/64/256-page work checks and a wrong-MM physical-pin negative control.
They are useful evidence for that checkpoint, but P7:650–653 explicitly
leaves all five integration obligations above open.

## Dispatch now: three disjoint packages

These are **witness extensions**, not asserted undiscovered product bugs.
For each, first show the new assertion fails under a narrowly injected defect,
then restore the real implementation and require green. Retain the mutation
patch and failure log; do not commit a mutant, count compile failure as red,
or edit a shared/N1 file even temporarily for the negative control.
If the real baseline fails, retain that red and reclassify any fix that escapes
the fence. The commands below are proposed verification, not runs by this audit.

### I1 — M2 argument width and no-dereference binding (priority 1)

**Exact files:** `crates/carrick-vmm-kvm/tests/cpl0_entry.rs` (new cases),
`crates/carrick-x86/src/cpl0_entry.rs` (local decoder unit cases and temporary
negative control only). Keep `cpl0_boot.rs`, image entry and common helper
unchanged.

The current live cases use small heads and lengths 0/23/24/25/MAX; they do not
exercise successful high-bit heads or lengths whose low 32 bits equal 24
(`tests/cpl0_entry.rs:45–47`). Add two-task sequences with distinct full-width
heads, including NULL and unmapped/noncanonical bit patterns, successful length
24, and rejected `0x1_0000_0018`. Registration stores the opaque head; it does
not access that address. Assert both heads after every success/error, exact
entry/completion/publication counts, full returned result, unchanged sibling,
and zero semantic forwards. Preserve entry/return kick cases.

**Cheapest red:** VM-free decoder case with `rdi`/`rsi` high bits; temporarily
truncate those arguments in `NativeFrame::decode`. The new unit and executing
cases must detect the truncation, not just fail boot. The executing image must
be rebuilt for both red and green. Authority: the already shared robust-list
contract at `thread_setup.rs:48–49,120–136`; families
`kernel.syscall.captured-stack`, `kernel.vcpu.kick-el0-boundary` and existing
lifecycle control-slot ownership. This extends M2 proof without adding a syscall.

On the Linux x86 VM, with nested KVM for entry execution:

```sh
cargo test --locked -p carrick-x86 --lib cpl0_entry::tests
cargo build --locked --release -p carrick-x86-cpl0 --target x86_64-unknown-none
CARRICK_RUN_ID=x86-i1-entry cargo test --locked -p carrick-vmm-kvm --test cpl0_entry -- --nocapture
just accept --profile linux-portable
```

### I2 — CPU custody after failed reads (priority 2)

**Exact file:** `crates/carrick-vmm-kvm/src/carrier_cpu.rs`, its existing
in-file tests and a local correction only if the witness demonstrates one.
The existing real readback test stays unchanged.

`FaultIo::read_image` always returns success (`:325–327`); its existing failure
matrix corrupts writes/readback values (`:328–365`). Add a deterministic
read-failure adapter at initial capture, idle audit, post-load readback,
pre-detach snapshot and post-reset audit. Distinguish pre-mutation refusal
from potentially partial load/detach: the latter must never issue a detached
context or allow later load/detach reuse. Exercise two task generations and
assert no extra retry/read/write calls after poisoning. Establish exact
call budgets per phase from the straight-line transaction; no timing loop.

**Cheapest red:** Linux VM-free `CarrierCpuIo` test (no `/dev/kvm` needed for
this unit filter). Temporarily replace the pre-operation Poisoned transition
with Idle in `save_and_detach`, fail only the post-reset readback, and
require the later-reuse assertion to fail: the neutral hardware image alone
must not manufacture a detach receipt. Retain the existing stopped-KVM two-image readback as the
hardware check; it does not execute guest instructions. Family:
`kernel.el1.task-load-entry` and execution-generation isolation, scoped to
x86 custody, not the ARM contract's no-maintenance-exit acceptance.

```sh
cargo test --locked -p carrick-vmm-kvm --lib carrier_cpu::tests
CARRICK_RUN_ID=x86-i2-cpu cargo test --locked -p carrick-vmm-kvm --test carrier_cpu -- --nocapture
just accept --profile linux-portable
```

### I3 — full admitted FP control across CPL0 switches (priority 3)

**Exact files:** `crates/carrick-vmm-kvm/src/carrier_interrupts.rs`,
`crates/carrick-vmm-kvm/tests/cpl0_progress.rs`, and
`crates/carrick-x86-cpl0/src/progress.rs` (temporary native restore mutation;
only a demonstrated local correction may remain). Do not change the common
scheduler, native context layout, entry source or shared CPU-state ABI.

Both current contexts seed the same x87 control word and MXCSR
(`carrier_interrupts.rs:194–200`); live assertions distinguish XMM/YMM15,
TLS and GPRs, but not distinct x87 control/MXCSR values. Seed two legal distinct
rounding modes, keep exceptions masked, execute user instructions that store
x87 control and MXCSR into the already private data page, and compare both
executed stores and saved XSAVE control bytes across the existing 16 turns.
Retain all existing compute-progress, exact-root, GPR/TLS/YMM, one-wake and
exit-count assertions. Do not infer live preservation only from initial buffers.

**Cheapest capable red:** executing nested KVM, because host snapshots cannot
prove the assembly switch. Temporarily reset FP control to a fixed mode after
XRSTOR in `progress.rs:56`; the new observed-control assertions must fail while
both tasks still make compute progress. Restore and rebuild. Families:
`kernel.scheduler.runnable-progress`, `kernel.vcpu.kick-el0-boundary` and
context isolation. Preserve zero semantic/interrupt host exits and the
existing exact timer, wake and three-control-exit budgets.

```sh
cargo build --locked --release -p carrick-x86-cpl0 --target x86_64-unknown-none
CARRICK_RUN_ID=x86-i3-progress cargo test --locked -p carrick-vmm-kvm --test cpl0_progress -- --nocapture
just accept --profile linux-portable
```

The three exact file sets have empty pairwise intersections and no intersection
with the N1 fence. All dependencies already exist on `b1167c6e1`; none needs
PR7 cherry-picks. Build artifacts are not disjoint: run in separate disposable
VM checkouts/clones, and serialize broad host gates through their normal lease.
“Dispatch” here recommends future assignments; this documentation task does
not start workers, VMs or workflows.

### I4 — secondary independent descriptor coverage

**Exact files:** `crates/carrick-mmu-core/src/x86/descriptor_txn/tests.rs` and
`crates/carrick-mmu-core/src/x86/descriptor_txn.rs` (temporary mutation or
proved local correction only). Existing tests cover terminal permissions,
COW, split/coalesce and publication failures (`tests.rs:164,230,324,375`).
Add an explicit per-level matrix for a permissive leaf beneath supervisor,
read-only or NX ancestors, and nonidentity 4 KiB/2 MiB/1 GiB terminal offsets.
Read-only translation performs zero stores and at most four loads, independent
of 16/64/256 unrelated branches. This is hardware interpretation, not VMA rights.

**Cheapest red:** VM-free descriptor words; mutate `translate` at
`descriptor_txn.rs:711–717` to enforce permission only on the terminal.
Ancestor denial assertions must fail. Restore and run:

```sh
cargo test --locked -p carrick-mmu-core --lib x86::descriptor_txn::tests
CARRICK_RUN_ID=x86-i4-memory cargo test --locked -p carrick-vmm-kvm --test carrier_memory -- --nocapture
just accept --profile linux-portable
```

Families: `kernel.el1.stage1-publication` and
`kernel.mm.address-space-occupancy`, limited to descriptor interpretation.
Run these commands on the Linux VM. Keep PR7's owner adapter and common
journal types untouched; coordinate later application with the M3 integrator.

## Verification placement and handoff

Cloudmac is macOS/Apple M4, shared and never to be rebooted, shut down or slept.
Source `/Volumes/carrick/dev/env.sh` before every cloudmac command. No Docker,
load generators, stash, bypassed hooks or GPL source inspection in this task.
All Linux/KVM package checks above belong on the Linux x86 VM; CPL0 entry and
progress execution belongs under nested KVM, as the willow pilot demonstrates.
The existing manual recipe is `.github/workflows/willow-pilot.yml:19–42`:
non-root KVM verification, locked freestanding build, executing `cpl0_entry`,
and retained logs. It currently runs neither I2/I3 nor `linux-portable`.

Each implementation package must record source HEAD, CPL0/test executable
hashes, nested host/capability identity, nonzero executed test population,
red patch/raw output, green output and cleanup. Stamp all executions with a
unique `CARRICK_RUN_ID` (the command values above are examples); reap only
that ID with `scripts/sudo/kill.sh <run-id>` where applicable. Never use a
zero-test macOS pass as Linux evidence. No timeout/retry/budget/concurrency
relaxation is authorized. Linux workers finish `just accept --profile
linux-portable` on the VM and queue `just remote-accept --ref <commit> --phase
host` with the director; include both verdicts and receipt paths. Shared ARM
changes, if later authorized, need their separately coordinated signed gates.

Existing test comments name contract families, but the inspected
`conformance-contracts/contracts/task-load-entry.toml:2–8` remains ARM/HVF
specific, and the scheduler descriptor does not register these new x86
observations. These leaf tests are supplementary evidence, **not new registered
KVM contract acceptance**. M7/integrator owns the cross-layer binding and
receipt work. If a change needs a new behavior contract rather than extending
an existing hardware invariant, stop the independent package at that seam.
No Linux semantic or performance closure is inferred from nested hardware
results; native-x86 oracle/timing and broad carrier acceptance remain separate
future owner work. No Docker command is proposed for cloudmac or this audit.

## UNKNOWNs and searches

| Unknown | What was searched / what would resolve it |
| --- | --- |
| Current whole-N1 acceptance after the cited snapshots | PR7 body/comments and grant handoff; director-supplied N1 audit. No fresh N1 build/gate was run. Need a current exact-artifact owner receipt, not branch presence or earlier focused passes. |
| Full expanded names in the driver's category reservations | Main/PR7 plans searched for `driver.reserved`, `reserved files`, `n1f`; then director mailbox and audit line 75. Categories remain broad, so this plan excludes their entire subsystems. |
| Live BSD CPL0 availability and AVX contract | `rg --files` and x86 engine/FP/XSAVE/bring-up searches in both BSD VMM crates and shared `vmm.rs`. No CPL0 carrier module or NVMM XSAVE override found; no BSD host was contacted. Need native-host feature and executing state-preservation evidence. |
| Fresh willow pilot receipt for this source | Inspected `willow-pilot.yml` and main `b1167c6e1`; pilot success is user-supplied context. No workflow run downloaded or triggered. Need an artifact tied to the implementation commit for each future package. |
| Actual defects behind the four proposed extensions | Inspected existing unit/live assertions and source, not executed mutants. Missing distinguishing inputs establish useful coverage work, not a demonstrated runtime defect. Require the red controls above before claiming a fix. |

## This document's verification

Documentation-only exemption: the sole changed path is this plan; no guest
semantics, work budget, source, test, ABI, controller or inventory changes.
Use the task's requested gate:

```sh
test -s docs/superpowers/plans/2026-10-04-x86-parallel-track.md && just fmt-check
```

Passing it establishes document presence and repository formatting only.
Product CI, signed tests, Linux/KVM tests and the proposed red controls are
not executed by this audit and confer no acceptance here.
