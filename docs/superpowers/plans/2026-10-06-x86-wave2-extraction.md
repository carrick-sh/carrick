# x86 acceleration on the shared kernel core: Wave 2

Read-only audit and draft, 2026-10-06. Continue the first track's purpose:
Linux/KVM should expose defects in the **same owners** used by AArch64 N1.
This document claims no implementation, guest run, or acceptance. Carrick
remains experimental. **Updated owner direction, relayed by the director on
2026-10-06: N1 is paused; x86 settles the shared core, then N1 rebases once.**
The per-move ARM bar is no new signed failure versus the `56bf8c0ca` baseline,
with both ISA callers switched in the same commit to one implementation.

## Start from N1; settle the x86 stack with an explicit audit revision

**Every current-code citation and census below is at
`56bf8c0caefe39fcc2260345d0a54772a74bffad`.** A citation such as
`crates/carrick-el1/src/fault.rs:960` means that revision, not the eventual
implementation branch. Destinations and X4–X8 tests are proposed unless
explicitly described as existing.

The first plan was read in full from
`/home/carrick/dev/x86-parallel-track-plan.md`, SHA-256
`6c3c093d1c9590318618e1b2bab03931d9cad17bbbd1130eccdfd980b90344a8`.
Preserve its extraction order, A/AM/AF/AW/AR gates, X1–X3 production-execution
requirements, two-process controls, and artifact discipline. Also retain the
[approved personality split](https://github.com/carrick-sh/carrick/blob/486394ebf2486e6491459c1540d49bbbf7318318/docs/superpowers/specs/2026-10-04-personality-core-split.md),
[N1 ownership controller](2026-10-02-el1-native-ownership.md),
[maintenance handoff](https://github.com/carrick-sh/carrick/blob/d5fdc6005bca46c9e5383c8553fed7a5466221ed/docs/superpowers/plans/2026-10-05-n1-backing-maintenance-handoff.md),
[contracts](../../conformance-contracts.md), and [rulebook](../../../AGENTS.md).
The split and handoff links pin published document revisions; neither file is
present in this plan's publication tree. They do not change the code-audit SHA.

This document branch starts on the requested `origin/work/n1`, which had
advanced to `09fff7bfabfdc2849dd4d0ee0ede66f1810b318b` when the scratch
worktree was created. That is a publication base, **not a replacement audit
snapshot**. Before implementation, re-inventory the current N1 symbols,
layouts, witness names and policy debt; do not restore older bodies from this
audit. The pause supersedes Wave 1's daily N1 rebase loop. The x86 integrator
stacks moves and shared fixes on the current x86 integration head, recording
the exact predecessor SHA for each move. Do not repeatedly rebase N1 while
interfaces settle. The final section specifies its single rebase.

Move each responsibility once, switch both callers, delete its displaced
body, and move its witnesses with it. Every discovered shared defect needs a
deterministic red, exact operation/generation, source SHA, failure log and fix
in the shared owner. The integrator preserves that packet and authorship for
the final N1 fix-stack audit. X4–X8 discovery and KVM execution do not wait for
N1 signed development work; a KVM pass still does not confer N1 acceptance.

**Predecessor 4b, done-in-flight:** the director reports that x86 X1 exposed
production protect/retire routing through ARM `HardwareAnonymousEditor` and
the absence of a shared transfer-service transport. At the audit snapshot,
dispatch invokes that editor directly
(`crates/carrick-el1/src/personality/dispatch.rs:384`, `:393`) and the current
prepared-write service constructs an ARM service frame
(`crates/carrick-aarch64/src/user_transfer/prepared.rs:26`, `:35`). Worker
`x86-x1c` is moving those owner/transport responsibilities into core on
`work/x86-x1a`. This is an in-flight integration input, not a claim about
implemented code at `56bf8c0ca`. Wave 2 starts **after 4b**, consumes its one
protect/retire and transfer-service path, and requires its executing X1 receipt
for same-path cross-MM transfer and peer-physical-pin rejection. Re-inventory
4b's actual symbol fence before order 5; do not re-extract or copy those bodies.

## What is shared today, and what the line numbers mean

Wave 1's modules are present in `carrick-core` (`crates/carrick-core/src/lib.rs:5`) and its ABI
(`crates/carrick-core-abi/src/lib.rs:5`). The ARM portal imports the transaction
body (`crates/carrick-el1/src/personality/mm_portal/production.rs:6`), COW
uses the shared owner (`crates/carrick-el1/src/cow.rs:16`), table retirement
uses the shared algorithm (`crates/carrick-aarch64/src/stage1_authority.rs:812`),
and the ABI re-exports core records (`crates/carrick-el1-abi/src/lib.rs:33`).
Wave 2 must extend those owners, not introduce a second MM or wait graph.

**Source sharing and CPL0 execution have different denominators.** At this
snapshot the CPL0 entry calls the common entry
(`crates/carrick-x86-cpl0/src/entry.rs:135`), whose admitted syscall body is
only `set_robust_list` (`crates/carrick-el1/src/personality/common_entry.rs:47`).
The x86 decoder maps native 273 to canonical 99 and refuses other ordinals
(`crates/carrick-x86/src/cpl0_entry.rs:43`). Other personality modules are
excluded from the x86 bare-metal build
(`crates/carrick-el1/src/personality/mod.rs:7`). The image's allocator halts
on allocation (`crates/carrick-x86-cpl0/src/entry.rs:13`). Thus moved-source
presence must not be presented as full X1–X3 production acceptance. Existing
KVM memory witnesses explicitly drive first-touch/COW from the host
(`crates/carrick-vmm-kvm/tests/carrier_memory.rs:79`, `:99`); those are useful
hardware prerequisites, not proof of a CPL0-owned fault operation.

The census uses tracked `.rs` files, including tests, build scripts and
assembly embedded in Rust. Count a physical line when nonblank and its trimmed
text does not start with `//`, `/*`, `*`, or `*/`. This deliberately simple
**non-comment-prefix line** metric reproduces the brief's magnitudes; it is
not a Rust lexer, compiled production SLOC, instruction count or work budget.
Inline comments do not erase their code line. Standalone assembly, generated
output, fixtures outside these packages, and the host kernel are excluded.

| Inventory at the audit SHA | Lines | Source anchors / interpretation |
| --- | ---: | --- |
| Shared extracted owners: `carrick-core` | 12,645 | `crates/carrick-core/src/lib.rs:5`; includes `crates/carrick-core/tests/x86_acceleration.rs:1` and its submodules |
| Shared extracted wire: `carrick-core-abi` | 3,742 | `crates/carrick-core-abi/src/lib.rs:5` |
| Shared Linux client: `carrick-personality-linux` | 619 | `crates/carrick-personality-linux/src/lib.rs:4`; policy is shared between ISAs, not neutral core |
| **Shared extracted package subtotal** | **17,006** | Owners + wire + Linux client; count each source once |
| ARM-resident image package: `carrick-el1` | 24,131 | `crates/carrick-el1/src/lib.rs:7`; contains tests and mixed policy/adapters |
| ARM-resident wire package: `carrick-el1-abi` | 10,932 | `crates/carrick-el1-abi/src/lib.rs:23`; also consumed by CPL0, so residency does not mean all these types are ARM-exclusive |
| ARM engine package: `carrick-aarch64` | 15,710 | `crates/carrick-aarch64/src/lib.rs:28`; host engine/adapters, not 15,710 lines executing at EL1 |
| **ARM-resident subtotal** | **50,773** | Image/wire alone: **35,063**; engine: **15,710** |
| x86 engine/adapters: `carrick-x86` | 5,435 | `crates/carrick-x86/src/lib.rs:35`; includes host engine and bring-up tests |
| x86 CPL0 image: `carrick-x86-cpl0` | 370 | `crates/carrick-x86-cpl0/src/entry.rs:26`, `crates/carrick-x86-cpl0/src/progress.rs:24`; source included by path is counted in its owning package once |
| **x86-only package subtotal** | **5,805** | Engine/adapters + image |
| **Focused inventory total** | **73,584** | Fixed Wave 1/2 package denominator, not all of Carrick |

This is the concrete **17.0k shared / 50.8k ARM-resident / 5.8k x86-only**
comparison used for forecasts below. Calling the middle column “truly
AArch64-only guest-kernel code” would be wrong. For example, common-entry plus
thread-setup and their tests already supply **381** frame-independent lines
from the ARM package (`crates/carrick-el1/src/personality/mod.rs:6`, `:21`).
Reclassifying only that proven shared island gives **17,387 / 50,392 / 5,805**;
additional mixed ABI records require item-level classification, not an
unsupported claim that an entire ABI crate is neutral.

The unchanged shared substrates are outside this focused denominator:
mmu-core 18,728; sched-core 11,169; guest-arch 351; fd-core 2,783; pipe-core
1,593; inotify-core 561; timer-core 644; signal-core 2,134; signal-linux 2,196
(**40,159** total). These are package footprints, not 40,159 neutral lines:
the MMU has ISA modules (`crates/carrick-mmu-core/src/lib.rs:13`, `:16`), scheduler
`ThreadCtx` is ARM-shaped (`crates/carrick-sched-core/src/lib.rs:382`), fd/pipe
policy is imported by IPC (`crates/carrick-el1-abi/src/ipc.rs:95`), and inotify
bits are Linux (`crates/carrick-el1/src/personality/inotify.rs:8`). Adding that
unchanged substrate footprint makes the broader tracked-source inventory
113,743 today, without changing the move forecast. KVM's entire package is
another 8,832 host/backend/test lines, reported separately: it is not CPL0
source (`crates/carrick-vmm-kvm/tests/carrier_memory.rs:41`).

Reproduce the census without checking out or modifying the audit revision:

```sh
python3 - <<'PY'
import subprocess
ref = '56bf8c0caefe39fcc2260345d0a54772a74bffad'
names = '''core core-abi personality-linux el1 el1-abi aarch64 x86 x86-cpl0
mmu-core sched-core guest-arch fd-core pipe-core inotify-core timer-core
signal-core signal-linux vmm-kvm'''.split()
paths = subprocess.check_output(
    ['git', 'ls-tree', '-r', '--name-only', ref, 'crates'], text=True).splitlines()
for name in names:
    prefix = 'crates/carrick-' + name + '/'
    total = 0
    for path in paths:
        if path.startswith(prefix) and path.endswith('.rs'):
            source = subprocess.check_output(['git', 'show', ref + ':' + path], text=True)
            total += sum(bool(s.strip()) and not s.lstrip().startswith(
                ('//', '/*', '*', '*/')) for s in source.splitlines())
    print(name, total)
PY
```

## Shared-core extraction order

Recommended sequence: **4b owner/transfer-service completion → 5 entry →
6 lifecycle → 7 residual MM → 8 IPC → 9 file/inotify**. Wave 2 numbering
continues orders 1–4; its milestones are X4–X8. Each moved order executes on
KVM against the preceding x86 stack without waiting for N1 signed work.
The existing VM-free `x4_shared_wait_records` name
(`crates/carrick-core/tests/x86_acceleration.rs:867`) is preserved and does
not become evidence for the new X4 entry milestone.

| Order / piece | Exact source symbols → planned destination | ISA seam retained / unchanged-ARM gate |
| --- | --- | --- |
| **5: common entry and Linux dispatch** | `EntryOutcome` (`crates/carrick-el1/src/personality/common_entry.rs:23`), `serve_canonical` (`:35`), the semantic body of `dispatch_syscall_with_lifecycle` (`crates/carrick-el1/src/personality/dispatch.rs:259`), and `dispatch_anonymous_with_reservations` (`:27`) → `carrick-personality-linux/src/{entry,dispatch}.rs`. Define normalized per-family handler traits there, with ARM implementations in `carrick-el1/src/personality/bindings.rs`; extract routing/completion from retained bodies in this order. `is_served_futex_op`, `Sched::serve_futex/serve_wait` (`crates/carrick-el1/src/personality/sched.rs:16`, `:31`, `:51`) → Linux `src/futex.rs`; Linux IRQ/idle timeout-result policy (`:90`, `:93`) → Linux `src/sched.rs`. Split `CurrentTask` (`crates/carrick-el1-abi/src/lib.rs:687`) into neutral exact execution/MM binding in `carrick-core-abi/src/entry.rs`, core admission/completion in `carrick-core/src/entry.rs`, and Linux task/diagnostic state in `carrick-personality-linux/src/abi/entry.rs`. One Linux routing/completion owner consumes the core capability. | `TrapFrame` (`crates/carrick-el1-abi/src/lib.rs:642`), `dispatch_entry` ESR classification (`crates/carrick-el1/src/personality/dispatch.rs:132`), fixed-region table acquisition (`:60`), native save/restore and hardware IRQ/timer operations stay adapters; Linux futex decode and ETIMEDOUT do not. AArch64 `x8` and x86 `rax` decoding/return registers stay ISA-specific; Linux ordinal tables leave the hardware interface. **A + AE + AW**. |
| **6: thread birth, clone, exit and clear-tid** | Neutral parts of `EntryState`, `EntryRef`, `ClaimedEntry`, `ExitAdmission`, `GateState` and pool transitions (`crates/carrick-el1-abi/src/thread_lifecycle.rs:126`, `:195`, `:225`, `:234`, `:365`, `:940`) → `carrick-core-abi/src/lifecycle.rs` for typed records and `carrick-core/src/lifecycle.rs` for claim/publish/rollback/retire. `serve_clone`, `serve_exit`, `TidOutputs`, signal-mask/altstack routines (`crates/carrick-el1/src/personality/lifecycle.rs:386`, `:514`, `:350`, `:217`, `:267`) → `carrick-personality-linux/src/{clone,thread,signal}.rs`. `ThreadControlSlot`, `BornRecord`, `EntryIdentity` Linux fields (`crates/carrick-el1-abi/src/thread_lifecycle.rs:459`, `:308`, `:294`) → `carrick-personality-linux/src/abi/thread.rs`; `set_robust_list`/`LifecycleVenue` (`crates/carrick-el1/src/personality/thread_setup.rs:123`, `:25`) → Linux `thread.rs`. | `ThreadCpu::save/load` currently takes ARM frames/context (`crates/carrick-el1/src/sched.rs:20`); split associated native context and exact-record sidecars, not fake ARM frames on x86. Stack/TLS/child-result installation (`crates/carrick-el1/src/personality/lifecycle.rs:483`) stays native; vDSO identity packing (`:491`) is Linux AArch64 ABI policy. ARM region lookup stays image glue; x86 FS/GS/XSAVE stays x86. **A + AL + AF + AW + AR**. |
| **7: residual MM orchestration, maintenance and fault ownership** | Neutral admission and exact settlement in `NativeBackingMaintenance::begin_backing_maintenance`, `BackingMaintenance::scrub` (`crates/carrick-el1/src/personality/mm_portal/maintenance.rs:35`, `:91`) → `carrick-core/src/mm/maintenance.rs`, parametrized by the existing owner-MMU seam. Neutral pending-fork capsule/authentication in `UnpublishedEl1Child`, `authenticate_pending_parent_write`, `reconcile_pending_parent_write` (`crates/carrick-el1/src/personality/mm_portal/fork.rs:76`, `:393`, `:411`) → `carrick-core/src/mm/fork/pending.rs`. Split `PortalBackingMaintenance`, `PortalClosedRootBind`, `PortalForkSlot` (`crates/carrick-el1-abi/src/mm_portal.rs:46`, `:16`, `crates/carrick-el1-abi/src/mm_portal_fork.rs:65`) into neutral operation/generation records in core-abi `mm/{maintenance,fork}.rs` and Linux request/result encoders in Linux `abi/mm.rs`. Semantic `PendingReservationSyscall`, `decide_anonymous_syscall`, `serve_delegated_anonymous`, `try_serve_munmap/mprotect` (`crates/carrick-el1/src/memory.rs:83`, `:186`, `:669`, `:889`, `:948`) → Linux `mm/entry.rs`. `LinuxForkPolicy` (`crates/carrick-el1/src/personality/mm_portal/fork.rs:48`) → Linux `mm/fork.rs`. Frame-independent refusal/grant/drain orchestration (`crates/carrick-el1/src/fault.rs:398`, `:583`, `:646`, `:919`, `:960`) → existing core `mm/{fault,capacity,cow}` after native inputs are decoded. | Do **not** move ARM ESR classification (`crates/carrick-el1/src/fault.rs:27`, `:57`), `HardwarePreparedResolver`/`HardwareDescriptorTxnApplier` (`:112`, `:302`), `Aarch64CowMmu` (`crates/carrick-el1/src/cow.rs:19`), ARM table walk `classify_stage1_range` (`crates/carrick-el1/src/memory.rs:490`), or `serve_*_hw` register/HVC bodies (`crates/carrick-el1/src/personality/mm_portal/production.rs:67`, `:310`). Separate maintenance algorithm from `retired_page` ARM descriptor interpretation (`crates/carrick-el1/src/personality/mm_portal/maintenance.rs:184`); geometry supplies spans/alignment. Host map/pin/supply remains host custody. **A + AM + AF + AW + AR + AX**. |
| **8: IPC owners, byte transfers and Linux IPC policy** | Neutral `IpcObjectHandle` generation/pin lifetime, lock/readiness revision, operation-slot generation/one-winner completion (`crates/carrick-el1-abi/src/ipc.rs:157`, `:398`, `:803`, `:1318`, `:1649`, `:1683`) → `carrick-core-abi/src/object.rs`, core `src/object/{pool,subscription}.rs` and `src/io/continuation.rs`. Split `IpcOperation` (`:650`); core holds exact object/MM/progress/completion, Linux holds fd pin, syscall/value/nonblock/SIGPIPE payload. `serve_ipc`, `admit`, `run`, `park`, `finish` (`crates/carrick-el1/src/personality/ipc.rs:185`, `:262`, `:406`, `:648`, `:699`) → Linux `src/ipc/{mod,io}.rs` over core wait/transfer APIs. `IpcBacking`, creation/release, eventfd, fd-table map and epoll owner (`crates/carrick-el1-abi/src/ipc.rs:273`, `:1419`, `:1463`, `:1483`, `crates/carrick-el1-abi/src/ipc_tables.rs:41`, `crates/carrick-el1-abi/src/ipc/epoll.rs:134`, `:665`) → Linux `src/ipc/{authority,epoll}.rs` and `src/abi/ipc.rs`. Reuse fd-core and pipe-core; `PrefixCopy` (`crates/carrick-el1/src/substrate/ipc.rs:57`) → core checked transfer helper, policy-bearing `transfer` (`:126`) → Linux IPC. | `frame.elr - SVC_LEN` replay address (`crates/carrick-el1/src/personality/ipc.rs:661`) and register handback (`:750`) stay native transport around an owned continuation; x86 uses its own SYSCALL instruction/return convention. Guest region mapping/doorbells remain image adapters. IRQ/timer instructions stay native, normalized absolute deadlines enter shared wait APIs. Linux epoll wire packing stays Linux **per-ISA ABI**, not neutral core (`crates/carrick-el1/src/personality/ipc/epoll.rs:56`, `:228`). **A + AI + AW + AL + AM**. |
| **9: file bytes, notification lifetime and Linux file/inotify client** | `ZoneFile`, byte `read_with/pread64_with/write_with/pwrite64_with`, dirty-range marking (`crates/carrick-el1/src/file.rs:268`, `:302`, `:337`, `:414`, `:450`, `:507`) → core `src/io/file_bytes.rs` only after splitting access/status/seek policy. Neutral storage/version fields of `DelegatedFile` (`crates/carrick-el1-abi/src/lib.rs:1106`) → core-abi `io/file.rs`; `DelegatedOpenFile`/Linux offsets and fd rules (`:1148`) → Linux `abi/file.rs`. `linux_result` (`crates/carrick-el1/src/personality/file.rs:25`), `el1_lseek` (`:34`) and wrappers (`:104`) → Linux `src/file.rs`. All `el1_inotify_*` (`crates/carrick-el1/src/personality/inotify.rs:29`, `:118`, `:170`), wd/mask/queue records (`crates/carrick-el1-abi/src/lib.rs:2613`, `:2623`, `:2736`, `:2953`), and policy-bearing `watches::add/remove` (`crates/carrick-el1/src/substrate/watches.rs:5`, `:66`) → Linux `src/inotify.rs`/`abi/inotify.rs`. Only authenticated subscription lock/order/lifetime from `FileAccess` (`crates/carrick-el1/src/substrate/file_notification.rs:9`, `:40`) joins core object subscriptions. | Guarded user copies (`crates/carrick-el1/src/file.rs:23`, `:84`) and the production `HardwareValidator` permission-checking implementation (`:164`) remain ISA adapters implementing the one checked-transfer contract. Host file handles, contained path lookup and external-writer coherence remain host services. Inotify event masks, watch descriptors, event packing, name-cache/path policy and recall/admission rules are Linux, even when frame-independent. **A + AQ + AM + AI + AW**. |

### Order 5: entry is the enabling cut, not a second dispatcher

The hardware boundary should produce a raw native entry snapshot with its ISA
and ABI profile. Linux then decodes ordinals/arguments and lowers errno.
`CanonicalCall` currently embeds a canonical ordinal plus six arguments
(`crates/carrick-guest-arch/src/lib.rs:123`); `EntryArch::decode_syscall` returns
that Linux-shaped result (`:341`). Move that interpretation to Linux while
retaining full native context. Do not broaden six Linux arguments into a
pretend universal syscall ABI, or smuggle Linux errno through a core integer.

**Director's ruling, already given to the order-5 implementer:** ONE routing
and completion owner moves to `carrick-personality-linux` in order 5.
Unmigrated families are reached through one narrow per-family trait defined
in that crate and implemented by `carrick-el1`, with no routing or completion
of their own. Orders 6–8 replace those trait methods with moved bodies; order 9
does the same for file/inotify. This is the required incremental cut.

The current dispatcher directly calls ARM-resident MM, IPC, lifecycle and
futex handlers (`crates/carrick-el1/src/personality/dispatch.rs:384`, `:517`,
`:569`, `:607`). Inverting those calls is part of order 5's fence, not deferred
to the family moves. Planned interfaces in Linux `src/handlers/` are
`LifecycleHandlers`, `MmHandlers`, `IpcHandlers`, `FileHandlers` (including
inotify), and `SchedulerHooks`. Each method accepts one already-selected,
normalized operation and exact execution/MM capabilities. No catch-all
`dispatch(nr, frame)` method, ARM ABI type, or dependency on `carrick-el1` is
allowed in the Linux crate. The existing EL1→Linux dependency
(`crates/carrick-el1/Cargo.toml:9`) is preserved; the planned graph is
`carrick-el1 → carrick-personality-linux → carrick-core/core-abi`; x86 supplies
its own native hooks to that same Linux entry.

The ARM bindings temporarily invoke the existing operation bodies using their
real native context. They return typed refusal, result, retained continuation,
execution-switch or termination outcomes to the Linux owner; they cannot
select a syscall family, publish an entry completion, lower final return
registers, count a served syscall or choose pending-work/restart disposition.
Suboperation settlement still belongs to its exact core resource owner.
Order 5 must remove the lifecycle `serve` ordinal match and served-completion
closure (`crates/carrick-el1/src/personality/lifecycle.rs:131`, `:139`, `:149`),
including its exit completion (`:188`), rather than wrap that whole function
as a trait method. Apply the same split to dispatch's IPC/futex completion
branches (`crates/carrick-el1/src/personality/dispatch.rs:519`, `:608`). A
switch carries the exact successor execution binding, so completion cannot
overwrite the switched-in task's result. No fake ARM frame is constructed for
x86. Replacing a trait body in orders 6–9 changes its implementation, never
introduces another routing/completion path.

Linux futex policy moves in order 5: opcode/admission/alignment/bitset decode
(`crates/carrick-el1/src/personality/sched.rs:16`), wait/wake serving (`:31`),
relative-timespec validation and the current timed-wait admission restriction
(`:51`, `:62`, `:69`), plus EAGAIN and ETIMEDOUT interpretation (`:10`, `:11`,
`:86`, `:87`). Linux `src/sched.rs` converts the normalized timeout cause to
Linux ETIMEDOUT for IRQ and idle completion (`:90`, `:93`). Clock sampling,
timer programming, IRQ acknowledgement and native context switching stay
behind ISA hooks; shared wait ownership remains core. The policy restriction
does not disappear during the move. Neither `serve_irq` nor `serve_idle_entry`
can be classified wholesale as retained hardware IRQ service.

Split pending-work handling into neutral completion ownership and Linux
signal/restart ordering. The current dispatch deliberately preserves a resumed
IPC operation before fd lookup when host work is pending
(`crates/carrick-el1/src/personality/dispatch.rs:307`). The new entry must retain
that property. ARM's currently served families stay callable through the
traits from the one entry; they do not become unported refusals merely because
their bodies have not moved. On x86, an unavailable family is an explicit,
side-effect-free refusal with an audited denominator. Delete the displaced
ARM dispatcher in order 5 and each temporary body as its family moves. No
permanent `common_entry_v2` beside the ARM dispatcher.

### Order 6: lifecycle has neutral state and substantial Linux policy

Neutral birth is reserve → initialize → publish or abort; exit requires exact
membership/admission → retirement → completion. Keep pool claim generations,
close/drain and rollback in core. `publish` races an exiting birth
(`crates/carrick-el1-abi/src/thread_lifecycle.rs:1113`); `ExitAdmission::drop`
restores the correct state (`:262`). Do not replace this with sampled census
or a copyable exit token. Core retains `ThreadLedgerActivity`
(`crates/carrick-core-abi/src/lifecycle.rs:8`).

Linux owns clone flag validation, visible tid/pid namespaces, uid/NPROC credit,
mask inheritance, robust-list interpretation, last-thread/process exit,
clear-child-tid copyout and futex wake ordering. The mixed ABI explicitly holds
visible tid/uid credit (`crates/carrick-el1-abi/src/thread_lifecycle.rs:294`),
clone flags and clear-tid (`:308`); those fields must not move unchanged into
core. Linux sidecars are exact-generation-owned and retire with the thread,
not private maps keyed by recycled visible tid. The child result/stack/TLS is
prepared through an ISA context hook after Linux selects the clone convention;
x86 clone argument order must be decoded by its Linux ABI codec.

Scope is conservative: the existing zone exit refuses robust lists, pending
signals and host-adopted jobs (`crates/carrick-el1/src/personality/lifecycle.rs:546`,
`:550`, `:573`), and only clears/wakes after nonfinal exit admission (`:591`,
`:603`). A move does not fill those semantic gaps. X5 must test both refusal
without effects and the admitted path. Full host-job retirement or robust
death support requires transfer of the actual completion authority; do not
drop the checks to make a CPL0 test pass.

Retain the existing host terminal-clear sequencer as a caller of the same
Linux clear/futex policy, not as a new CPL0-only completion path:
`retire_with_child_tid_clear` and `wake_persistent_child_tid`
(`crates/carrick-runtime/src/vcpu_loop/threads.rs:104`, `:127`). Switching its
policy call is an explicit order-6 dependency; host execution/job teardown
stays with its runtime authority. No extra relocation credit is assigned to
this host code in the guest-package forecast.

### Order 7: finish owner seams; do not re-extract COW

The residual portal census is 6,591 lines: production/mod/fork/maintenance/
edit-wait 1,396; tests/test-support/x86-tests **5,195**
(`crates/carrick-el1/src/personality/mm_portal/tests.rs:918`,
`crates/carrick-el1/src/personality/mm_portal/test_support.rs:1`,
`crates/carrick-el1/src/personality/mm_portal/x86_tests.rs:1`). Fault/COW/memory
add 5,301, but their code before trailing test modules is only 932/173/863
lines respectively (`crates/carrick-el1/src/fault.rs:1113`,
`crates/carrick-el1/src/cow.rs:198`, `crates/carrick-el1/src/memory.rs:1024`).
The whole 11.9k is not a fresh neutral production owner.

Extend existing MMU/fault/COW capabilities for normalized fault inputs,
retired-span discovery and exact maintenance completion. Shared orchestration
must release root/editor before physical supply. Maintenance currently holds
both guards (`crates/carrick-el1/src/personality/mm_portal/maintenance.rs:21`)
and rejects replacement aliasing the predecessor (`:130`); preserve that
transaction shape and same-VA peer bytes. Move architecture-independent
assertions into core; leave real ARM descriptor/ASID/alias tests with ARM and
add x86 descriptor bindings. Merely moving an ARM fixture into core does not
make its geometry portable.

Linux owns brk's unchanged-break refusal, mmap placement/flags/protection,
mremap/madvise semantics, DONTFORK/WIPEONFORK and errno. The current mmap decoder
checks Linux flags/offset and chooses placement
(`crates/carrick-el1/src/memory.rs:186`); `LinuxForkPolicy` reads inheritance
flags (`crates/carrick-el1/src/personality/mm_portal/fork.rs:55`). These belong
in the existing Linux client. `NativeOwnerVenue::encode_error`
(`crates/carrick-el1/src/personality/mm_portal/production.rs:34`) must become
Linux encoding, not an ostensibly native hardware callback. Any wire-format
change is one versioned change across host, image and layout hashes.

The remaining host-side ARM authority is not another guest owner to copy.
`Stage1Authority::prepare_guest_descriptor_txn` and
`execute_guest_descriptor_txn_as_host`
(`crates/carrick-aarch64/src/stage1_authority.rs:500`, `:567`) remain host
setup/physical-maintenance adapters; an admitted operation must instead call
its moved core owner. `retire_table_capacity` already composes core retirement
(`:796`, `:812`); keep the host arena publisher, source and physical teardown
there.

**Order 7 also shares the aggregate prepared-write consumer.** `PreparedWrite`
(`crates/carrick-aarch64/src/user_transfer/prepared.rs:46`) is mixed, not wholly
an ISA adapter. Generic `prepare` (`:65`, `:66`), `settle` (`:177`),
`PreparedGuestWrite::commit` (`:228`) and `Drop` (`:252`) orchestrate aggregate
preparation, exact settlement, short-prefix delivery and cancellation. Move
that protocol and its portable witnesses to
`carrick-core/src/mm/transfer/prepared_write.rs`, using neutral service/pin
hooks. Reuse the existing exact permit/operation records
(`crates/carrick-core-abi/src/mm/transfer.rs:137`, `:181`), extending core-abi
`src/mm/transfer.rs` with neutral typed outcomes as needed. Core must not
import ARM `TrapError`, native frames or Linux `MemoryPrepareError` variants
unchanged. The numeric errno checks
(`crates/carrick-aarch64/src/user_transfer/prepared.rs:148`, `:161`) are Linux
ESRCH/EFAULT interpretation and move to
`carrick-personality-linux/src/mm/transfer.rs`, which also implements the
Linux-facing consumer/error conversion over the neutral aggregate.

`CurrentService` and its `PreparedService::run` ARM service transport
(`crates/carrick-aarch64/src/user_transfer/prepared.rs:26`, `:33`, `:35`),
`prepare_current`'s native executor loan (`:53`), and physical pin/copy effects
(`:199`) remain adapters. Hooks supply those effects; they must not own a
second prepare/settle/cancel loop. The hardware-free witnesses prove all pages
prepare before consumption and short-prefix delivery (`:402`), cancellation
of earlier permits when a later prepare suspends **before returning the
executor loan** (`:438`), and unused-page cancellation on short delivery/drop
(`:464`). Move these assertions with the shared consumer, preserving their
ordering, and bind ARM plus x86 transport implementations before either lane
admits aggregate copyout. X6's VM-free controls and X7's retained byte-transfer
controls use this one consumer; a separate x86 implementation is forbidden.
Allow 350–425 relocated lines, planning value 400 (350 core/ABI, 50 Linux),
including portable witnesses, from this 483-line host-engine source footprint.
This is added explicitly to the order-7 forecast below, not claimed to execute
in the guest image.

The vfork share counter (`crates/carrick-aarch64/src/stage1_authority.rs:728`,
`:733`) remains mixed host lifetime debt: a future typed MM-share lease needs
its own host/core review and two-ISA binding. Wave 2 does not credit that
counter or the entire host engine as moved guest logic. Include exact host
adapter retirement/transfer controls in AM/AR; KVM does not qualify their HVF
physical publication.

### Order 8: IPC is mostly a Linux client, not a 6k neutral core

Move object generation, operation ownership, readiness publication and retained
byte progress to core. Keep Linux pipe atomicity/packet rules, eventfd counter/
semaphore semantics, epoll masks/ET/ONESHOT, fd allocation/CLOEXEC/CLONE_FILES,
SIGPIPE/EPIPE/EINTR and signal-mask transitions in Linux. The current operation
record includes eventfd value, original ARM x0/syscall number, completed result
and CNTVCT deadline (`crates/carrick-el1-abi/src/ipc.rs:660`). Its wire cannot
be copied wholesale into a neutral ABI. Normalize clock deadlines and make
completion ownership explicit; retain typed Linux payloads outside core.

Reuse the existing fd/pin and pipe owners imported at
`crates/carrick-el1-abi/src/ipc.rs:95`; do not create a competing fd table or
force another personality through Linux fds. Core object pools must not import
fd-core policy types. Split actual pool/slot logic, keeping a typed Linux
authority over core object capabilities. The original token becomes invalid
on finish (`crates/carrick-el1-abi/src/ipc.rs:1683`). Close/reuse cannot redirect
a retained operation to the replacement fd.

The existing epoll codec specifies AArch64's **16-byte** event
(`crates/carrick-el1/src/personality/ipc/epoll.rs:56`) and writes data at offset
8 (`:234`). Do not share that wire layout with x86 blindly: add an independently
qualified Linux x86 codec and numeric-errno/output oracle before admitting it.
Mixed host/zone sets currently restore harvested reports before forwarding
(`:221`); preserve the no-lost-event behavior. Readiness and byte-prefix
mechanics can be shared; wire packing and mixed-set policy are Linux.

### Order 9: retain file/Linux boundaries and bounded notification work

Core can own bounded cached bytes, storage identity, dirty spans and exact
subscription lifetime. Access checks, open-file offsets/status, SEEK_* error
precedence, watch masks/wd allocation, Linux path/hash/name cache and event
serialization remain Linux. `FileError` currently includes `Forward` and
access/offset outcomes (`crates/carrick-el1/src/file.rs:525`); split a neutral
byte-operation outcome from Linux completion/admission rather than export
`Action::Forward` as a core I/O error.

The current inotify client forwards modifier masks it does not admit
(`crates/carrick-el1/src/personality/inotify.rs:20`, `:41`), and watch mutation
locks file before instance (`crates/carrick-el1/src/substrate/watches.rs:13`).
Preserve transactional admission, lock order, rollback and ready publication.
Extraction does not promise wider path/cache/external-writer semantics or
erase N4's born-in-zone requirement. Inotify is a Linux notification client,
not the generic notification primitive for every personality.

## Dependencies and why this sequence

| Dependency | Reason and admission condition |
| --- | --- |
| Wave 1 + in-flight 4b → every order | Consume the existing MM/wait/retirement capabilities and 4b's shared production protect/retire and transfer-service path. Requalify X1–X3's actual CPL0 execution before using them as predecessors, including cross-MM transfer and the peer-physical-pin rejection. Source movement and hardware callback tests alone are insufficient; N1 signed development is not a prerequisite for the x86 rung. |
| 5 → 6/7/8/9 | Order 5 owns all routing/completion and defines the per-family traits in Linux; ARM implements only operation bodies/native hooks. This dependency inversion preserves ARM calls without a Linux→EL1 cycle. Orders 6–8 and then 9 replace trait bodies with shared implementations; x86 admission grows through the same entry. |
| 5 + Wave 1 → 6 | Clone outputs and clear-tid use the existing checked MM transfer and wait owners. Birth/exit must preserve exact membership before object operations become widespread. Consume any newer N1 terminal-clear/adoption fixes, never overwrite them. |
| 5 + 6 + Wave 1 → 7 | Resumed fault/edit work needs the exact execution generation and lifecycle cancellation. Finish checked user-copy, maintenance and the neutral aggregate prepared-write consumer before IPC introduces larger retained transfers. A later preparation suspension must cancel prior permits before releasing its executor loan. |
| 5 + 6 + 7 → 8 | IPC needs typed entry/re-entry, exit/exec cancellation, MM transfer permits and release-before-enroll. Linux epoll codecs must be qualified before their KVM handler is admitted. |
| 5 + 7 + 8 → 9 | File/inotify reuse the checked transfer and generic subscription owners; adding a separate notification waiter here would duplicate IPC lifetime machinery. |

Orders 6 and 7 can be prepared against their disjoint symbol fences, but their
executing gates run in the sequence above. No claim of safe parallel edits to
the entry, ABI layout, scheduler context, or shared test-support files. One
integrator owns those seams and re-inventories the clean integrated tree.
ARM bindings/callers switch in each extraction commit, not at the final N1
rebase; a signed queue delay cannot justify leaving a second ARM owner alive.
The director tracks the baseline comparison packet for every moved SHA while
x86 advances independently. A new ARM signed regression requires a shared fix
and re-proof; unresolved comparisons remain explicit acceptance debt.

## Gates for every shared extraction

**A:** move existing assertions with their owner, run them with ARM and x86 MMU/
context adapters, then run these VM-free targets from repo root:

```sh
cargo test --locked -p carrick-core --test x86_acceleration
cargo test --locked -p carrick-core -p carrick-core-abi -p carrick-personality-linux --lib
cargo test --locked -p carrick-mmu-core -p carrick-sched-core -p carrick-el1-abi --lib
cargo test --locked -p carrick-conformance-contract --lib personality_boundary
```

Keep X1/X2/X3 and `x4_shared_wait_records`; existing source anchors are
`crates/carrick-core/tests/x86_acceleration.rs:225`, `:442`, `:867` and
`crates/carrick-core/tests/x86_acceleration/fork_cow.rs:213`. Some core witnesses
still borrow EL1 test support (`crates/carrick-core/tests/x86_acceleration.rs:8`):
move portable fixtures once and retain architecture-specific fixtures locally.
Do not keep an obsolete owner alive for its former test path.

Before each move run the source tests listed below. Afterward keep assertions,
scales and fault injection in the proposed exact X4–X8 targets. New contracts
and execution bindings are required **red-first before implementation**, not
added by this docs-only change. Reject zero-test runs and missing bindings.

| Gate | Existing witnesses / contracts and exact pre-move VM-free command |
| --- | --- |
| **AE: entry/completion** | `cargo test --locked -p carrick-el1 --lib personality::common_entry`; `cargo test --locked -p carrick-el1 --lib personality::dispatch`; `cargo test --locked -p carrick-el1 --lib substrate::sched::tests`; `cargo test --locked -p carrick-x86 --lib cpl0_entry::tests`. Preserve `kernel.el1.task-load-entry` (`conformance-contracts/contracts/task-load-entry.toml:2`). Add **new** `core.entry.completion` for wrong generation, unported ordinal, pending work, one completion and no semantic host dispatch; Linux entry witnesses must exercise each retained ARM family binding, futex admission and IRQ/idle ETIMEDOUT policy. Reject a binding that routes or completes independently, a Linux→EL1 dependency, double completion after a switch, and any silently dropped currently served ARM family. |
| **AL: lifecycle/Linux policy** | `cargo test --locked -p carrick-el1-abi --lib thread_lifecycle`; `cargo test --locked -p carrick-el1 --lib personality::lifecycle`; `cargo test --locked -p carrick-kernel --lib prepared_parent_exit_`. Preserve pool claim/revoke one-winner and exit-admission rollback (`crates/carrick-el1-abi/src/thread_lifecycle.rs:1380`, `:1516`), tid-copy rollback (`crates/carrick-el1/src/personality/lifecycle/tests.rs:464`), clear/wake (`:860`) and host-job refusal (`:882`). `kernel.el1.thread-lifecycle` explicitly retains terminal-clear/adoption gaps (`conformance-contracts/contracts/el1-thread-lifecycle.toml:46`); add **new** `core.lifecycle.publication` for the extracted neutral state. |
| **AM/AF/AW/AR + AX: residual MM** | `cargo test --locked -p carrick-el1 --lib personality::mm_portal::tests`; `cargo test --locked -p carrick-el1 --lib fault::tests`; `cargo test --locked -p carrick-el1 --lib cow::tests`; `cargo test --locked -p carrick-el1 --lib memory::tests`; `cargo test --locked -p carrick-aarch64 --lib user_transfer::prepared::tests`. Preserve fork undo (`crates/carrick-el1/src/personality/mm_portal/tests.rs:2484`), retained parent-write abort (`:2547`), partial retirement (`:918`), and release-before-enrollment (`:3781`). Preserve the aggregate prepare/short-prefix/cancel-before-loan-return witnesses (`crates/carrick-aarch64/src/user_transfer/prepared.rs:402`, `:438`, `:464`) in the shared consumer with both service/pin bindings. Preserve `kernel.el1.mm-exclusive-owner` (`conformance-contracts/contracts/el1-mm-exclusive-owner.toml:2`) and `kernel.el1.fault-entry` (`conformance-contracts/contracts/el1-fault-entry.toml:11`); extend bindings for both geometries, not a duplicate owner contract. |
| **AI: IPC** | `cargo test --locked -p carrick-el1-abi --lib ipc`; `cargo test --locked -p carrick-el1 --lib personality::ipc`; `cargo test --locked -p carrick-fd-core -p carrick-pipe-core --lib`. Retain blocked-read fd reuse, partial-write no replay, SIGPIPE after progress, and pending-work repark (`crates/carrick-el1/src/personality/ipc.rs:1913`, `:1965`, `:2031`, `:2332`). Bind `kernel.el1.ipc-lifecycle`, `kernel.el1.ipc-fd-authority`, `kernel.el1.ipc-two-process`, `kernel.el1.epoll-zone` (`conformance-contracts/contracts/el1-ipc-lifecycle.toml:2`, `conformance-contracts/contracts/el1-ipc-fd-authority.toml:2`, `conformance-contracts/contracts/el1-ipc-two-process.toml:2`, `conformance-contracts/contracts/el1-epoll-zone.toml:2`). Add **new** `core.object.subscription` for neutral pin/close/operation races. |
| **AQ: file/inotify** | `cargo test --locked -p carrick-el1 --lib personality::file`; `cargo test --locked -p carrick-el1 --lib personality::inotify`; `cargo test --locked -p carrick-inotify-core --lib`; `cargo test --locked -p carrick-kernel-example --test contracts inotify09_hotpath` (bindings at `crates/carrick-kernel-example/tests/contracts.rs:267`, `:280`). Preserve `kernel.el1.files`, `kernel.inotify.watch`, `kernel.inotify.readiness`, `kernel.inotify.mark-race-hotpath` (`conformance-contracts/contracts/el1-files.toml:2`, `conformance-contracts/contracts/inotify-watch.toml:2`, `conformance-contracts/contracts/inotify-readiness.toml:2`, `conformance-contracts/contracts/inotify-mark-race-hotpath.toml:2`). Add **new** `core.io.file-bytes` only for newly extracted neutral bytes/dirty-span work; Linux event/error tests remain Linux. |

Freeze deterministic work at at least three scales **before** altering bodies.
Birth/exit counts scale with affected threads, not all historical tasks;
MM work scales with touched leaves/tree height and extent crossings, not
unrelated VMAs; IPC visits enrolled subscribers/ready members, not all objects;
cached byte work scales with transferred bytes and dirty spans. Keep existing
limits exactly; add stable units with fail-closed measurement, not permissive
time budgets. Linux authority is the descriptors' man-pages and pinned
source-hash-qualified oracle, not the host OS's errno or scheduler answer.

P0 policy enforcement must accompany the moves. The current MM owner imports
ARM-named shared types (`crates/carrick-core/src/mm/transaction/owner.rs:12`)
and accepts error encoding in `OwnerVenue` (`:29`); these are explicit seam
debt, not permission for Linux semantics in new core modules. Add negative
boundary fixtures for clone bits, signal masks, errno, fd exec policy, eventfd
and epoll masks; reject production dependency leaks and opaque integer payloads.
The order-5 boundary gate must reject `carrick-personality-linux` imports of
`carrick-el1` implementations (the reverse dependency) and routing/completion
inside a temporary family binding. Trait definitions and normalized
request/result types live in Linux; hardware bindings consume them, never the
reverse.
No broad rename of shared MMU modules to hide their ISA responsibilities.

Workers run focused tests, changed-crate Clippy with `--all-targets -- -D warnings`,
`just fmt-check`, and `just lint-domains`. The director owns the full stacked
gate; no worker `just accept`/`remote-accept`, Docker phase or signed-host queue
takeover. Reconcile inventories on the clean integrated tree before lint.

### Unchanged-ARM signed packet

For each move the ARM requirement is **no new signed failure versus
`56bf8c0ca`**, preserving assertions and budgets. The director records the
baseline packet and affected per-move packet independently of x86's KVM
execution schedule; N1 stays paused until the settled-core rebase. No signed
receipt is inferred from source or KVM results. The Mac runner rebuilds/signs
each compared SHA and records its artifact identity, then:

```sh
just build
just --no-deps test-embed el1_ --nocapture
just --no-deps test-embed inotify_hotpath_contract_budget --exact --nocapture
```

The `el1_` packet does **not** select `inotify_hotpath_contract_budget`
(`crates/carrick-embed/tests/inotify_hotpath_contract.rs:41`). The signed runner
uses substring selection (`scripts/lib/test-signed-body.sh:348`) and rejects
only an entirely empty substring selection (`:362`); other EL1 witnesses do
not prove this contract ran. Exact selection requires exactly one test
(`:342`, `:357`). The director's current acceptance command also uses `el1_`
(`crates/carrick-xtask/src/accept.rs:1106`, `:1112`), so its existing receipt
alone is insufficient. Require the explicit exact invocation's execution
receipt **alongside** the EL1 packet, on the same integrated source, recording
each signed test executable's identity, the test name, nonzero execution and
observed structural-budget results. Preserve zero host watch registrations,
preparatory position queries and queue scans
(`conformance-contracts/contracts/inotify-mark-race-hotpath.toml:47`, `:54`,
`:61`); missing measurement or an absent budget receipt blocks order 9's ARM
non-regression claim and final N1 promotion even if the EL1 packet is green.
It does not hold the x86 executing rung behind the N1 signed queue.

Retain the N1 driver's current complete packet and Wave 1 AM/AF/AW/AR. In
particular preserve:

| Order | Existing signed witnesses that must still bind |
| --- | --- |
| 5 | `el1_task_load_costs_no_host_round_trip` (binding in `conformance-contracts/contracts/task-load-entry.toml:34`); fault context preservation (`conformance-contracts/contracts/el1-fault-entry.toml:32`); admitted robust-list calls and pending-work completion |
| 6 | `el1_thread_lifecycle_spawn_slope`, `el1_thread_lifecycle_cleartid_tid_reuse`, fork/exit-group/exec during clone storm, and parked threads beyond default executor capacity (`crates/carrick-embed/tests/el1_sched.rs:4374`, `:4461`, `:4487`, `:4498`, `:4539`); add missing clear-tid-across-exec/retained-predecessor binding explicitly |
| 7 | anonymous frame return/reuse and cross-vCPU edit/fork/exec stale-translation controls (`crates/carrick-embed/tests/el1_sched.rs:2583`, `:2738`, `:2942`); host copyout's exact live-MM binding and maintenance zero/regrowth controls from N1 |
| 8 | inherited descriptor lifetime, two-process blocking IPC and epoll ping-pong (`crates/carrick-embed/tests/el1_sched.rs:1114`, `:1141`, `:1397`); mixed host/zone and signal/close controls |
| 9 | file bytes/shared inode/path mutation/cross-process readers (`crates/carrick-embed/tests/el1_files.rs:15`, `:72`, `:145`, `:351`) and inotify/churn (`crates/carrick-embed/tests/el1_inotify.rs:16`, `:257`), **plus the separately invoked `inotify_hotpath_contract_budget` execution receipt** (`crates/carrick-embed/tests/inotify_hotpath_contract.rs:41`) |

A missing comparison receipt or new affected failure blocks N1 promotion.
Baseline failures remain named debt, never relabeled as green; preserve the
same zero-work budgets and distinguish pre-existing failures from new ones by
their measured observations. Preserve the invalidation negative control.
Compare baseline/pre/post-move source, CLI/test/fixture SHA-256,
CDHash, LC_UUID, entitlement, DOF and layout hashes plus scoped cleanup.
After the single N1 rebase, the director runs the final signed gate sequence
below. Docker remains a separate director phase.
X4–X8 do not close N1/N3 performance, N4 external-writer coherence, or whole
Linux workload coverage.

## CPL0 milestones

All commands below run from repo root. **New** targets/functions must be added
with nonzero test registration and production bindings; these commands are
implementation instructions, not tests run by this audit. Before every KVM
rung, with no live guest using the image, build its exact image:

```sh
cargo build --locked --release -p carrick-x86-cpl0 --target x86_64-unknown-none
```

Record image/test/source hashes, ELF build identity, KVM CPU capabilities,
vCPU/page geometry, nested-host status, run ID, all raw streams and scoped
cleanup. Do not use the no-allocation bootstrap image for allocating owners;
bind the existing shared capacity owner with ISA aperture hooks first. Missing
KVM/image, zero population, missing counters or unbound required contract is
a failure, not a skip.
X4 follows the executing 4b/X1 predecessor; X5–X8 use the preceding integrated
x86 rung. None requires N1 to resume or complete its signed development
stack. ARM callers and VM-free bindings still switch atomically with each
move, and the per-move baseline comparison remains an acceptance obligation.

| Milestone / prerequisites | Shared execution / N1 defect classes exposed | VM-free first → exact KVM command (all Wave 2 names **new**) |
| --- | --- | --- |
| **X4: native entry into one Linux dispatch** / order 5 | CPL3 issues admitted robust-list, private-futex wake through bound native scheduler/MM hooks, and side-effect-free malformed/unported calls; CPL0 uses one Linux decode/dispatch and core execution binding. VM-free controls exercise retained ARM per-family bindings through that same owner, futex admission and IRQ/idle timeout-result policy; x86's unavailable bodies refuse without effects. Two live tasks reuse visible IDs under different exact generations. Entry/return kicks must not repeat publication/completion. Catches wrong current task after switch, canonical/native ordinal aliases, stale generation, result clobber, a binding's duplicate completion, dropped ARM family and pending-work double dispatch. | `cargo test --locked -p carrick-personality-linux --test x86_wave2 x4_linux_common_entry -- --exact` → add in existing `cpl0_entry`: `CARRICK_RUN_ID=x4-wave2-entry cargo test --locked -p carrick-vmm-kvm --test cpl0_entry x4_linux_common_entry -- --exact --nocapture` |
| **X5: shared birth/retirement and Linux clone/clear-tid** / orders 5–6; Wave 1 MM/wait | CPL0 prepares/publishes thread births, runs children, joins admitted nonfinal exits through Linux clear-tid, and cancels unpublished births. Two live processes, tid/entry reuse, parent/child tid-copy failure, exit-vs-publish/exec close, stale completion and host-adopted-job refusal. Check native TLS/extended context separately. Catches birth before resources commit, pool leaks/double release, wrong-MM clear, lost futex wake, successor tid clear and premature terminal notification. | `cargo test --locked -p carrick-core --test x86_wave2 x5_lifecycle_publication -- --exact` **and** `cargo test --locked -p carrick-personality-linux --test x86_wave2 x5_linux_clone_exit -- --exact` → new `cpl0_lifecycle`: `CARRICK_RUN_ID=x5-wave2-lifecycle cargo test --locked -p carrick-vmm-kvm --test cpl0_lifecycle x5_shared_clone_exit -- --exact --nocapture` |
| **X6: residual owner maintenance and normalized faults** / orders 5–7; executing X1–X3 | CPL0, not a host callback, services first-touch/COW, protect/unmap and pending brk contraction/regrowth. Two same-VA MMs and a retained fork peer; inject grant refusal, alias rollback, parent-write abort, stale maintenance request and late descriptor completion. VM-free shared aggregate controls cover later-prepare suspension, exact commit/cancel, short-prefix delivery and cancellation before executor-loan return with both transport bindings. Catches brk waiting on its own closed gate, zeroing shared predecessor bytes, grant/pin misordering, partial compound return, hole resurrection, leaked aggregate permits and lost drain/retirement authority. | `cargo test --locked -p carrick-core --test x86_wave2 x6_residual_mm_owner -- --exact` **and** `cargo test --locked -p carrick-personality-linux --test x86_wave2 x6_linux_mm_entry -- --exact` → existing `carrier_memory` new CPL0-backed case: `CARRICK_RUN_ID=x6-wave2-mm cargo test --locked -p carrick-vmm-kvm --test carrier_memory x6_residual_mm_owner -- --exact --nocapture` |
| **X7: in-zone IPC through shared object/wait owners** / orders 5–8 | CPL3 pipe/eventfd/epoll clients execute Linux IPC on core generation/pin/progress owners in CPL0. Two process tables, retained operation across close/dup/reuse, large partial write, writer-close/EOF, signal-after-progress, epoll timeout/ready/close and entry pending work. Catches replayed prefixes, wrong object after fd reuse, missed wake, double unpin, stale operation successor, mixed-harvest loss and ARM epoll packing on x86. | `cargo test --locked -p carrick-core --test x86_wave2 x7_object_subscription -- --exact` **and** `cargo test --locked -p carrick-personality-linux --test x86_wave2 x7_linux_ipc -- --exact` → new `cpl0_ipc`: `CARRICK_RUN_ID=x7-wave2-ipc cargo test --locked -p carrick-vmm-kvm --test cpl0_ipc x7_shared_ipc -- --exact --nocapture` |
| **X8: cached bytes and Linux inotify** / orders 5,7–9 | CPL0 executes checked cached read/pread/write/pwrite plus Linux watch add/remove/read. Two live file tables observe one shared storage object; unrelated object changes remain isolated. Copy faults, cache-version replacement, watch reuse/close/cancel and bounded churn. Catches dirty-span loss, offset cross-talk, stale cache generation, dead watch alias, ready publication loss and file/instance lock inversion. Host operations only cross the contained real-file boundary. | `cargo test --locked -p carrick-core --test x86_wave2 x8_file_bytes -- --exact` **and** `cargo test --locked -p carrick-personality-linux --test x86_wave2 x8_linux_file_inotify -- --exact` → new `cpl0_file`: `CARRICK_RUN_ID=x8-wave2-file cargo test --locked -p carrick-vmm-kvm --test cpl0_file x8_shared_file_inotify -- --exact --nocapture` |

VM-free matrices must instantiate both native adapters and mutate the same
receipt fields. KVM observations need nonzero CPL0 owner entry/completion,
actual bytes/context, zero semantic host forwards for admitted in-zone work,
balanced pins/capacity and no host process growth per guest task. Fixture
doorbells used for observation must be counted separately from semantic
forwards. No host implementation that answers the tested fault or syscall.

X5 uses 16/64/256 births; X6 retains 16/64/256 touched pages and 16/512 unrelated
mappings, both 4 KiB and 16 KiB compound custody in VM-free geometry. X7 uses
1/8/64 pairs, 128 rounds, plus `max(32, actual_executor_count + 1)` participants
with overrides unset. X8 uses 1/8/32/128 affected storage/watch populations
and an independent unrelated-object population. Freeze exact affine budgets
from current owners before moves; do not invent a larger ceiling here.

The existing CPL0 progress fixture is single-vCPU
(`crates/carrick-x86-cpl0/src/progress.rs:71`). It cannot prove production
default-pool exhaustion or multi-vCPU shootdowns. X5/X7 need the carrier's real
execution-pool binding and X6 needs exact multi-vCPU invalidation/drain before
those claims close. Until that capability is qualified, report the missing
binding and retain the signed production witness; do not reduce concurrency,
poll, enlarge the pool/timeout or relabel a fixture pass as pool acceptance.

## Size forecast and explicit residue

Estimates count **existing source and witnesses relocated**, not new features
or tests. Do not sum overlapping candidate files twice: dispatch moves only
its own routing body, not lifecycle/IPC/MM bodies; MM moves portable portal
fixtures once; file/IPC share checked transfer without duplicating it. Ranges
reflect mixed-file splits and architecture-bound tests, not measured patches.
These estimates retain the `56bf8c0ca` denominator. They are not additional
credit on top of 4b: at its integration SHA, subtract any overlapping
protect/retire or transfer-service relocation from order 7 and refresh the
candidate table before implementation. The 400-line aggregate consumer move
excludes native service transport; consume 4b's shared transport rather than
inventing or crediting another one. No measured 4b diff or line delta is
claimed here.

| Order / target | Current candidate footprint | Move range / planning value | Planning split core+ABI / Linux | ARM-resident remainder after order (no new glue) |
| --- | --- | --- | --- | ---: |
| Before Wave 2 | 50,773 ARM-resident | — | Shared subtotal 17,006 | **50,773** |
| 5 / X4 entry | dispatch 1,713 + common entry/tests 265 + Linux sched/futex policy 85; selected task/entry fields, normalized per-family traits and ARM bindings | 1,700–2,100 / **2,000** | 250 / 1,750 | **48,773** |
| 6 / X5 lifecycle | lifecycle/tests 1,405 + lifecycle ABI 1,475; thread setup and selected context-interface splits | 2,100–2,600 / **2,400** | 1,000 / 1,400 | **46,373** |
| 7 / X6 residual MM | portal 6,591 + fault/COW/memory 5,301; selected residual portal records; aggregate prepared-write consumer/tests from a 483-line ARM host-engine file | 3,350–4,625 / **4,200** | 1,750 / 2,450 | **42,173** |
| 8 / X7 IPC | personality IPC 2,334 + IPC ABI/tables/tests 4,325; substrate transfer helpers | 5,300–6,500 / **6,000** | 1,400 / 4,600 | **36,173** |
| 9 / X8 file/inotify | personality file/inotify 1,094; substrate bytes/notifications and selected mixed ABI fields | 1,200–1,700 / **1,600** | 450 / 1,150 | **34,573** |
| **Total relocated** | Mixed candidates, not all neutral | **13,650–17,525 / 16,200** | **4,850 / 11,350** | Range **33,248–37,123** |

Current footprint anchors are the order table's cited files. In particular,
dispatch's trailing tests start at
`crates/carrick-el1/src/personality/dispatch.rs:1044`; lifecycle's external
tests at `crates/carrick-el1/src/personality/lifecycle/tests.rs:1`; IPC's tests
start at `crates/carrick-el1/src/personality/ipc.rs:771`, with separate ABI
tests at `crates/carrick-el1-abi/src/ipc/tests.rs:1` and
`crates/carrick-el1-abi/src/ipc/epoll/tests.rs:1`. The numbers describe the
same census rule above, including tests, not thousands of newly shared live
handlers. Relocation into Linux is ISA sharing **without** declaring Linux
policy neutral. Order 5's planning range includes the 85-line Linux sched/futex
source and removal of completion from retained bodies; its new traits/bindings
are adapter allowances rather than relocation credit. Order 7 separately adds
350–425 aggregate-consumer lines (400 at the planning value) to the original
3,000–4,200 residual-MM range. The aggregate's generic body occupies lines
65–258 and hardware-free witnesses/fixtures lines 260–495 in
`crates/carrick-aarch64/src/user_transfer/prepared.rs:65`, `:260`; native
transport and Linux interpretation are split rather than moved wholesale.

At the planning values, shared owners+ABI grow from **16,387 to 21,237** and
the shared Linux client from **619 to 11,969**: **33,206 shared package lines**.
ARM-resident source falls to **34,573**, x86-owned source remains **5,805**
before new adapters. Image+wire ARM debt alone falls from **35,063 to 19,263**;
the ARM host-engine package falls from **15,710 to 15,310** with only the
aggregate consumer's 400-line planning move, not a wholesale engine move.
Allow **400–900** net new ARM adapter lines and
**700–1,300** x86 adapter lines: practical planning totals approximately
**33.2k shared / 35.0–35.5k ARM-resident / 6.5–7.1k x86-owned**. New witnesses,
policy expansion and manifest/checker work are additional, unestimated source.
The broad footprint with unchanged substrates becomes 114.8–115.9k after
these adapter allowances, not a claimed reduction in runtime work.

With all relocation uncertainty, rather than the planning values, shared
packages are **30,656–34,531**, ARM residue plus new adapters
**33,648–38,023**, and x86 adapters **6,505–7,105**. These are source-placement
forecasts, not 30–34k provably neutral lines or a forecast that all remaining
ARM source is hardware-specific. A later live/cfg-aware census must separate
reachable guest instructions, host engine, policy debt and test-only code.

**Explicitly do not share as neutral owner bodies:** ARM TrapFrame/register
save/restore, SP_EL0/TPIDR state, ESR/FAR decoding, descriptor bits/TTBR/ASID/
TLBI and alias geometry; x86 NativeFrame/IRET/SWAPGS/FS-GS/XSAVE, CR3/PCID,
page-fault bits, APIC/IDT/TSS and KVM port transport; GIC/SGI versus APIC IRQ
instructions and hardware clock/timer programming. Source anchors are
`crates/carrick-el1-abi/src/lib.rs:642`,
`crates/carrick-el1/src/sched.rs:20`, `crates/carrick-el1/src/cow.rs:21`,
`crates/carrick-el1/src/memory.rs:496`,
`crates/carrick-x86/src/cpl0_entry.rs:18`,
`crates/carrick-x86-cpl0/src/entry.rs:41`, and
`crates/carrick-x86-cpl0/src/progress.rs:24`. Shared orchestration calls typed
ISA hooks. Linux signal/epoll/clone ABI codecs are per-ISA **Linux policy**,
not core and not a reason to retain a whole second Linux implementation.

## Dispatch and acceptance limits

After 4b's executing predecessor receipt, the first Wave 2 implementation
unit is order 5's source fence, normalized per-family traits
and ARM bindings, sole Linux routing/completion owner, futex/timeout policy,
typed context seam, AE red controls, and X4. Next: order 6's actual birth/exit
owner and X5, with N1's current clear-tid/adoption fixes intact. Then residual
MM/X6, IPC/X7 and file/X8. Each task reports exact N1 SHA, symbol fence,
source/fixture hashes,
red/green commands, affected signed packet and remaining binding gaps.
No two-week completion promise: production pool, allocator, terminal-clear,
multi-vCPU and Linux codec qualification can block executing milestones.

Nested KVM on VM 210 is discovery capacity, not quiet native performance or
ARM/HVF hardware coverage. No Docker is authorized on this worker. Native
x86 oracle qualification and same-ISA timing are director work; the established
native-arm64 Docker <=2x target stays unchanged. KVM cannot qualify ARM boot
relocation, HVF stage-2 16 KiB custody, signing, DOF, GIC or ARM invalidation.

## Document verification

This plan's only tracked change is
`docs/superpowers/plans/2026-10-06-x86-wave2-extraction.md`.
Documentation exemption covers the entry/lifecycle/MM/IPC/file contract
families above: no owner, ABI, witness, budget or guest artifact changes.
Verify cited paths/line bounds and named-symbol definitions against the pinned
SHA, verify normative links, reproduce the census, run `just fmt-check`,
focused personality-boundary tests/Clippy and
`just lint-domains`, and check the one-file diff. Do not treat those checks as
execution of the proposed X4–X8 tests. No KVM, Docker, signed/HVF or acceptance
receipt is claimed by this audit; signed tests cannot run on this Linux host.

Original publication (`6bdb950f8`) checks on base `09fff7bfa`: 138 explicit
citations across 70 pinned files resolve within bounds; census arithmetic
agrees. `just fmt-check`, the 30 `personality_boundary` tests, focused
conformance-contract Clippy, and staged
`git diff --check` pass. `just lint-domains` fails at its runtime-aborts checker:
`hvf.json` fingerprint drift for `CarrierVmCustody::new #2` in
`crates/carrick-vmm-hvf/src/trap/carrier_custody.rs`. The focused
`python3 scripts/migrate/check-runtime-aborts.py --check` reproduces it; source
and inventory have no diff against that base. This read-only plan leaves the
pre-existing gate failure open and makes no lint/acceptance success claim.

Review-fix commit `8b7dd8424` checks: 153 explicit citations, 307 including
abbreviations, across 75 pinned paths pass bounds checks. Twenty-one relevant
definitions
(entry/file pairs, production validator, futex/IRQ/idle, prepared-write
protocol/witnesses, existing permit/operation records and the inotify budget
test) match their cited symbols; the validator's production cfg is also
checked. The exact budget-selection command, focused census and revised
relocation arithmetic pass. All five normative links are retrievable: three
local targets and two immutable GitHub revisions verified through the
repository API. The 30 personality-boundary tests, focused Clippy and fmt pass;
lint and its focused runtime-aborts checker reproduce the same existing
fingerprint failure. This revision changes no code and claims no signed or
runtime acceptance.

Owner-sequencing follow-up checks: 155 explicit citations, 311 including
abbreviations, across the same 75 paths pass bounds checks. The 4b source
anchors, both exact budget invocations, final N1 rebase section, normative
links and one-document diff pass inspection. Rust, scripts and build/gate
recipes are unchanged from the tested review-fix commit; its focused results
and existing lint failure still apply. No additional runtime receipt is claimed.

## N1 rebase

N1 rebases **once onto the settled shared-core stack**, after 4b and X4–X8
execute their required KVM bindings and interfaces stop changing. The director
publishes an exact settled-core SHA and packet, not a floating branch name.
This pause changes scheduling, not the requirement that every move switch ARM
and x86 callers in the same commit. N1 resumes as a caller of those owners,
not as a second implementation or a cherry-pick of whole old ARM files.

First audit the N1 fix stack since `56bf8c0ca` against the settled core. Record
one ledger row per fix: original SHA/author, defect and exact operation or
generation, old/new owner and symbols, disposition, mapped implementation SHA,
retained witness/scale/budget, pre-fix red and post-fix green receipts, and any
remaining ISA binding. Classify every fix before rebasing:

| Disposition | Required proof |
| --- | --- |
| **Kept** | The fix is still required and already represented by the settled shared owner or the appropriate ISA adapter. Map it to the exact implementation and keep its witness; do not apply a duplicate patch. |
| **Ported** | The defect remains but the responsibility moved. Reapply its semantics to core or Linux policy, or retain the truly ISA-specific fix in its adapter. Switch every caller and preserve authorship; no private ARM correction beside a defective shared body. |
| **Dropped** | The fix is superseded by an identified shared fix, or its responsibility was actually retired. Record the superseding SHA and equivalent witness, or a proof that the retired operation is no longer admitted. Conflict difficulty, an absent witness or a green smoke is not a reason to drop it. |

**Re-prove the red for every fix**, including kept and superseded fixes:
use an isolated pre-fix owner revision or narrowly invert the mapped fix on an
isolated settled-stack worktree, without restoring an obsolete dispatcher.
Run the retained witness at the same population, fault injection and work
budget; record the actual false assertion, exact operation and artifact.
Restore/apply the mapped implementation and prove green with both relevant
VM-free ISA bindings and the applicable executing witness. For a retired
operation, re-run its red at the pre-fix owner and prove the new
refusal/retirement boundary instead of fabricating a live binding. A missing
red or unresolved
disposition blocks the audited rebase packet; do not suppress a fix to make
the rebase compile.

Rebase the audited remaining N1 fixes onto that recorded SHA in the director's
clean N1 worktree. Resolve conflicts by responsibility and exact authority,
preserving the settled shared owner and native hooks; never resurrect the
old owner. Reconcile line-pinned inventories on the clean integrated tree,
refresh source/layout/census receipts and run VM-free/P0 and compile checks
before signing. Carry forward every per-move ARM comparison: **no new signed
failure versus `56bf8c0ca`** is the required bar, not a fresh zero-failure
claim about an already imperfect baseline. New failures require attribution,
a shared/native-owner fix as appropriate, and red/green re-proof.

The director owns this final gate order on the rebased SHA:

1. Run the one full stacked acceptance gate (`just accept`, or its authorized
   remote runner), rebuilding/signing the exact integrated artifact. Record
   source, CLI/fixture hashes, CDHash, LC_UUID, entitlement, DOF and layout
   identities, scoped run IDs and cleanup; preserve the unentitled negative
   control. No worker runs this gate on VM 210.
2. Complete the unchanged-ARM comparison packet on that SHA, including both
   exact commands below and any affected AM/AF/AW/AR bindings. Require separate
   test-executable identities and the inotify budget execution receipt; the
   acceptance runner's `el1_` filter is insufficient. Then run
   `just --no-deps el1-gate` against the held CLI artifact.

   ```sh
   just --no-deps test-embed el1_ --nocapture
   just --no-deps test-embed inotify_hotpath_contract_budget --exact --nocapture
   ```

3. Promote the same CLI artifact through exact-artifact probe → smoke → full:

   ```sh
   just --no-deps conformance-probes
   just --no-deps conformance smoke
   just --no-deps conformance full
   ```

   Verify SHA/CDHash at each rung, with no intervening CLI rebuild/re-sign.
   Docker oracle work is a separate director phase with no live Carrick guest.
   Record unresolved baseline failures and performance/coherence gaps; KVM or
   the extraction census does not close them.

Only the completed fix ledger, per-move baseline comparisons, final signed
packet (including the budget receipt) and exact-artifact promotion constitute
the N1 handoff. Missing evidence stays explicit; the x86 discovery stack is
not retroactively described as signed N1 acceptance.
