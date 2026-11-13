# x86 exec family (#2235, #2142)

Contract: `process.exec.custody`. Linux authority: execve(2) and execveat(2).
Successful replacement must enter the new image without returning; a pre-arm
failure preserves the old image and returns the specific errno. The successor
and its still-live parent must keep independent MMs and inherited descriptors.
No retries, widened budgets or host-side descriptor/stack editor are permitted.

## Existing mechanisms

ARM's root exec owner comes first: `HvpatchExecVenue` implements the shared
`RootExecVenue` in `crates/carrick-runtime/src/vcpu_loop/exec.rs:1800`; the
transaction driver is `crates/carrick-kernel/src/kernel/exec_transaction.rs:133`.
The neutral native-child owner is `begin_exec_service` in
`crates/carrick-el1-linux/src/native_process_runtime/service.rs:1188`.

The x86 loader already uses the shared exec parser and resolver:
`prepare_native_x86_exec_image`, `crates/carrick-runtime/src/runtime/exec.rs:146`.
`stage_native_exec`, `crates/carrick-x86-cpl0-host/src/cpl0_exec.rs:680`, reserves
successor tables/data and imports the closed root. `ParkedX86Exec` retains the
exact request and stock-release revision. `build_x86_successor`,
`crates/carrick-x86-carrier/src/initial_boot.rs:391`, runs boot's existing editor
in CPL0 over the reserved table order, without repeating boot's admission.

Root rebinding is already implemented: `Cpl0RootBinding::replace_exec`,
`crates/carrick-runtime/src/vcpu_loop/executor/cpl0.rs:120`, and
`ProductionCpuLease::retarget_root_exec`,
`crates/carrick-x86-cpl0-host/src/cpl0_boot.rs:1451`. Pending replacement is
venue-typed in `crates/carrick-runtime/src/vcpu_loop/executor/binding.rs`.
These mechanisms must be reused, not rebuilt from the older #2146 inventory.

The remaining production refusals are x86 `CompletionRoute::NativeService`
settlement in `crates/carrick-x86-cpl0/src/linux_personality.rs`, the unmatched
Exec request in `crates/carrick-x86-cpl0-host/src/cpl0_native_service.rs`, and
`ServiceExecMachine`'s three Unsupported crossings in
`crates/carrick-x86-cpl0/src/native_process.rs:222`.

## Witnesses

The static-child and three root cases reuse closed drafts #2149 and #2146.
The child retains its original 32-exit budget; the root cases retain 128.
The new `native_fork_child_execs_while_parent_keeps_running` blocks SIGUSR1
and SIGUSR2 before fork. After replacement, the successor signals SIGUSR1 to
its parent and consumes the parent's SIGUSR2 acknowledgement with
rt_sigtimedwait. The parent receives the successor's signal, acknowledges it,
and only then collects wait4 status and prints `live-exec-ok`. Both signal
waits have a five-second bound; a returned child errno is propagated by the
parent. The syscall census requires that the fixture actually reached exec. The
successor checks initial stack alignment, argc, argv and the empty environment,
then writes and reads its stack before announcing replacement.

This uses signal-owner operations rather than in-zone pipes: the separate
`in_zone_child_pipe_write_without_ipc_execution_is_counted_enosys_in_ring`
production witness explicitly pins the missing IPC execution binding. The
initial pipe handshake was red before exec and is superseded by this signal
exchange; that original log remains evidence, not exec proof.
A native x86 fixture sanity run checks the assembly; it is not the required
native-arm64 Docker semantic/timing oracle.

Every caller gets an explicit host filesystem backend so the temporary ELF
can actually resolve once exec transport is wired. The production CPL0 image
and scheduler pool remain the entry point; no test helper performs replacement.

These witnesses are deliberately red until the entire server is present.
The crossing allowlist must flip in a separately labelled commit with its
server and director review. No early errno-only flip is allowed.

## Stack adoption

The staged successor imports a PRIVATE|GROWSDOWN stack before admission,
where boot inserts it after admission. The neutral slot's `prepare_adoption`
(`crates/carrick-el1-linux/src/exec_successor.rs:92`) calls `finish_import`.
That seals admission and notification sources; it does not add ANONYMOUS to
imported rows (`crates/carrick-core/src/mm/reservation/root.rs`). Boot's
`insert_opaque` also strips ANONYMOUS. Thus both describe a carrier-built
opaque stack, not a demand-zero anonymous stack. The VM-free characterization
`exec_import_and_boot_insertion_preserve_the_same_opaque_stack` drives the
production slot admission and adopter in both orders, checks the entry stack
row remains opaque with identical range/protection/flags, then drops the
rollback token and checks the space was retired. A live successor stack
access witness still needs the completed physical transport.

## Overlap

#2084 owns native executable-link identity and changes shared exec services,
HAL backing custody and the runtime loader. Reuse its live executable object
and per-MM backing custody for #1903; do not create a path snapshot or another
identity registry. #2263 owns x86 fault contention and changes shared native
service continuations. #2266 owns prepared-page publication for fork faults.
No production function from those diffs is changed by the witness commit.

Signed ARM execution, native-arm64 Docker comparison, the x86 scoreboard A/B,
and the full final-head gates remain required before accepting the exec fix.

## Remaining build handoff design

The director confirmed that no existing transport is known and accepted a
neutral typed retained build descriptor tied to the exact preparation,
including a manifest extension if that is the cleanest handoff. This document
records a proposed integration, not implemented production behavior.

The descriptor must retain immutable image/string records, ordered table and
data grants, and publication storage under the same service identity, receipt,
successor MM and root generation as the sealed manifest. The first table is
the sealed root and the editor's final stack pointer must equal the sealed RSP.
The host stages bytes and custody; the guest runs the existing image editor.
No host descriptor or stack writes are allowed.

The existing exact-MM alias mechanism is
`carrick-mmu-core/src/x86/copy_window.rs::with_cow_copy_aliases`: it maps a
retained source/destination pair, invokes the copy, restores both leaves and
drains them. `initial_mm.rs::install_initial_image` already provisions a
private copy branch for each new root. These are the mechanisms to investigate
for the guest build's staged-byte reads and data writes, rather than inventing
a global physical-memory alias. Currently `InitialWords` authenticates table
access and the boot source's direct aliases cover only the initial extent;
`CarrierExecData` uses dynamic GPAs outside those aliases. The build transport
must close that gap with exact preparation custody and a guest-owned editor.

Any temporary closed-root load must preserve supervisor entry/stack mappings,
keep interrupts and live-context authentication coherent, restore the caller
before a physical crossing, and drain on cleanup. Indeterminate descriptor
cleanup quarantines the preparation. Adoption transfers tables, inventory and
executable backing once; cancellation releases only never-published resources;
settlement retires the predecessor after translation switch. A stock refusal
retains its per-ticket operation and enrolled release revision, then probes
once after the holder's settlement. No polling or errno conversion is allowed.
