# x86 exec family (#2235, #2142)

Contract: `process.exec.custody`. Linux authority: execve(2) and execveat(2).
Successful replacement must enter the new image without returning; a pre-arm
failure preserves the old image and returns the specific errno. The successor
and its still-live parent must keep independent MMs and inherited descriptors.
No retries, widened budgets or host-side descriptor/stack editor are permitted.

## Existing mechanisms

ARM's exec owners come first. The run root execs through the host:
`HvpatchExecVenue` implements the shared `RootExecVenue`
(`crates/carrick-runtime/src/vcpu_loop/exec.rs:1800`), driven by
`drive_root_exec` (`crates/carrick-kernel/src/kernel/exec_transaction.rs:244`).
A native fork child execs through the neutral ring owner:
`begin_exec_service` (`crates/carrick-el1-linux/src/native_process_runtime/service.rs:1188`)
proposes the successor, `complete_exec_prepared` (`:2872`) adopts it and
`commit_exec_successor` (`:2503`) rebinds the record. The closed successor
slot, adoption and cancellation are `crates/carrick-el1-linux/src/exec_successor.rs:152,241,287`.
ARM's carrier answers the request in `NativeService::prepare_exec`
(`crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:334`) and the
crossings in `service_native_exec_{adopt,cancel,settle}`
(`crates/carrick-vmm-hvf/src/metadata_grant.rs:2064,2194,2235`). The shared
fork stock moves a child to its successor and settles the predecessor
(`crates/carrick-hal/src/fork_stock.rs` `replace_child_for_exec`,
`settle_exec_predecessor`).

x86 reuses all of these. Before this change it had the loader
(`prepare_native_x86_exec_image`, `crates/carrick-runtime/src/runtime/exec.rs:146`),
the stager (`stage_x86_exec`, `crates/carrick-x86-cpl0-host/src/cpl0_exec.rs`),
the adopter (`X86ExecSuccessor`, `crates/carrick-x86-cpl0/src/exec_successor.rs`)
and boot's editor as a successor build (`build_x86_successor`,
`crates/carrick-x86-carrier/src/initial_boot.rs:391`). The exact-MM alias it
now reads and writes through is the COW copy window
(`crates/carrick-mmu-core/src/x86/copy_window.rs`), which boot already
provisions in every root.

Root rebinding for the KVM executor is on main: `Cpl0RootBinding::replace_exec`
and `retarget_loaded_task` (`crates/carrick-runtime/src/vcpu_loop/executor/cpl0.rs:120,1465`),
`ProductionCpuLease::retarget_root_exec`
(`crates/carrick-x86-cpl0-host/src/cpl0_boot.rs:1451`), the venue-typed
`PendingExecReplacement::cpl0` (`crates/carrick-runtime/src/vcpu_loop/executor/binding.rs:400`)
and `Cpl0TaskBindingDirectory::replace_exec` (`cpl0.rs:1901`). No x86
`RootExecVenue` publishes it yet.

## The fork-child path (#2235, implemented)

1. Ring entry: a claimed fork child's execve/execveat stages its payload
   (`native_exec_stage_request`) and begins the shared service through
   `begin_exec_call` (`service.rs:1245`), the inline-settling twin of the
   host-file call (`native_exec_call`,
   `crates/carrick-x86-cpl0/src/linux_personality.rs:745`). A staging fault
   is supplied through the owner fault path and the syscall re-entered; a
   refused supply is EFAULT. The ring census records the call as served once
   the owner takes it. A root's exec keeps the counted ENOSYS
   (`settle_unwired_native_service`, which no longer stages anything).
2. Host Exec arm: `service_native_notice` authenticates the payload and the
   ring's proposed manifest and hands them, with custody released, to the
   runtime's loader (`load_native_x86_exec`). `finish_native_exec`
   (`cpl0_exec.rs:1038`) returns a loader errno as the exec's errno, or
   stages the successor and one build extent, seals the manifest with a
   fresh receipt and the extent (`ExecSuccessorManifest::seal_with_build`)
   and publishes it on the exact ticket. A ring that cancelled meanwhile gets
   no manifest and the preparation is released. A stock refusal parks the
   request with its ticket outstanding; every crossing that can return
   tables probes woken parked requests once (`probe_parked_execs`).
3. Build extent: one wire layout, `crates/carrick-el1/src/isa/x86/exec_build.rs`,
   owned by neither side. The host encodes a header (boot's request record
   with its own magic), the rows, strings, grants (tables first, the first
   being the sealed root), a publication area and the initialized file
   bytes, each region's on its own pages at its user page offset.
4. Guest build: before the consuming crossing, `X86PrepareCross` runs
   `ServiceExecBuild` (`crates/carrick-x86-cpl0/src/native_process.rs:272`):
   `build_exec_successor` (`crates/carrick-x86-carrier/src/exec_build.rs:119`)
   reads the extent and writes the unpublished frames one page at a time
   through the predecessor's copy window (`with_copy_window_frames`), runs
   boot's editor, checks the sealed root and stack pointer, and writes its
   publications and results back. The host never writes a descriptor or the
   stack.
5. Crossings on `NATIVE_EXEC_PORT` (RDI names the operation, RAX the stack
   record). Adopt (`adopt_prepared`, `cpl0_exec.rs:1301`) authenticates the
   receipt, its sealed identity against the stopped predecessor, the
   manifest and the build's results (`read_exec_build_results`: every byte
   the host wrote unchanged), binds the closed space's root, replays every
   publication into the carrier's descriptor model and commits the data
   frames as boot does, releases the extent, and moves fork-stock custody
   keeping the linked tables as the successor's
   (`replace_child_for_exec_with_tables`). Cancel zeroes and returns the
   reservation; the ring's slot retires the root. Settle runs from the
   maintenance root (the carrier admits only this port and the work port
   there): it moves the task's registered CR3 to the successor and releases
   the predecessor like a reclaimed child, or defers that release to the
   next quarantine drain.
6. Resume: after the owner commits, the scheduler enters the record's new
   context on the successor's root (`native_execution.rs`).

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
then writes and reads its stack before announcing replacement. The parent
checks that its own stack canary survived before sending the acknowledgement.

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

The two child witnesses and
`native_fork_child_exec_refusals_return_their_errno_to_the_old_image`
(ENOENT and ENOEXEC from the child's old image) are green with the child
server. The three root witnesses stay red until root exec lands. The crossing
allowlist must flip in a separately labelled commit with its server and
director review. No early errno-only flip is allowed.

## Parked exec and signals (#2273)

Linux `execve(2)` and `signal(7)` govern the signal boundary: a pending caught
SIGUSR1 outlives the parked service, then the successor's reset-to-default
disposition terminates it; SIG_IGN persists through exec and the successor
exits normally. A default-terminate SIGTERM ends the child and reaps the
outstanding ticket without waiting for its fork-stock holder. The native Linux
oracle recorded SIGUSR1, normal exit 7, and SIGTERM respectively with a
pending signal across exec. The x86 KVM production witness keeps a second live
child holding stock and observes an actual successor-table refusal in every
case. It also retains the SIGKILL control.

The red KVM witness (`2273-round4-red4`) showed caught SIGUSR1 returning the
saved syscall number RAX=59 to the old image (its negated exit was 197);
SIGTERM waited until the holder's five-second bound ended. The fixed KVM
witness (`2273-round4-fix2`) passed all six focused child-exec cases. The
shared service excludes exec from ordinary signal interruption
and lets only a deliverable default-terminate signal cancel it. Fatal signal
work drives a host probe of the parked ticket. An error while probing preserves
all unprocessed parked execs.

The final cancellation boundary adds two production KVM witnesses under the
same stock pressure. `native_fork_child_exec_fatal_signal_beats_caught_signal_while_parked`
queues caught SIGUSR1 before default-fatal SIGTERM and records any old-image
handler write. On `c61e80c77`, the handler wrote `H\n` before the child died:
`2273-red-a` failed with stdout `[72, 10]`. The real two-thread fork child in
`native_fork_child_exec_sibling_fatal_signal_retires_parked_caller` has a
sibling consume SIGTERM while the exec service is cancelled; it records `R\n`
if the old image resumes. On the same head, `2273-red-b8` exited 197, the
negation of saved syscall number 59, rather than being reaped as signaled.

The native Linux oracle (`native_exec_signal_oracle.c`) installs a seccomp
user-notification listener that holds the real `execve` syscall in the kernel.
With caught SIGUSR1 then default-fatal SIGTERM, Linux reports a SIGTERM wait
status and zero old-image bytes. With a real sibling receiving SIGTERM while
the caller's `execve` is held, Linux again reports SIGTERM and zero old-image
bytes. The KVM sibling reduction uses `rt_sigtimedwait` to consume the first
SIGTERM after cancellation was selected, exposing the otherwise unreachable
`NoPending` handback. Its pre-fix exit 197 proves the signal had been removed
before the old image resumed. The green check requires no old-image marker and
the Linux SIGTERM wait status; the sibling's `S\n` marker proves it ran before
the parked exec. One fatal-signal choice is retained through the service ACK;
completion uses the existing group-exit path, with no extra wait or poll.
The focused KVM run `2273-green-final` passed all eight child-exec rows with
the native oracle enabled. The Linux oracle reported
`signaled=1 signal=15 old_image_bytes=0` for both the one-thread and two-thread
seccomp-held `execve` cases. The sender and target were pinned to one allowed
CPU so the two signal publications occurred before the target ran.

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
rollback token and checks the space was retired. The live-parent witness's
successor now writes and reads its initial stack on the production carrier.

## Overlap

#2084 owns native executable-link identity and changes shared exec services,
HAL backing custody and the runtime loader. Reuse its live executable object
and per-MM backing custody for #1903; do not create a path snapshot or another
identity registry. #2263 owns x86 fault contention and changes shared native
service continuations. #2266 owns prepared-page publication for fork faults.
No production function from those diffs is changed by the witness commit.

Signed ARM execution, native-arm64 Docker comparison, the x86 scoreboard A/B,
and the full final-head gates remain required before accepting the exec fix.

## Root exec (#2142): what remains

The root's exec is not the child's. The x86 run root is a ring-native
process whose filesystem authority, descriptor table, credentials and
`/proc/self/exe` identity the host Kernel retains (`host_root_retains_filesystem`,
`encode_caller_access` refuses it ENOSYS). Its exec must therefore commit
the host Kernel's exec transition (close-on-exec on the host table, the exe
identity and binfmt argv, the `/proc` generation, the signal reset, the
ptrace stop) and publish `PendingExecReplacement::cpl0` so the executor
retargets its loaded root. That is `drive_root_exec`, whose typestate runs
synchronously in one host call, while the x86 successor is built by the
ring adopter between the arm and the consuming crossing. Two designs need a
director ruling before code: an x86 `RootExecVenue` whose `install_image`
drives a host-entered CPL0 build (boot's pattern, mid-forward), or the
child's ring path for the root with the driver's neutral steps split across
the Exec arm, adopt and settle crossings. Until then the root keeps its
counted ENOSYS and `Execve`/`Execveat` stay `x86 = false` (no early flip).

#1903: a native child's `/proc/self/exe` is not served on x86 at all today;
#2084 owns that readlink. The successor's image is loaded by the shared
resolver, so #2084's executable object is where the identity belongs; this
change adds no path snapshot.
