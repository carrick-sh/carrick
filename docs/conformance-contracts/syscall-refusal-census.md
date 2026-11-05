# Syscall refusal evidence (#1394)

The acceptance question is whether Carrick served the guest operation, not
whether the workload found a fallback and exited zero. Under the owner's
2026-11-03 ruling on #231, census emission is opt-in: set
`CARRICK_EL1_CENSUS=<directory>`. Unset, empty, and exact `0` disable emission
and host timing hooks. Ring counters still exist independently. No census JSON
is printed to user stderr. CI and signed test runners explicitly enable a
census destination; conformance and smoke override it with private directories.

The gates request a private directory, read its files and retain
`CARRICK_SYSCALL_CENSUS` records in their evidence logs. The CLI does not
write JSON to the user's stderr. The
`refusal_evidence` uses native ordinals, an explicit ISA, and root/native-child
populations. Root identity comes from the admitted process graph, rather
than assuming its visible PID is 1. The ring owner seals caller lineage into the retained service birth;
exec preserves it and invalid lineage fails closed. Ring refusals and carrier venue refusals remain separate. Bucket
512 means unknown/out of range and cannot qualify. Carrier service payloads
retain the requesting ordinal, including write/writev and execve/execveat;
length and ordinal share the existing bounded service-cell word, preserving
its size. The image layout fingerprint changes with the counter geometry.

Both smoke and conformance consume this evidence. Permanent/Temporary
allowlisted refusals fail independently of the oracle. Other refusals require
a source-qualified syscall shape and fail if Docker served that ordinal.
Missing shapes are reported as coverage debt and do not gate nonallowlisted
refusals until an observation exists. A VM-free test caps committed missing
shape rows at 11,484; lower that ceiling as shapes land. `--refresh-oracle`
captures shapes; old semantic cache entries cannot manufacture them.
Native-oracle runs currently provide no bpftrace shape. This temporary debt
does not excuse allowlisted refusals, overflow or missing census files.

Shape capture is a separate Docker-only pass; its duration is never a speed
oracle. The workload retains its ordinary PID namespace and security flags.
A dedicated privileged observer uses bpftrace inside Docker, follows native
TIDs, and releases the waiting PID1 workload only after attachment. Its image
defaults to the architecture-matched LTP image; `CARRICK_ORACLE_TRACER_IMAGE`
can select another bpftrace-equipped image. Natural completion, matched
entry/return populations, no tracked survivors and no reported drops are
required. Only ordinary workload execution supplies semantic/timing evidence.

Generic probe shards run each probe directly as PID1 and behind a waiting
shell that performs `cd /tmp` before fork/exec and stays there. Returning
to the startup directory would hide the stale-cwd refusal in #1392. Each run
retains its own existing carrier deadline. Compare termination and every output line. Three deliberate
Linux topology observations have exact expectations rather than equality:
PID1's absent namespace parent (`pidnsroot`), orphan adoption by namespace
init (`pidnsorphanreap`), and session-leader setpgid EPERM (`proclife`). No
other output difference is normalized or admitted.

The VM-free bindings prove counter preservation, caller splitting, overflow,
wire transport and the gate's refusal override of otherwise passing output.
They do not prove the live child mkdirat or cd/exec witness. Signed execution,
Docker refresh and exact-artifact smoke remain required acceptance evidence.

The KVM `production_cpl0_refuses_non_allowlisted_forwards_with_enosys`
binding also checks mapped census counts for the initial process with a
non-1 visible PID. Both refused ordinals belong to the root population.

The per-process access-context integration preserves both authorities: host-file
service intake carries the `chdir` completion flag alongside its native census
ordinal, and exec seals the caller's current cwd and credentials before service
publication. Changing uid is served under the changed identity; the previous
expectation that every such exec must be refused is superseded. The capability
refusal check remains intact. The portable process-owner bindings include
`native_child_exec_after_ring_setuid_carries_the_new_credentials` and
`arm_root_fork_seeds_each_childs_row_with_the_roots_live_cwd`.

Live AArch64 follow-through requires the signed `task_cwd` test
`sibling_processes_own_their_cwd_and_umask`, the generic probe shards with the
changed-cwd child differential, and the exact-artifact `smoke-signed` gate.
The x86 KVM root-refusal binding does not replace a live child `mkdirat`
(ordinal 34) census and refusal-gate witness on AArch64.

Access admission is counted before a service ticket is published. A typed
`NativeServiceCall` binds the native ordinal to its census; `caller_access`
returns an opaque failure only after recording ENOSYS in the ring population.
Both exec and path admission consume that failure directly. Carrier venue
counts remain zero because no carrier request exists yet. Ordinary access
errors (such as ESRCH) preserve their errno and do not become refusals.

The native-child production service binding drops CAP_DAC_OVERRIDE and checks
one refusal each for openat and execve. The root exec binding removes the
known cwd, checks execve/execveat and the unknown-ordinal bucket, and proves
that a non-1 root does not enter the child population. These are VM-free
production service entries, not live guest instruction execution. The signed
child mkdirat and changed-cwd differential witnesses remain required.

Refusal bookkeeping uses one typed `Counters::record_refusal` operation for
ring/carrier venue and initial/descendant lineage. Native tickets retain their
own mapped counters, resolved from carrier stage-2 custody. A later process-global
counter pointer cannot redirect a ticket's refusal into another carrier.
Exec failure 38 and publication-race refusal follow this same path. Missing
cwd at chdir completion and structural IPC leaves count before returning 38.
Docker shape capture admits every naturally completed workload exit status,
including the nonzero statuses deliberately exercised by conformance suites.

Each publication retains a uniquely created JSON file, including sequential
embedded carriers sharing a host PID and grouping ID. The Lima lane forwards
the destination into its VM and retrieves those files with bounded collection
commands before checking the same evidence as local lanes.

## Six-item review audit for the continuation worker

This audits the independent review on PR #1403, not acceptance of the branch.
All nine inherited commits were retained when rebasing onto admitted main.
The #1444 carrier census ownership and #1409 per-process access semantics are
retained. No syscall routing allowance, errno policy or work budget changed.

1. **Authority catalogue: implemented.** The catalogue names
   `carrick_runtime::el1_census::publish` for its existing filesystem APIs.
   The continuation gate worker must quote source-debt and lint-domains results
   on the final head; an older worker's receipt does not qualify this head.
2. **Refusal holes: implemented; carrier-path proof remains.** Exec failure 38
   and publication-race refusal count in the retained carrier ticket before
   acknowledgement. Ring overflow, missing-fs chdir completion and structural
   IPC leaves use `Counters::record_refusal`. The remaining policy and mmap
   sites now also use that method, and the separate child-only updater is
   removed. Counter tests cover both venues, both caller classes and overflow;
   `unconfigured_host_aperture_refuses_unported_calls_and_counts` drives dispatch
   overflow; `native_structural_refusals_retire_without_host_handback` drives
   IPC. The access-refusal production witnesses remain bound above. **Remaining:**
   red-first witnesses through carrier `prepare_exec`, its publication race,
   and missing-fs chdir completion have not been supplied by earlier workers.
   Counter-only tests do not substitute for those production paths.
3. **Ticket-scoped bookkeeping: implemented.** Intake obtains the census from
   retained carrier custody; `NativeService` retains that pointer until ACK.
   Recording does not look up a process-global pointer and cannot add a fatal
   error. The two-carrier counter test proves inventory isolation; a retiring
   sibling-carrier production witness remains unrun.
4. **Caller identity: implemented.** Venue accounting uses the ticket's sealed
   `ServiceOrigin`. `ProcessNative::is_root_process` has no default; production
   implements it using the admitted graph and test doubles state their identity.
   `service_lineage_survives_ticket_intake_and_exec_rebind` and the non-1-root
   access witness cover lineage transport and graph identity respectively.
   The root access witness also substitutes an unadmitted generation for both
   the caller and stored root key and requires `is_root_process` to return false;
   key equality alone cannot establish root authority. A negative control replacing
   `is_ok_and` with a fail-open `map_or(true, ...)` fails this assertion
   (exit 101); restoring the production lookup preserves fail-closed behavior.
5. **Emission: implemented under the latest owner ruling.** No default output
   or sidecar; `CARRICK_EL1_CENSUS=<directory>` opts in. The unset/empty/exact-0
   policy test fails against the previous default-on implementation and passes
   after the fix. The signed runner explicitly enables evidence; conformance
   and smoke request private destinations themselves. Both CI workflow `env`
   blocks (`ci.yml`, `kernel-runtime.yml`) set
   `CARRICK_EL1_CENSUS: ${{ github.workspace }}/target/carrick-census`; the
   director published them, since dispatch credentials cannot update workflow
   files.
6. **Landing behavior: implemented; live oracle gate remains.** Missing shapes
   remain counted debt under the existing 11,484-row ceiling, and shape capture
   accepts natural nonzero workload exits. A killed row without teardown keeps
   its ordinary verdict; a completed HVF/KVM row still requires a census.
   BSD lanes lacking transport retain their ordinary verdict in its absence.
   Evidence that is present is always checked, including on killed/BSD rows.
   The report-builder witness fails before this correction and covers missing
   evidence, unsupported transport, and allowlisted child refusal after it.
   **Remaining:** Docker is absent here, so committed-cache
   `conformance-quick` and live nonzero-exit shape capture are unrun.

The separate Linux x86_64 gate turn returned these results:

- `just lint-domains`: exit 1, blocked at `scripts/lint-domains.sh` because
  Semgrep is not installed. The full typed-domain/compiler gate is unqualified.
- `just test-el1-native`: exit 0; both partitions ran in the one-process-per-test
  runner: 633 regular tests passed, one ignored, and 29 `serial_host` tests passed.
- `just clippy`: exit 0.
- `just check-linux`: exit 0, including the no-HVF closure assertion.
- `just cross-check-macos`: exit 0 (cross-compilation and clippy, not HVF execution).
- `just xtask authority-debt --source-only`: exit 0; source ceilings pass.
  Repeating with `--base` admitted main also exits 0 and passes the PR-base ratchet.
- `just check-contract-change` against admitted main: exit 0.
- `cargo check -p carrick-vmm-kvm`: exit 0; no live KVM test is claimed.

Signed smoke, generic probe shards, `task_cwd::sibling_processes_own_their_cwd_and_umask`, and the
live AArch64 child mkdirat census/gate witness remain director work. The
reviewer's signed mkdirat observation is historical evidence, not a receipt
for this rebased artifact. Keep the PR draft.

### Terminal publication custody

The run terminal owner publishes the census before delivering the result to
CLI or embed callers. HVF does this in the existing run finalization callback,
while the explicit carrier and persistent pool remain alive. KVM publishes
from its terminal completion path before shutting down the pool. Shutdown no
longer publishes a second census. Publication writes a private `.pending`
file, syncs its contents, renames it to `.json`, and syncs the directory.
Readers ignore pending files; an I/O failure fails terminal delivery.

`smoke_terminal_census_precedes_pool_shutdown_for_two_carriers` reads each
census immediately after a real guest terminal result, before shutdown, then
runs a second explicit carrier in the same process. This witness is expected
to fail against the old shutdown-only writer. It requires signed HVF execution;
compilation and the VM-free atomic writer test do not qualify the live ordering.

### Host-file staging refusal audit (carrick-87)

`native_host_file_staging_refusal_is_counted_once` drives the production
`native_host_file_stage` entry with a relative `openat` through a host-backed
dirfd, then its production return settlement. It requires one ring refusal,
one served answer, the exact root/child subset, and no carrier refusal.
An ordinary EBADF settlement must leave refusal counts unchanged.
Both `Returned(ENOSYS)` and `InRing` settle through `native_host_file_return`;
there is no carrier ticket to count these answers later.

The native-path ENOSYS audit found these other sites:

- `native_host_file::Staging::path_base` and `Faccessat` with an empty path
  and `AT_EMPTY_PATH` produce `Returned(ENOSYS)`. Both now reach this settlement.
- `dispatch`'s delegated private mmap refusal already records through
  `PendingFamilies::record_refusal`, then counts its served answer.
- `ipc`'s structural refusal already records in its completion path.
- `native_process_runtime::service::encode_caller_access` propagates ENOSYS
  to `caller_access`, which records it; missing-fs `complete_chdir` records
  before returning ENOSYS.
- `service`'s Crossing, HostFile and Exec `ServiceResult::Refused` arms consume
  carrier refusals. `NativeService::refuse` and `refuse_host_file` record the
  venue refusal before acknowledgement; recording again in ring would count
  the same refusal twice.
- The `GuestDispatchFrame` signal-frame default methods return unsupported
  capability errors, rather than native host-file dispatch answers. Native
  ARM signal restoration overrides the default, and signal setup uses the
  process backend. Exec staging itself emits only E2BIG, EFAULT,
  ENAMETOOLONG and ENOMEM, not ENOSYS.

No additional uncounted native dispatch ENOSYS return was found in this audit.
This VM-free witness does not qualify signed guest execution or oracle shapes.

With the shared return settlement's accounting removed, the witness failed
with `refused[56] == 0` instead of `1` (exit 101). Restoring accounting is
required for the green witness; staging still returns errno 38 unchanged.

### Combined ABI after object-wait protocol 13

The census layout must be fingerprinted together with main's object-wait
protocol 13, rather than pinning the pre-rebase census hash. The combined
`EL1_ABI_LAYOUT_HASH` is `0xe329ce06dd84c0a6`. The compile-time assertion was
red with `0x486abff97ce01d37` (E0080, exit 101).

Relative to admitted main, `Counters` appends `refused_child`,
`venue_refused` and `venue_refused_child`, each 513 atomic u64 entries.
`ServiceCell` retains its byte layout but encodes `ServiceBirth` lineage
in the high half of the process-ID word and Exec/HostFile diagnostic
ordinals in the high half of the payload-length word. The corresponding
Rust `ServiceBirth`, `ExecPayloadDescriptor` and `HostFilePayloadDescriptor`
values gain those fields. `NATIVE_SERVICE_PROTOCOL` advances once from
main's 6 to 7; `OBJECT_WAIT_PROTOCOL` stays at main's 13. This fix round
only refreshes the layout pin; it changes no protocol or record again.

### Artifact authority and isolated policy tests

Census publication uses the existing observability artifact publisher, which
owns the host directory open, durable temporary write, no-clobber publication,
inode verification and directory sync. The census keeps its unique name
reservation until that publication completes. The existing terminal-publication
and successive-carrier bindings still prove complete-file transport, distinct
publications and propagation of I/O failures. The shared publisher's
`artifact_publication_is_private_durable_and_no_clobber` binding additionally
checks that writable artifact directories are refused. No authority ceiling
increases are needed.

The emission-policy test self-spawns only its exact test function to get a
fresh environment and `OnceLock`; it bounds and reaps each child. The runtime
process-creation inventory now lives in the portable `host_process` test module
so every host runs the same check. It classifies this test-only call explicitly, keeping
production host-process creation forbidden. After rebasing onto the admitted
main, exec test calls retain the new caller-table argument alongside the
`NativeServiceCall` census context; neither authority is dropped.

New census directories request mode `0700` at creation. An existing directory
keeps its permissions and remains subject to the shared publisher's admission
check. The real KVM CLI binding
`mounted_static_x86_elf_writes_hello_and_exits_seven_through_shared_kernel`
exposed a group-writable destination under host umask `0007`: the guest wrote
`hello`, but terminal publication returned status 125. With private directory
creation, that same binding returns the guest's status 7 and reads one complete
x86_64 census file. Its failure assertion retains stdout and stderr so future
publication errors identify their cause.

Collectors that pre-create a census destination also request private
permissions explicitly: `tempfile` directories otherwise inherit the host's
creation mask. The conformance runner requests `0700` on its census temporary
directory, and the signed smoke fixture uses private directory creation. The
successive-carrier unit binding lets the production publisher create its census
subdirectory and then reuses that same directory for both publications.

## Final unclaimed-child capture (#1335, slice 1)

The real-fork namespace baseline exposed a later gap in final capture:
`refused[34]` was 2 but `refused_child[34]` was 0. The same production
boundary now uses the existing typed recorder with descendant/ring identity.
Two live children and a successful exec successor require all six namespace
refusals in the descendant population, zero carrier refusals and no carrier
notices. The unclaimed-ordinal negative control retains one errno-38 result
and one total refusal. No syscall routing or namespace service was added.
Signed image/CLI and Docker evidence remain open.
