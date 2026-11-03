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
All seven inherited commits were retained when rebasing onto admitted main.
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
5. **Emission: implemented under the latest owner ruling.** No default output
   or sidecar; `CARRICK_EL1_CENSUS=<directory>` opts in. The unset/empty/exact-0
   policy test fails against the previous default-on implementation and passes
   after the fix. Both CI workflows and the signed runner explicitly enable
   evidence. Conformance and smoke request private destinations themselves.
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

The separate gate worker must run the requested lint-domains, both native test
partitions, clippy, check-linux and cross-check-macos. Signed smoke, generic
probe shards, `task_cwd::sibling_processes_own_their_cwd_and_umask`, and the
live AArch64 child mkdirat census/gate witness remain director work. The
reviewer's signed mkdirat observation is historical evidence, not a receipt
for this rebased artifact. Keep the PR draft.
