# Syscall refusal evidence (#1394)

The acceptance question is whether Carrick served the guest operation, not
whether the workload found a fallback and exited zero. The census is enabled
unless `CARRICK_EL1_CENSUS=0`; an optional directory value also retains the
full JSON sidecar and enables the existing CPU timing diagnostics. Default
counting adds no thread-clock reads.

`CARRICK_SYSCALL_CENSUS` on carrier stderr contains the full census. Its
`refusal_evidence` uses native ordinals, an explicit ISA, and root/native-child
populations. Root identity comes from the admitted process graph, rather
than assuming its visible PID is 1. Caller classification runs only when a
refusal occurs. Ring refusals and carrier venue refusals remain separate. Bucket
512 means unknown/out of range and cannot qualify. Carrier service payloads
retain the requesting ordinal, including write/writev and execve/execveat;
length and ordinal share the existing bounded service-cell word, preserving
its size. The image layout fingerprint changes with the counter geometry.

Both smoke and conformance consume this evidence. Permanent/Temporary
allowlisted refusals fail independently of the oracle. Other refusals require
a source-qualified syscall shape and fail if Docker served that ordinal.
Missing shapes require `--refresh-oracle`; old semantic oracle cache entries
cannot manufacture syscall evidence. Native-oracle runs currently provide no
bpftrace shape and therefore cannot qualify a nonallowlisted refusal.

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
