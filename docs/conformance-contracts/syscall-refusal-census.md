# Syscall refusal evidence (#1394)

The acceptance question is whether Carrick served the guest operation, not
whether the workload found a fallback and exited zero. The census is enabled
unless `CARRICK_EL1_CENSUS=0`; an optional directory value also retains the
full JSON sidecar and enables the existing CPU timing diagnostics. Default
counting adds no thread-clock reads.

`CARRICK_SYSCALL_CENSUS` on carrier stderr contains the full census. Its
`refusal_evidence` uses native ordinals, an explicit ISA, and root/native-child
populations. Ring refusals and carrier venue refusals remain separate. Bucket
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
shell that performs `cd /` before fork/exec. Each run retains its own existing
carrier deadline. Compare termination and every output line. Three deliberate
Linux topology observations have exact expectations rather than equality:
PID1's absent namespace parent (`pidnsroot`), orphan adoption by namespace
init (`pidnsorphanreap`), and session-leader setpgid EPERM (`proclife`). No
other output difference is normalized or admitted.

The VM-free bindings prove counter preservation, caller splitting, overflow,
wire transport and the gate's refusal override of otherwise passing output.
They do not prove the live child mkdirat or cd/exec witness. Signed execution,
Docker refresh and exact-artifact smoke remain required acceptance evidence.
