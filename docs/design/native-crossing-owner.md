# Native crossing ownership (design for #1335)

Status: proposed, docs-only, keep draft. This round does not repair or close
#1335. Implementation needs independent review of the shared interface and
its lock ordering before the slices below start.

A forked guest has no host task to receive a raw Linux syscall. The ring must
own its Linux operation and ask the carrier for a typed host service only
when that operation actually crosses the guest boundary. Being present in the
forward allowlist is not proof that a native child has such a service.

## Evidence and limits

Source observations below refer to admitted main
`04deeb00729d48ec881eec6ecac8716d64161492`. Anchors are review navigation,
not a new line-pinned inventory or acceptance receipt. Delete obsolete
observations as their implementation slices land.

The issue reports `mkdir`, path stat and output failures with errno 38 on
`09d43ed824`, plus 21 failing smoke suites out of 23. Those are director
observations, not measurements repeated by this worker. The June binary
comparison does not establish the first bad commit or prove the ARM flip
caused the defect. Missing dispatcher logs alone do not distinguish a ring
refusal from a carrier refusal before host dispatch.

The durable trace header in
`scripts/dtrace/hvpatch-native-crossing-refused.d:1` records a live qualification
on that same old main: native children produced carrier refusals for mkdirat
(34), statfs (43), socket (198), mmap (222), getrandom (278), ioctl (29),
lgetxattr (9), llistxattr (11), and pipe2 (59) in a separate pipeline.
Its old ordinal 0 observation is explicitly ambiguous: older host-file venue
refusals also used 0. Do not classify that observation as an io_setup call.
The header also records that admitted root credentials did not cause the
observed refusals. These historical observations must not be presented as a
current-main census.

The present source has changed materially: statx, newfstatat and writev now
have typed host-file staging, while #1530 refuses an unclaimed fork-child
syscall in ring before a carrier crossing. A design that simply forwards the
old four names would bypass current ownership and revive a carrier failure.
No current ENOSYS frequency or runtime ratio was measured here. This Linux
x86_64 runner cannot execute the reported signed ARM/HVF workload; GitHub CLI
also has no authentication, so the supplied brief and inbox are the available
owner instructions. The original 01:39 comment is not independently recovered.

## Current route and refusal sites

| Source anchor | Existing decision and consequence |
|---|---|
| `crates/carrick-personality-linux/src/crossing.rs:205`, `:229`, `:240`, `:259` | mkdirat, writev, newfstatat and statx are Permanent crossings. This classifies a boundary; it does not implement native service or authenticate a caller. |
| `crates/carrick-el1-linux/src/dispatch.rs:721` / `unclaimed_native_syscall` | ForkChild selects CountedEnosys; Root and Unowned retain HostRoute. |
| `crates/carrick-el1-linux/src/dispatch.rs:771` / `native_unstaged_exit` | A remaining Forward SVC from a child becomes one in-ring refusal, not a raw host syscall. |
| `crates/carrick-el1-linux/src/dispatch.rs:735` / `refuse_unclaimed_native_syscall` | Writes -38 and increments refusal/served accounting once. Preserve the negative control for truly unrouted calls. |
| `crates/carrick-personality-linux/src/native_host_file.rs:221`, `:248`, `:254`, `:646` | Decodes writev, newfstatat and statx and stages writev as host Write. There is no Mkdir host-file wire operation in the current enum. |
| `crates/carrick-el1-linux/src/native_process_runtime/service.rs:886` / `caller_access` | Counts an ENOSYS access-context failure in ring; absent task fs at `:916` leaves paths unrouted rather than guessing carrier cwd. |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:390` / `refuse` | Unsupported Crossing/Exec/HostFile tickets are refused; there is no dispatcher fallback. |
| `crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs:439`, `:523` | HostFile resolves retained capability, serves staged bytes, or records a carrier venue refusal. Wire-op refusal ordinals use 65536 + op; census retains the Linux ordinal. |

Root success is insufficient. The shell can execute a builtin redirection
without exercising the child path used by external mkdir or ls. Nor does
successful openat prove namespace mutations, output vector staging or child
fs inheritance. Distinguish missing routing, missing fs seed, unsupported
venue, stale authority and ordinary Linux errors in evidence.

## One operation owner

Extend the existing native-process continuation and host-file record. Do not
introduce a generic host syscall trampoline or a carrier task impersonating
a child. The Linux personality decodes Linux arguments and selects ring or
host-backed resources; neutral core authenticates lifetime and service
identity; a backend performs only the real host crossing.

The operation owns the exact caller TaskKey generation, calling thread,
file-table generation, execution/MM incarnation and service sequence. Path
operations retain the caller's fs context and effective credentials, root,
cwd and umask; fd-relative operations retain the selected directory
capability. An absolute path cannot silently inherit the carrier root.
CLONE_FILES and fork's copied descriptor table preserve their existing
semantics; dup shares the open description, not a second namespace.

Use existing `ServiceOperation::HostFile` and `HostFilePayloadDescriptor`,
`PendingHostFile`, access-context encoding and the file-table lease. The ring
copies user inputs and owns copyout/fault recovery. The carrier receives a
bounded staged record, never a guest pointer to dereference or an authority
inferred from its own pid/uid. A response belongs only to its authenticated
request and cannot be installed in a recycled table, record or exec successor.

Names for any new APIs remain proposals until implementation review. Prefer
an operation-specific admitted token to an `is_allowed` boolean followed by
an unrelated lookup. Decode and validate all sizes/flags before publication;
reserve reply capacity before a host mutation. A successful mutation must not
be replayed when copyout, cancellation or receipt delivery suspends.

### Does `HostFileOp::Crossing` stay?

There is no `HostFileOp::Crossing` on this main. `HostFileOp` is the typed
host-file wire enum in `crates/carrick-core-abi/src/host_file.rs:19`;
`ServiceOperation::Crossing` is the separate untyped boundary at
`crates/carrick-core-abi/src/service.rs:129`. Keep those concepts distinct.

Do not add Crossing to HostFileOp. Keep the existing service Crossing only
for its current root/unowned capture and diagnostic uses while those callers
remain. A native child must never rely on it for successful execution.
Adding mkdir support means an explicit typed operation, not teaching the
carrier to redispatch a numeric syscall with ambient host-task state.
Delete obsolete Crossing producers only after auditing all callers on both
ISAs; do not remove root routing as an incidental part of this fix.

### Completion, waits and ordering

Follow the existing sequence: authenticate the ring caller, retain its
operation and resources, publish the ticket, resolve/pin the exact carrier
capability, perform the host operation, publish reply, then complete the ticket
and resume/copy out through the ring owner. No graph, file-table or fs lock
may remain held across carrier execution or a guest park. Implementation must
write down the actual cross-crate acquisition order before changing it; this
design does not license an invented global lock or a new lock inversion.

Busy retains the owned operation, enrolls on the existing holder release,
probes once and releases execution capacity. It is neither ENOSYS nor fatal.
A closing table joins existing terminal custody; do not reacquire a draining
generation using the numeric fd. Cancellation owns cleanup of staged records,
leases, payloads and prepared outputs. After a committed host mutation it
settles that mutation exactly once; it cannot restart at admission.

In-zone pipes, sockets and ptys remain ring services even when the same Linux
ordinal also supports a host file. A stdout fd may name either kind. Partial
writev completion retains byte/iovec progress and endpoint lifetime; no
restart at zero, fake short write or host readiness pipe for an in-zone fd.

## Baseline measurement before implementation

On the director's admitted signed artifact, run the original shell workload
with default fs and `--fs host`, then a controlled fixture with root, two live
fork children, and a child after exec. Record stdout, stderr, exit status,
image digest, argv, HEAD, binary SHA-256/CDHash/UUID, entitlements and DOF.
Use a unique CARRICK_RUN_ID and prove scoped cleanup after each bounded run.

Use `carrick trace` with the durable native-crossing-refused script to name
carrier refusals. Its 45-second bound and top-level exit closure are already
provided. Also collect the existing ring refusal census, partitioned by initial
versus descendant origin and ring versus carrier venue, including started and
completed population. Zero trace events cannot prove zero refusals now that
#1530 answers children in ring. If the available census cannot attribute an
ordinal to the required population, extend the existing Rust diagnostic first;
do not use a one-off D script or debug logging as measurement authority.

Report attempted/completed/refused calls and errno numbers per ordinal and
venue, and compare those counts between base and candidate. Explicitly mark
missing or dropped observations unknown. The historical list above is a
starting hypothesis, not an expected-output allowlist. Separate uninstrumented
paired/interleaved runtime measurements from trace runs. Serialize Docker and
Carrick; use native ARM Docker with the same image and credentials. No fresh
baseline is claimed by this document.

## Slices and red-first witnesses

Each slice stays under the PR cap, has an issue and contract binding, and
preserves earlier worker fixes. Use native GitHub stacks if interfaces depend
on unmerged work. The director owns routing-policy edits and signed acceptance.

1. **Baseline and contract binding.** Extend the production-entry native
   process harness in `carrick-el1-linux/src/aarch64_process_tests.rs`, using
   real fork admission, child publication and dispatch, rather than fabricated
   task keys or an inner staging helper. Reuse its `TestStockCrossing` only
   behind test configuration. Require two live children with distinct cwd,
   umask and descriptor tables. Preserve the existing unclaimed-child refusal
   witness (`dispatch.rs:4727`) as a negative control. Add the missing contract
   for native host namespace mutation before changing behavior; link existing
   directory-copyout and fork-child-admission contracts for shared boundaries.
   This slice produces measured baseline evidence; no semantic fix claim.
2. **Smallest missing typed mutation.** Add mkdirat through the shared Linux
   decoder, bounded host-file ABI record, retained native service and actual
   host venue. Review wire encoding/alignment before code. Reuse VFS mutation
   authority, permission and cache/event publication; do not duplicate path
   resolution in HVF. The red witness calls production dispatch in an admitted
   child and initially observes -38; after correction it asserts directory
   identity, caller umask, dirfd and parent visibility. Cover EEXIST, EFAULT,
   invalid flags as applicable, lower-layer/default fs and host fs. Carrier
   adapters consume the shared operation on x86 and ARM; an unavailable backend
   binding is explicit unfinished work, not a silent ISA gap.
3. **Existing typed calls and lifecycle.** Drive statx/newfstatat, write/writev
   and openat from children and exec successors through production entry. Fix
   only demonstrated failures: current code already stages several of these.
   Cover AT_EMPTY_PATH, relative dirfd, inherited stdout, ring pipe stdout,
   partial vector writes, close/dup races and two different process credentials.
   Force Busy once then success, cancellation during wait, table drain and
   reused generations. Mutating each changed admission predicate or suppressing
   its completion must make its own witness red. Keep lifecycle fatals in scope
   only when the same retained operation demonstrates causality; otherwise
   preserve them as separate defects with their own evidence.
4. **Production boundary and promotion.** Add the required single CLI
   process-boundary regression through the established audited topology runner,
   documenting why embed alone cannot prove `carrick run` integration. It runs
   the original image shell path, asserts MKDIR-OK and LS-OK, verifies actual
   contents and exit status, and fails on any child ENOSYS. Keep ordinary ABI
   probes in conformance-next. The native harness is the cheap structural
   proof; it does not substitute for this CLI red-first witness.

Every behavior slice records false lines on pre-fix code, restores the fix,
and proves the same production witness green. Run regular and serial_host
focused suites (native tests via `just test-el1-native`), contract-change,
source/base debt checks and pre-push clippy. Apply macOS cross checks and
Linux/KVM checks to touched code as required. The director promotes one signed
artifact through smoke-signed, conformance-probes, smoke and full conformance,
with Docker phases serialized and complete started/finished populations.
Repairing the separate libpython-map gate failure remains necessary evidence
infrastructure; it cannot turn missing workload execution into a pass.

## Work budgets and kill criteria

Require one authenticated admission, at most one host mutation and one terminal
reply per operation, with zero side effects for failed admission. Count staged
bytes, iovec visits, capability resolutions and completed mutations. Scaling
rows use 1, 16 and 256 entries plus mixed widths and a large final entry;
work is linear in actual bytes/entries, independent of unrelated tasks and
file tables. Suspension cannot repeat committed prefixes, full table scans or
namespace publication. Set numerical budgets from the existing owner algorithm
and native oracle before coding, not from a failing candidate's observed cost.
Target at most 2x native ARM Docker with paired release measurements; any
completing workload at least 10x stops promotion under the contract skill.

Stop this architecture bet if it requires a second descriptor namespace,
ambient carrier credentials, raw syscall fallback, a shadow lifecycle owner,
host-worker blocking on guest work, polling or widened timeouts. Stop a slice
if its production witness is not red first, if a typed operation cannot serve
both ISA clients, or if a claimed operation still increments refusal counts.
Do not weaken the unclaimed-call negative control to make mkdir pass.

Missing current baseline counts, image identity, native binding, completed
binaries or signed receipts blocks implementation acceptance. A docs review
can approve an approach with those measurements pending; it cannot declare
#1335 fixed or conformance restored. Keep the design PR draft until independent
review and the director's implementation ordering are recorded.

## Descriptor cleanup admission (#1678)

The retained fd-core close transaction supplies the descriptor lifetime half
of this slice: preparation reserves the exact slot and pins its description;
commit removes that slot and returns cleanup custody; cancellation releases
both without changing the descriptor. Cleanup settlement addresses the retained
description, never the old descriptor number. Range cleanup needs one such
receipt per removed description, including aliases of the same description.

Production integration is blocked on the other half: the existing native
host-file continuation has no typed close-cleanup operation that owns those
receipts through publication, cancellation and completion. `CarrierWork` drains
retired OFDs for final physical releases, but a close effect can apply while
other aliases remain. It therefore cannot replace per-close cleanup custody.
The current native descriptor close uses `CommitOwed(0)` when close effects
are present. Replaying the original numeric close after the slot is reusable
can act on a successor descriptor and is not a valid cleanup implementation.

The carrier cleanup venue must retain the exact description and the closing
caller's task and file-table identities, reserve service capacity before the
slot is removed, and consume record-lock, epoll and inotify effects exactly
once. It must use the existing crossing owner on both ISA adapters. Existing
host close helpers that capture an ambient host `FileTable` cannot establish
that authority for a native fork child. A final-release queue alone cannot
carry the per-close effect, and a second native descriptor table is excluded.

A check that effects are empty before closing is insufficient: registration
uses `require_pinned_close_effects` on an existing pin and can race the check.
An effect-free admission must either synchronize with registration or retain a
cleanup receipt when an effect appears; it cannot discard the receipt or
convert a committed close to an unrouted answer. `CLOSE_RANGE_UNSHARE` also
needs native successor-table publication rather than mutation of a shared
`CLONE_FILES` table. Keep `close` and `close_range` in the Forward allowlist
until these ownership paths and their production witnesses are implemented.

Required production witnesses close an old descriptor, reuse its number, then
settle or replay the old cleanup and assert the successor survives. Cover
single close and several range members, cancellation before publication,
service-capacity refusal, Busy once then success, late effect registration,
shared-table unshare and both ISA adapters. VM-free fd-core receipt tests prove
lifetime and rollback only; they do not establish production cleanup acceptance
or a signed census result.

## Pipe capacity allocation service (#1678)

`HostFileOp::PipeCapacity` extends the existing retained native service record.
Its fixed header carries the caller's table, fd, fcntl command and integer
argument; it carries no user pointer. The Linux decoder and carrier venue are
shared; the current native staging caller is AArch64-only. x86 has no native
host-file staging bridge on this main, so its pipe-capacity adapter remains
unimplemented and requires a neutral staging entry before acceptance. This is
an allocation crossing for an
in-zone object, not delegation of Linux pipe semantics to a host pipe.

The carrier pins the selected shared description through the fd authority,
without retaining a descriptor-table lock across pipe access or provisioning.
The exact pin spans allocation, capacity publication and wake delivery; a
concurrent numeric close/reuse cannot redirect it to a successor description.
The existing shared pipe core performs rounding, shrink/occupancy checks,
growth limits and revision/wake publication. The existing IPC owner provisions
backing and reclaims replaced extents. No new fd table or pipe path is added.

The VM-free child witness proves retained request/acknowledgement custody;
the shared production venue witness separately exercises backed growth and
both endpoints. Those compositional tests do not prove signed execution or
Linux oracle parity, which remain director acceptance requirements.

Pipe-capacity service errors keep Linux results separate from authority
failure. Ordinary unsupported requests retain counted ENOSYS. A stale object,
invalid backing, or failed exact-pin settlement is an invariant result that
passes through the runtime service boundary and becomes a carrier run error,
without publishing a guest reply. Settlement failure after a committed resize
overrides the provisional success; it cannot turn into ENOSYS or a replay.
This uses the adapter's existing Result error path, without new fatal sites.
