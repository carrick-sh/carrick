# One owner for memory waits (`kernel.memory.owner-wait`, #802)

Owner-backed stream `recvfrom` reads and validates `addrlen` after payload
copyout, including when the pointers alias and under `MSG_PEEK`. Empty sockets
still return errno 11 or wait before touching address completion. The VM-free
recvfrom witnesses cover zero/negative post-copyout lengths (success/errno 22),
invalid length pointers (errno 14), and retained read/write waits after copyout.
Address completion resumes its exact phase and never receives again; payload
and metadata each use one bounded prepared copyout, with no permit held while
waiting.


The #711/#802 owner contract is:

- Owner waits are killable-only; stops and handled signals never complete them.
- Fatal process-wide cancellation (SIGKILL or group exit) stops every waiter's
  resume, regardless of the thread selected for signal delivery.
- Cancellation uses native terminal custody for every completion origin:
  mailbox trap, direct-EL0 IPC record, and physical dependency. A typed origin
  prevents the direct-EL0 route from publishing a mailbox response or retiring
  a guest trap completion it does not own.
- Nothing is consumed before secured copyout, or after cancellation is pending.
- Writer exclusion is released before re-preparation.
- All users share one settlement path, including already-ready enrollment.

`vcpu_loop::owner_wait::OwnerWait` owns dependency release and settlement for
physical, zone and supply-ready resumes. Every cancellation query consults the
exact lifecycle page's monotonic `CancellationAuthority`; signal delivery
reservation and native dequeue cannot erase it. Native signal state binds the
root or freshly admitted child page. Terminal custody consumes the obligation
without clearing its cause. At owner-wait enrollment and task-wake edges,
bridge SIGKILL eligibility is authenticated against the exact native recipient
and promoted to that same authority before settlement. Native ingress retains
signal delivery. The atomic publication elects one subscription rebroadcast so
siblings checked earlier also observe cancellation. The bridge witnesses cover
two live parked members, a sibling-selected process signal and a thread-directed
signal, without dependency release or signal polling; dequeue cannot undo
cancellation. Nonfatal wakes perform exactly one bridge query per parked member
at populations 1, 8 and 32 (the initial membership scan measured 1, 64 and 1024).
The core concurrent-publication model proves that only one caller owns the
rebroadcast, even after terminal consumption.

A validated fatal request atomically closes effect admission. Its typed
publication drains existing bounded effects outside signal/topology locks,
then publishes before queue/wake delivery. `ProcessEffect` is non-cloneable
and non-Send; prepared output retains it through consumption, copyout and
cursor/descriptor publication, releasing it before notifications or waits.
An already-ready resume must acquire effect custody after securing memory.
This orders actual effects before fatal publication, not merely the earlier
cancellation sample. Rejected stale targets cannot request cancellation;
accepted targets that retire during drain fall back to the process queue.

The physical witnesses use real `pipe2` dispatch and `PendingContentWrite`,
with a live carrier leader and a separately admitted non-leader waiter.
Against main's physical route, ready SIGKILL committed output, non-leader
SIGKILL installed descriptors, and immediate/scheduled retry retained writer
exclusion. The actual leader-reservation tests exercise the delivery gap.
Native IPC and sleep witnesses need #735's retained-operation prerequisites:
restoring unconditional trap retirement fails direct-EL0 completion; ordinary
sleep owner parking wakes on a handled signal before editor release. These
are regression controls with prerequisites, not pristine-main builds.
A late-kill test publishes during re-preparation: without effect admission it
commits one output, with admission none. Empty IPC reads and stale authorized
SIGKILL posts also have red-first review regression controls.

Six runtime loom models call shipping settlement and cancellation code with
loom atomic words. They explore editor release, sibling effects, process
cancellation, nonfatal deferral, two waiters and already-ready enrollment.
The strict model asserts no consumption after fatal publication. It is not
an expected panic. There is no preemption/permutation/time cap; each execution
has a 1,000-branch bound. Core models separately exercise concurrent admission, two admitted effects,
request/publication and terminal consumption. Production queues, mailbox
transport, scheduler enrollment and the complete editor-holder audit remain
outside these models; the production witnesses bind the modeled protocol to
its adapters. See [input disposition and scope](../design/owner-wait-handoff.md).
Signed HVF acceptance remains director-owned on this Linux worker.
## Private fixed file segment replacement

`kernel.mm.private-file-fixed-replacement` covers the libpython loader shape
reported in #759: a real file mapped PROT_NONE over `0x65ee48` bytes, fixed
RX text over `0x64ee48`, then fixed RW data at `+0x47a000` over `0x1d4000`.
Linux `mmap(2)` requires replacement and private stores, including guest-page
aligned addresses and offsets that are not host-page aligned. Internal copy
bounds and host-page congruence cannot introduce ENOMEM. The descriptor records
open reproduction and signed/oracle bindings explicitly until demonstrated.

The production-source VM-free binding is
`libpython_fixed_file_segments_use_owner_source_without_eager_copy`. It uses
`AddressSpace`, a real host file, the shared dispatcher and the admitted
reservation root. Its pre-fix RED is eager compatibility-image initialization;
it does **not** reproduce the ARM ENOMEM return. The code path that makes such
fallbacks invalid is the whole-length `write_bytes_unchecked` in `mmap.rs`,
which reaches the admitted owner's UserWrite PREPARE (bounded to 4096 bytes).
It also asks the old root/placeholder for write permission before replacement
has committed. The trace's backend refusal and omitted offset still need Mac
attribution; this finding alone cannot certify the recorded ARM failure.

The binding also forces a real nonroot `RLIMIT_MEMLOCK` refusal on a fixed
LOCKED replacement. It requires errno 12 while retaining the predecessor's
file source and permissions; the pre-fix implementation removes that mapping.

Admitted regular private host files now retain one source in the existing
owner root and retire old physical backing before committing new metadata.
First touch uses the existing private frame-grant service; no VA is reused as
an IPA and no host-page congruence is imposed on the source offset. Fixed
host-served placement preserves the predecessor until successful publication.
POPULATE, LOCKED, GROWSDOWN and nonregular objects keep their existing paths.
The source lease is secured before physical retirement. A typed retirement
result proves whether a refusal preserved the predecessor: preparation and
authenticated clean descriptor refusal can return ENOMEM before any chunk
commits. Any partial or unknown retirement, failed TLBI, or backend failure
after descriptor retirement fails stopped while source custody remains held.
`retirement_refusals_are_clean_only_before_any_chunk_commits` exercises the
production progress classifier with refused, rolled-back and unsettled
receipts. Signed first touch, private-store/fork
integration, the exact observed ENOMEM attribution, Python startup, native
ARM64 oracle and full artifact promotion remain required.

The local signed trace records reservation flags **0x822**, including
MAP_ANONYMOUS; file text and data use **0x812**. The fixture now covers both
that anonymous reservation and the requested file-backed variant. The
production-component binding `libpython_old_deferred_recipe_and_owner_copy_refusals`
registers the RX file view, applies the derived alignment trims, and proves
that a fixed data overlap is refused by `reserve_private_file` with
`InvalidRange`. Both tested data offsets then exceed `PreparedStreamRanges`'s
unchanged 4096-byte limit. In the old dispatcher the lowering error selects
whole-map snapshot fallback; `write_bytes_unchecked` reaches that owner
PREPARE refusal and the dispatcher converts it to ENOMEM (12). This is a
production registry plus production admission reproduction, without a fake
memory backend. The trace carries only four mmap arguments and no backend
refusal message, so exact-offset/branch live confirmation remains for the Mac.
The fallback first requests writable physical protection, which can itself
refuse before the bounded copy is reached; the component witness establishes
the incompatible fallback, not which downstream ENOMEM exit the Mac took.
The signed static case reads the actual immutable OCI libpython file; a new
mutable /tmp file would not bind the original lowering path.

Run the signed selectors with
`CARRICK_RUN_ID=759-libpython-map env -u RUSTC_WRAPPER CARRICK_SCCACHE=0 just test-conformance-next case_libpython_ --nocapture`.
The [fixture instructions](../../crates/carrick-conformance-next/tests/fixtures/libpython-map/README.md)
describe source and executable identity and the pending native ARM64 bless.

## Frozen select and retained poll/select publication (#986 slice 4)

`kernel.memory.owner-wait` covers immediate select and the terminal output
of retained poll/select waits on the shared retained-output transport.
Readiness or deadline expiry freezes the return count and all result bytes.
A memory refusal transfers the dependency and the output cursor; resumption
never samples readiness, reads input sets, resolves numeric fds, or starts a
new relative timeout. The retained wait keeps its original descriptions,
registrations and absolute deadline until publication completes or is dropped.
Temporary signal-mask restoration remains in readiness completion and is not
repeated by output resumption.

Select writes page-contained units of at most 4096 bytes across all three
sets, preserving the committed prefix on a later genuine fault (errno 14).
Poll writes only its two-byte `revents` fields, preserving edited `fd` and
`events` fields. Its field remains one prepared unit across a page boundary.
The 1/8/512-entry VM-free schedules require exactly `n + 3` preparations and
`n` commits across one owner, one supply and one physical refusal, with no
input reads and no repeated commits. Physical dependency custody is released
before the next preparation. An 8192-byte select set requires one committed
4096-byte prefix before the second-window refusal and one suffix commit on
resume. Stale task/ASID and fatal/group-exit rejection access no guest memory.

These bindings exercise the production dispatcher and completion fold. They
do not establish signed scheduler/VMM or Docker differential acceptance.
Those gates remain director-owned. Immediate ppoll publication and the other
operation families still listed on #986 remain outside this slice.
