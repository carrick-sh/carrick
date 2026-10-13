# In-ring file service over Carrick VFS

Design for [#224](https://github.com/carrick-sh/carrick/issues/224).
**Review required: no F1 implementation starts until the director approves this
design.** This document proposes slice boundaries and witnesses; none of the
behavioural witnesses below has been implemented or run by this documentation PR.

## Decisions and existing surface

The owner decisions in [#224 and its comments](https://github.com/carrick-sh/carrick/issues/224)
and [decision log #231](https://github.com/carrick-sh/carrick/issues/231) govern:

- File services are in-ring over Carrick VFS and delegated files. There is no
  new host file-object request family and no personality Forward path.
- Open may use one typed, counted member of the **existing HostObject crossing**
  because backing names and storage belong to the host. Host-bound open, read
  and write suspend through an owned continuation and release execution capacity.
- `FileRoot` grants contained root/mount-namespace authority. Non-Linux tasks
  do not acquire Linux uid/gid/DAC or a fabricated Linux file-descriptor table.
  Personality path translation, desired access, ACLs and share policy stay above
  this seam.
- `NameMatch::CaseFold` is required for M3. It applies to the final component
  through bounded indexed lookup; an O(directory population) readdir scan at
  open is forbidden.
- The M3 zone limits are 128 inode records, 256 KiB per delegated file and 512
  open records. Files outside zone eligibility retain a real host binding.
  Attributes refresh through the attribute operation.
- There is **no in-memory or fake FileService backend anywhere**, including
  test support. Behavioural tests use the real VFS, delegation and crossing
  implementation. Pure F0 type tests are not file-behaviour evidence.

[F0, merged PR #234](https://github.com/carrick-sh/carrick/pull/234), supplies
[`carrick-core::file`](../../crates/carrick-core/src/file.rs): `FileService`,
`FileRoot`, `NamePath`, `OpenRequest`, `OpenOutcome`, non-cloning `FilePin`,
`WriteAt::{Offset, End}`, attributes and distinct `IoError`s. The existing
[`carrick-personality-api`](../../crates/carrick-personality-api/src/lib.rs)
re-exports these types. `CallContext::with_files` binds the authority and
`cx.files()` is the call-facing handle. Unbound calls return `Unsupported`;
there is no shipped backend yet. `FilePending` is deliberately uninhabited.

[#209](https://github.com/carrick-sh/carrick/issues/209) and
[merged PR #210](https://github.com/carrick-sh/carrick/pull/210) supply `cx.user()`
over the existing checked, fault-aware user transfer machinery. File I/O uses
that same authority; no second pointer-copy implementation is introduced.

The inspected source owners are:

| Current owner | Responsibility and limitation |
|---|---|
| [`carrick-el1-abi::DelegatedFile` / `DelegatedOpenFile`](../../crates/carrick-el1-abi/src/lib.rs) | Shared inode bytes/size and separate open flags/cursor/incarnation. Open records have no seam pin count yet. |
| [`carrick-el1::file::ZoneFile`](../../crates/carrick-el1/src/file.rs) | Existing positional read/write and shared mutation core. Callers hold the inode authority; Linux lowering stays outside the neutral service. |
| [`carrick-el1::personality::file_table`](../../crates/carrick-el1/src/personality/file_table.rs) | Linux fd publication, duplication, fork and retirement; becomes a client of the same pin lifetime. |
| [`carrick-kernel::el1_delegation`](../../crates/carrick-kernel/src/el1_delegation.rs) | `enter_zone_at_open`, `delegate_transaction`, inode membership, recall and writeback. Admission currently requires Linux fd/table inputs and Linux eligibility policy. |
| [`carrick-vfs::FsBackend` and its host backend](../../crates/carrick-vfs/src/fs_backend.rs), [`kernel VFS`](../../crates/carrick-kernel/src/vfs/mod.rs) | Real contained path resolution, mounts, host opens and namespace mutation. Existing code has no neutral bounded CaseFold entry point. |
| [`carrick-x86-cpl0::linux_personality`](../../crates/carrick-x86-cpl0/src/linux_personality.rs) | Region-resident fd map, but static 16-entry open/object tables. Stdio is admitted; this is not regular-file service. |
| [`carrick-x86-carrier::entry`](../../crates/carrick-x86-carrier/src/entry.rs) | Constructs an unbound `CallContext`; the generic carrier must bind the neutral service without depending on Linux. |
| [`carrick-runtime` KVM executor](../../crates/carrick-runtime/src/vcpu_loop/executor/kvm.rs) | Existing tagged HostObject write/release handling is stdio-oriented. F4 extends its authenticated transport, not its Linux syscall fallback. |
| [`carrick-vmm-kvm::cpl0_boot`](../../crates/carrick-vmm-kvm/src/cpl0_boot.rs) | Retains the shared supervisor region and backing across VM/vCPU lifetime. F2 publishes a typed region binding from this owner. |

These are source anchors, not a line-pinned inventory. Existing implementations
move into shared ownership where needed; they are never copied into a parallel
personality or backend. Hot ABI/dispatch files integrate through their
[`CODEOWNERS`](../../.github/CODEOWNERS) owner.

## One authority and two storage venues

The planned ring implementation is `ZoneFileService` in the neutral
`carrick-el1` substrate, implementing the existing `FileService`. Its authority
contains the live region, root grants and authenticated open-record pins.
`DelegatedOpenFile` owns explicit references; `DelegatedFile` owns bytes, size,
mutation and notification admission. Host storage remains Carrick VFS's storage.
The proposed type names below identify owners, not already implemented APIs.

```text
personality call -> cx.files() -> ZoneFileService
    admitted delegated record -> ZoneFile positional core -> ring completion
    path open / host-bound storage -> existing HostObject crossing
        -> Carrick VFS / binding authority -> owned completion -> same service
```

An open record's storage venue is selected at admission. Zone refusal due to
size, capacity or unsupported storage preserves the same record with a host
binding, not a different FileService implementation. Recall transfers authority
before a host operation observes or mutates the inode. Recalled descriptions do
not opportunistically re-enter; retain the existing one-shot admission rule.

The backend authenticates a root's namespace and lifetime, and a pin's region,
open slot, incarnation and rights. Public `from_backend` constructors grant no
authority. A stale or foreign key returns a typed refusal before storage access.
One identity names the backing inode across separate opens; one pin owns one
reference to an open description. Explicit release consumes that reference;
there is no destructor I/O. A fabricated replay of a released key cannot retire
a reused slot, underflow references or close another process's file.

Positional reads/writes preserve the open cursor. `WriteAt::End` selects EOF
and commits bytes under the same inode mutation authority. An APPEND pin cannot
write at an arbitrary offset. Two live pins must see coherent bytes and size;
close by one task cannot destroy the other's authority. Last-pin retirement
hands off recall/writeback once and cannot park a guest execution worker.

## Slice plan and size ceilings

All ceilings count added **plus deleted** lines, including tests, contracts and
glue. They are planning allocations, not exceptions. If a necessary atomic
change cannot fit, stop and obtain approval for a revised decomposition before
coding. Each implementation slice starts with its linked issue and draft PR.

| Slice | Integration owner | Path | Ceiling | Exit |
|---|---|---|---:|---|
| F1 | `carrick-el1::substrate::ZoneFileService`; `DelegatedOpenFile` pin authority | Real VFS-admitted delegated records, shared `ZoneFile` core | 1,950 | Real backend and pin/positional contracts green; full path-open binding remains explicitly F4-owned |
| F2 | `carrick-x86-cpl0` table venue; KVM retained region owner | Region-resident open/object/cache tables, existing carrier transport | 1,800 | No static file tables; authenticated host/guest region publication and KVM receipt |
| F3 | `carrick-kernel::el1_delegation` neutral admission and binding registry | Existing VFS open -> neutral record admission -> separate Linux fd publication | 1,950 | Shared admission/lifetime; Linux is a pin client; rollback and recall contracts green |
| F4 | `ZoneFileService` pending state; VFS leaf lookup; runtime HostObject adapter | Counted Open/positional host I/O/attributes/release on existing crossing | 2,000 | All required end-to-end seam witnesses green, bounded suspension and lookup, required acceptance receipts |

Ordering follows #224: F1 and F2 can be developed independently; F3 follows
F1, and production F4 requires F1, F2 and F3. Coordinate ABI edits on the
owner's stack. No F1 shipping path pretends that F4's Open transport exists.
F5 is the out-of-tree consumer, not another Carrick file implementation.

### F1: first real FileService backend and pin lifetime

Implement the neutral ring backend over actual delegated records. Extract and
reuse the `ZoneFile` positional core and add atomic append admission. Add typed
pin acquisition/release to `DelegatedOpenFile`; Linux dup/fork/close/retirement
must account for the same references, replacing the last-reference fd-map scan
rather than retaining two close authorities. Partial publication rolls acquired
pins back. Inode notification and dirty-page publication retain their existing
owner and order.

F1 fixtures mount a real temporary host root through Carrick VFS, create/open
real files through existing production admission, and obtain backend-issued
pins over those records. Fixture setup may use today's Linux open entrance to
reach real delegation; the non-Linux test personality itself owns no Linux fd
table and calls only the neutral API. Setup is not evidence that neutral Open
works. No bytes, names, EOF or errors are served from an example HashMap or a
hand-filled DelegatedFile pretending to be the real backend.

Introduce the full behavioural witness inventory below in F1 and preserve red
evidence. F1's green exit proves positional create/write/read **after real VFS
creation/admission**, EOF, append and double-release lifetime, including two
live consumers. The name-error, CaseFold and complete `cx.files().open` chain
have their green production binding in F4. Record these as dependencies, not
passing, skipped or accepted failures. This distinction is proposed for director
approval: requiring all required production opens green in F1 would move F3/F4's
admission and continuation work into F1 and needs a different slice plan.

Witnesses also check cursor preservation, APPEND-offset refusal, stale/foreign
pins and rollback with a live peer. Deterministic work: pin retain/release visits
one open record, with zero fd-map population scan to decide last release;
positional I/O visits only the touched pages and bytes. Test populations
1, 16 and 512 and transferred spans 0, 1 page and the 64 KiB API cap.

Line allocation: 450 pin ABI/lifetime, 500 real service and positional sharing,
700 real-backend witnesses, 300 contracts/glue = 1,950. Because Linux lifetime
changes, exit requires focused VM-free proofs, clippy, lint-domains, portable
acceptance and the **full signed gate**, plus the affected existing EL1 file
contracts. No fake lower-layer pass substitutes for real admission evidence.

### F2: x86 CPL0 region-resident tables

This is the already planned table slice, not an alternative file backend. Move
the static open/object tables in `linux_personality.rs` into the retained
supervisor region using the shared ABI offsets and capacities. All access,
including stdio, uses one typed region venue. KVM retains and registers the host
mapping together with its guest region binding; guest VA, GPA and host pointer
remain different typed domains. Never reuse a process-global raw region pointer
as authority for another carrier.

Prove layout size/alignment and extent checks, stdio parity, access to records
beyond index 15, and failure on a foreign or retired region. A two-carrier
witness must show independent records; a two-live-task witness must show the
same carrier's intended shared inode with distinct open references. Use
`TestEl1Region` for aligned VM-free storage. Do not fabricate a FileService for
these layout tests, and do not claim regular-file open from a table-only test.

Line allocation: 500 shared venue/layout, 450 CPL0 migration, 300 KVM region
custody, 400 witnesses, 150 contracts = 1,800. Exit: old statics removed,
publication/retirement and existing stdio witnesses green, CPL0/KVM builds,
portable gate, full signed gate and merge-queue KVM `NEW=[]` receipt. Allocation
is bounded by the fixed region capacities, not by each guest MM or open call.

### F3: neutral admission, Linux publication and binding custody

Split `delegate_transaction` by **moving** its shared transaction into neutral
admission: root authorization, backing identity, inode membership/cache fill,
open incarnation, reference ownership and commit/rollback. Linux fd publication
is a later typed client transaction. Linux DAC, seccomp, observers and rlimits
remain Linux adapter policy; capability clients do not inherit them. Neither
client can publish a live handle before the shared transaction commits.

The proposed `FileBindingRegistry` belongs to the carrier's file authority in
`carrick-kernel`, with lifetime custody in `carrick-runtime`. It retains real VFS
open descriptions and issues generation-scoped host bindings. Raw host fds and
stdio encoding are transport details, never authority in a guest-created key.
No registry stores an alternate file implementation or a second byte cache.
Migrate the stdio binding client where necessary to avoid two registries.

Witness neutral admission without Linux fd publication, subsequent Linux
publication over the same inode, two live personalities' independent roots,
alias identity, failed cache fill, exhausted records, failed fd publication,
recall while another pin lives, and release after cancellation. Rollback returns
each reservation once and leaves no live unpublished binding. Retain existing
cross-process-reader/shared-inode/path-mutation tests as regression contracts.
Cache fill is bounded by 256 KiB per admitted inode; each transaction touches
its selected records and touched pages, with no whole-task census per pin.

Line allocation: 650 admission extraction, 350 Linux adapter, 350 binding
custody, 450 witnesses, 150 contracts = 1,950. Exit: no Linux fd requirement in
neutral admission, one registry and lifetime authority, green rollback and
cross-client contracts, portable acceptance, full signed gate and KVM receipt.

### F4: real Open and host-bound completion

Add typed Open and positional Read/Write to the existing counted HostObject
transport. Attributes and explicit release use that same authenticated binding
owner. The ring service remains the API owner: it either serves the admitted
zone operation or retains an owned crossing operation. It never forwards a
personality ordinal to the host Linux dispatcher. No new x86 Linux file syscall
crossing or allowlist expansion is needed or permitted by this plan.

Open resolves `FileRoot` plus neutral components through existing Carrick VFS
and mount containment, performs disposition/mutation under namespace admission,
then calls F3's transaction. Classify a missing parent separately from a missing
final leaf using the resolving owner; do not infer both from a flat ENOENT.
Symlink handling obeys `follow_final` and root containment. Readonly mounts,
directory expectations and failed create are real backend results.

CaseFold extends the existing VFS namespace authority with an indexed final-leaf
lookup shared by open/create/rename/unlink publication. It must work on Linux
hosts too; a case-insensitive macOS filesystem is not the implementation.
Directory-wide scans on the request path, including lazy index reconstruction,
are forbidden. Index admission/population work must have its own measured
budget and maintained mutation coherence. Cold lookup must either use an
already admitted index or a host primitive with the required bound; lack of
that mechanism blocks F4, rather than enabling a scan fallback.

The director must approve the precise Unicode folding/normalization and
multiple-matching-leaf policy before CaseFold implementation. The neutral API
does not define those today. The acceptance fixture includes ASCII mixed case,
non-ASCII names, colliding folded names and concurrent create; NT path syntax
and its status mapping remain outside Carrick. This design does not silently
choose an ASCII-only implementation or host-locale behaviour.

`FilePending` becomes owned operation custody: copied input or read result
buffer, exact root/pin/binding generation, byte progress, selected append
reservation, destination `UserRange` and exact MM/task completion authority.
There are no borrowed call buffers, frame references or retained vCPU leases.
F0's scratch buffer currently dies when `Pending` is returned; F4 must move
ownership into the pending operation before returning. On resume, read copyout
revalidates the initiating MM through #210's user-copy authority. Fault or
cancellation settles rights and storage once. Partial writes resume at their
retained offset; they never replay already committed bytes or select EOF again.

Recall/writeback must settle before host I/O, attributes or file mapping uses
the backing inode. Refresh the attributes the API exposes. The owner's fresh
timestamp requirement needs neutral typed timestamp fields beyond F0's
kind/len/read_only record; add them with their real refresh witness if M3 queries
them, rather than inventing or returning cached timestamps.

Witness the required full operations below on zone-eligible and real host-bound
files, forced recall, files beyond the 256 KiB cap, capacity spill, two live
processes and cancellation/exit. Exhaust the default executor pool while one
host operation is blocked and prove an unrelated guest runs. Completion must
enroll/park/wake once, with no polling, retries, timeout growth or extra pool.

Line allocation: 500 crossing/registry glue, 500 continuation and copy custody,
400 VFS CaseFold/error classification, 450 witnesses, 150 contracts = 2,000.
This is a hard feasibility check, especially for indexed CaseFold. If the
required index or suspension work cannot fit, revise the design with the
director; do not omit either feature or claim an implicit size exception.
Exit: all behavioural and work-budget bindings green; full signed acceptance
when Linux adapters change (otherwise the approved additive seam gate), portable
acceptance and merge-queue KVM `NEW=[]`. Production non-Linux `cx.files()` is
bound through the generic carrier and uses no Linux dependency in its facade.

## Behavioural red-first contract and evidence

[`core.personality.files`](../../conformance-contracts/contracts/personality-files.toml)
currently proves only F0 vocabulary. Extend its behavioural bindings, or add
separate stable contracts beneath that surface, before implementation. Existing
`kernel.el1.files`, `.shared-inode`, `.cross-process-readers` and `.path-mutation`
remain Linux regression obligations; they do not prove a non-Linux open call.

| Proposed witness | Real-backend assertion | Green binding |
|---|---|---|
| `file_name_vs_path_not_found` | Existing parent/missing leaf -> `NameNotFound`; missing parent -> `PathNotFound`; distinguish non-directory parent | F4 neutral Open |
| `file_create_write_read` | CreateNew reports `created`; existing open reports false; same identity, exact positional bytes, backing bytes after release; create collision -> Exists | F1 admitted data/lifetime; F4 whole open chain |
| `file_eof` | Exact EOF and beyond EOF return zero; short read returns remaining bytes without changing the cursor | F1 zone; F4 host binding |
| `file_append_two_live_pins` | End selection/mutation atomic across writers; no overwrite, preserved cursor, APPEND rejects arbitrary offset | F1 zone; F4 suspended host I/O |
| `file_casefold_leaf` | Mixed-case final leaf resolves without changing parents; exact and folded create/alias rules coherent, bounded lookup | F4 VFS/crossing |
| `file_double_release` | Replayed backend key -> Stale; reference count never underflows; reused incarnation and live peer survive | F1 zone; F4 pending release/cancellation |

Create/write/read is one scenario with separate create, write and read assertions;
the table covers all named behaviours from #224. Preserve each assertion's
pre-fix red output and post-fix output. A pre-F1 unbound `Unsupported` proves
the seam is absent, not that the append or lifetime algorithm is wrong: those
must also have failing real-backend structural/semantic assertions before their
respective corrections. Never bless Unsupported as expected open behaviour.

Use a non-Linux in-tree test personality with real VFS/crossing bindings for
the lowest capable layer, then the same service in mounted guest execution.
New guest probes belong in `carrick-conformance-next` via embed, not subprocess
CLI probes. Bound coordination with the existing test deadlines; test capacity
by admission outcomes rather than host timing. Structural observations carry
the exact graph/region generation and fail on missing/dropped measurements.

Budget zero host crossings for completed resident positional operations, one
open request per admitted open, one last-reference retirement, and no directory
population slope in CaseFold lookup. Count path-component visits separately;
that bound may depend on path length, never sibling count. Exercise 1, 32 and
1,024 sibling names and mixed component widths. For host I/O, count admitted
chunks/completions and copied bytes with linear bounds in transferred bytes,
including partial-progress/cancellation cases; no replay amplification.

Linux lowering uses public man pages and the native Linux oracle for
open/pread/pwrite/EOF/append/stat/mmap semantics. Neutral capability, error and
CaseFold rules use the approved #224 contract, not Linux errno guesses. NT
status/share semantics use carrick-nt's clean-room public specification and
oracle. No Linux, Wine or ReactOS source is an implementation input.

Implementation evidence follows [conformance contracts](../conformance-contracts.md):
VM-free red/green and deterministic work, actual guest binding, serialized native
oracle phase and required signed gates. Signed promotion belongs to one exact
artifact with provenance and cleanup; KVM evidence comes from the merge queue.
This Linux documentation worker has no Docker or HVF and claims neither.

## Consumers: NT M3 and x86 dynamic images

For NT M3, carrick-nt's F5 implements NtCreateFile, NtReadFile, NtWriteFile,
NtQueryInformationFile and NtClose over `cx.files()` and `cx.user()`. It translates
NT names into `NamePath`, retains explicit pins in its typed handle authority,
and maps `IoError` into its status vocabulary. Share modes/access checks use
personality-global typed state from #220, not host pid-keyed maps. F1 proves
the real shared substrate; F2 supplies its x86 venue; F3 supplies neutral root
admission; F4 makes M3's path open, CaseFold and suspension work end to end.
NT pins Carrick only at the merged main commit. F5 has its own <=2,000-line
slices and NT acceptance; #224's backend gate cannot declare NT M3 complete.

[#291](https://github.com/carrick-sh/carrick/issues/291) and its loader slice
[#296](https://github.com/carrick-sh/carrick/pull/296) load PT_INTERP and arrange
initial auxv, but ld.so then needs open/stat/read/**file mmap** in-ring. The
#231 decision explicitly waits for this seam and forbids new x86 file crossings.
The Linux personality must lower openat, stat/fstat and read/pread into the same
file authority and pin records, with Linux policy/status conversion at its edge.
Open may cross for real host storage using HostObject; the Linux ordinal never
forwards to an x86 host file syscall implementation.

F0 has no mapping operation, and F1-F4 alone do not implement file-backed mmap.
The #291 consumer must bind the opened backing identity and a retained mapping
reference to the existing exact-MM file-mapping owner. Mapping requires settled
recall/writeback, correct PRIVATE/SHARED semantics, offset/EOF rules and owned
frame publication. Closing the file pin cannot retire a live mapping. It must
not treat a host fd as guest memory or copy loader libraries through a second
file path. Any missing in-ring mapping/readiness seam gets its own reviewed,
<=2,000-line slice under #291, coordinated with the MM owner; this design does
not hide that work in F4's budget or enable a new mmap crossing.

The loader consumer's red-first witnesses are mapped bytes after close, EOF and
invalid offset/permissions, two live MMs with PRIVATE isolation, and the actual
Ubuntu `/bin/true` and `/bin/sh -c 'echo ok'` runs on the exact KVM artifact.
Count filesystem/HostObject bindings and ring completions to prove ld.so uses
the intended path. A PT_INTERP loader unit pass is not that workload's exit.
The file seam is a prerequisite; #291 remains open until mapping, Linux adapters
and both dynamic-image runtime witnesses have their own acceptance evidence.
