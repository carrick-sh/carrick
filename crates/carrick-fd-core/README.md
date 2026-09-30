# Descriptor substrate (checkpoint 3.1, shared records for checkpoint 3)

`Core<T>` owns T table identities as one `repr(C)` object of atomics with no
pointers, so a single instance can live in memory shared by the host and EL1.
Open file descriptions are elastic venue records (`SlotBacking::ofd`): the
venue publishes them in segments (`publish_ofds`, O(count), outside any lock;
the count is published with Release before the records join the lock-free free
list) and the core only resolves published indices. An empty free list is
`NeedsOfds`, an internal request: the venue grows and retries, or reports its
zone-wide file limit (ENFILE). It is never EMFILE and never ENOMEM by itself. Both venues operate on it through
`core.bind(&backing, wait)`, an `Authority` view supplying descriptor-slot
resolution (`SlotBacking`) and a lock-wait policy (`LockWait`, shared with
sched-core: EL1 uses a bounded spin and forwards on `Contended`, the host
waits). No `std`, `alloc`, host lock, host fd, syscall or venue binding is
present; the only dependency is the neutral `carrick-sched-core` lock-wait
trait. The workspace's `crates/*` membership includes this crate automatically.

Each table's slots and hierarchical free-slot bitmap live in a venue-provided
`Extent` (opaque token + capacity) stored in its `TableRecord` and resolved per
operation under the table's lock; tokens are never pointers. Descriptor backing
capacity is independent of the configured soft limit. The venue validates that
limit against RLIMIT_NOFILE's hard limit and `nr_open`; the core imposes only
the signed descriptor number's representation limit. When the lowest free
descriptor needs additional storage, `NeedsBacking` reports the required
descriptor count without changing entries or refcounts. The venue provisions a
larger extent **outside any lock** (`bitmap_words(capacity)` u64 words beside
the slots), calls `grow_table`, and retries. Geometric growth amortizes storage
replacement; `NeedsBacking` reports the minimum, not an allocation policy. The
venue must never translate `NeedsBacking` to EMFILE. EL1 never provisions: it
forwards before effects. `TooManyFiles` means no free descriptor exists below
the configured soft limit. A table may start with no backing (`Extent::EMPTY`),
including with a 1,048,576 soft limit.

`create_table` and `fork` consume an `Extent` only on success. `grow_table`
swaps larger backing into an existing table, preserving its identity, flags,
offsets, free holes and shared OFD reference counts; the argument receives the
retired extent. `destroy_table` likewise returns its extent after
finalization. No reference into replaced storage outlives the operation.

## Contract: kernel.el1.ipc-fd-authority

Shared-record rules (VM-free bindings: this crate's `el1_ipc_*` tests):

- **Publication.** Zeroed memory is a valid *unpublished* core; every operation
  fails closed (`StaleTable`) until the one initialization venue calls
  `Core::initialize(identity)`, which links the free lists and then publishes
  the nonzero identity with Release. A table becomes visible when its record's
  generation and then `state` (Release) are stored, under its lock.
- **Synchronization.** One lock word per table serializes every change to
  that table's slots, limit and extent; there is no whole-core lock, and no
  operation holds a lock across I/O. Lookups (`get`, `pin`) take no lock:
  they read the table's identity and extent under its sequence count `seq`
  (odd while a writer changes them), read the slot, and validate. A lock
  holder stopped mid-section (a vCPU the host took out of the guest) never
  stalls or refuses a lookup; only an extent or identity change in progress
  makes one wait. OFD reference/pin counts, status flags and offsets are atomic
  words shared by every table naming the description (fork, CLONE_FILES); the
  OFD and table free lists are tagged lock-free stacks. Lock order: at most one
  published table lock, plus the lock of an unpublished fork/create target.
- **Pins.** `pin(table, fd)` resolves a descriptor without a lock (the slot,
  the named record's generation, the slot again, then one OFD word; the
  generation is rechecked after the pin, so it holds the incarnation the fd
  named, linearized at the second slot read like `fget` racing `close`) and
  returns an owned, non-Copy `OfdPin` retaining that exact description
  incarnation. A pin that landed on a record freed and reused meanwhile is
  handed to the caller as `PinRaced` (its ownership, to release and retry). Closing or reusing the fd, closing every alias, or
  destroying the table never finalizes a pinned description: `holds` packs
  descriptor references (high 32 bits) and pins (low 32 bits), and whoever
  moves it to zero receives the description exactly once (from `close`,
  `dup2/3`, range/exec/destroy callbacks, or `unpin`). `pinned` reads current
  flags (F_SETFL from a sibling is visible to a suspended operation).
  `into_raw`/`from_raw` move the one ownership into and out of a shared
  continuation record; a stale, copied or foreign raw pin fails `StalePin`
  and changes nothing.
- **Pinned replacement.** `replace_pin` uses the same locked replacement as
  dup2/dup3. It retains the incoming OFD before retiring the displaced slot,
  so aliases never reach zero and readers see no intermediate absent slot.
  Refusal preserves destination flags, contents and incoming hold counts.
- **Generations.** Table IDs carry authority, index and a non-wrapping
  generation; OFD records advance their generation when freed, so reused
  indices never match stale keys. Exhausted generations retire the slot.
- **Budgets.** A pin reads exactly one descriptor slot twice at 65, 4096 and
  65,536 populated descriptors; allocation keeps the logarithmic bitmap budget
  below; zero allocation (no `alloc`). A contended lock with a bounded policy
  refuses with `Contended` before any effect. Concurrent pin/unpin/close from
  two forked tables finalizes exactly once (200 threaded rounds).

## Contract: fd-core-lifecycle-v1

Authority: Linux man-pages [dup(2)](https://man7.org/linux/man-pages/man2/dup.2.html),
[F_DUPFD](https://man7.org/linux/man-pages/man2/F_DUPFD.2const.html),
[F_GETFD](https://man7.org/linux/man-pages/man2/F_GETFD.2const.html),
[F_GETFL](https://man7.org/linux/man-pages/man2/F_GETFL.2const.html),
[close_range(2)](https://man7.org/linux/man-pages/man2/close_range.2.html).
Existing Carrick references: `dispatch/fs/close_dup.rs`, `dispatch/fs/locks.rs`,
`kernel/objects.rs`. No Linux kernel sources were used.

VM-free binding: this crate's unit tests. Scale points: 65, 130, 4096 and
65,536 backed descriptors; fully populated, descending single holes, sparse
holes, and every minimum. Growth tests start with zero/four slots and reach
65,536 and 1,048,576 while preserving references across fork and exec.
Allocation examines at most `2 * levels - 1` bitmap words, where each level
summarizes 64 words below it: O(log64 capacity) independently of occupancy.
Marking an allocated/freed slot updates one word per level. Lookup indexes one
table slot and one OFD slot. OFD allocation remains a free-list pop.
All core operations allocate zero heap objects; production code imports neither
`alloc` nor `std`. Table creation/fork cost O(backed capacity) (identities come
from a lock-free free list) and growth
costs O(backed capacity). Range close/exec/teardown scan backed capacity and
update the bitmap in O(log64 capacity) per closed descriptor, never scanning
O(last) for an unbounded close_range endpoint. Table identity uses a non-wrapping generation plus
authority identity; exhausted IDs fail closed.

Signed/EL1/host integration bindings and performance ratios are **not claimed**.
The director owns those later gates. No existing runtime behavior changes.

## Venue responsibilities

- Host and EL1 bind the SAME core in shared memory; never construct a second
  authority for the same descriptor namespace, and never copy records.
  Constructor identity allocation belongs to one initialization venue.
- CLONE_FILES owners use the same TableId, without adding OFD references.
  The venue tracks table owners and calls destroy_table at last-owner exit.
  Fork creates a new TableId and retains once per copied descriptor.
- On exec, unshare first if other tasks own the table. Then sweep close-on-exec.
  For CLOSE_RANGE_UNSHARE use unshare_close_range and atomically publish its
  successor for the calling task under the same ownership lock. Retire the old
  table only if its last owner leaves; siblings retain the old contents.
- close and dup2/3 return a description exactly when its final descriptor
  reference disappears. Range/exec/destroy deliver these to a callback, which
  must not panic or reenter. Consume these releases to finalize backing tokens.
  Dropping Core does not release external resources: drain tables first.
  The venue must also perform per-descriptor epoll/record-lock cleanup, including
  non-final closes; final-OFD notifications do not replace descriptor cleanup.
- A get snapshot does not retain an OFD; a suspended or in-flight operation
  (and future SCM_RIGHTS in flight) holds an `OfdPin` instead of a numeric fd.
  A final release from `unpin` obliges the venue exactly like a final close.
- Translate raw ABI constants to typed modes/flags. getfd/setfd model FD_CLOEXEC
  (ignore other F_SETFD bits); dupfd's bool selects F_DUPFD_CLOEXEC; dup3's bool
  represents validated O_CLOEXEC. Reject any other dup3/close_range raw flags
  with EINVAL before entering the core. Strip creation flags from open status,
  preserve additional immutable F_GETFL bits in StatusFlags::immutable, and
  encode access mode separately. F_SETFL ignores requested access/creation
  flags; setfl changes only APPEND, NONBLOCK, ASYNC, DIRECT and NOATIME.
  Before committing, authorize append-only attributes, NOATIME credentials,
  DIRECT support and async notification in the backing personality. O_PATH
  allows duplication and descriptor flags but rejects setfl with BadFd.
- Map BadFd to EBADF, InvalidArgument to EINVAL, TooManyFiles to EMFILE and
  NoMemory to ENOMEM. StaleTable, StalePin and BadBacking are venue ownership
  bugs, not guest errnos; Contended means "forward before effects".
  Resource exhaustion differs from the per-table soft fd ceiling. Existing
  descriptors remain usable after lowering the soft limit, including dup2 onto
  self, fork and close-on-exec above the new limit. A storage request is not
  a guest error: provision backing and retry, or report a genuine venue
  allocation failure. T and O remain venue-selected authority object counts;
  their exhaustion is NoMemory, distinct from descriptor backing and limits.

Run `cargo test -p carrick-fd-core` and
`cargo clippy -p carrick-fd-core --all-targets -- -D warnings` for this revision.
The earlier bare-metal check is not rerun for this crate-scoped review fix.
