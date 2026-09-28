# Descriptor substrate (checkpoint 3.1)

`Core<T, O>` owns T table identities and O shared open file descriptions.
Each table borrows venue-provided descriptor slots and a hierarchical free-slot
bitmap through `TableStorage`. No `std`, `alloc`, dependency, host lock, host fd,
syscall, or venue binding is present. The workspace's `crates/*` membership
includes this crate automatically.

Descriptor backing capacity is independent of the configured soft limit. The
venue validates that limit against RLIMIT_NOFILE's hard limit and `nr_open`;
the core imposes only the signed descriptor number's representation limit.
When the lowest free descriptor needs additional storage, `NeedsBacking`
reports the required descriptor count without changing entries or refcounts.
The venue supplies larger slots plus `bitmap_words(capacity)` u64 words, calls
`grow_table`, and retries. Geometric growth amortizes storage replacement;
`NeedsBacking` reports the minimum, not an allocation policy. The venue must
never translate `NeedsBacking` to EMFILE.
`TooManyFiles` means no free descriptor exists below the configured soft limit.
A table may start with no backing, including with a 1,048,576 soft limit.

`create_table` and `fork` consume a `TableStorage` only on success. `grow_table`
swaps larger backing into an existing table, preserving its identity, flags,
offsets, free holes and shared OFD reference counts. The argument receives the
retired backing, which can be reused for another table or recovered with
`into_parts`. `destroy_table` likewise returns its backing after finalization.
No pointer into replaced storage is retained. Supply storage with a lifetime
covering the authority; recycling slices does not require dropping the core.

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
`alloc` nor `std`. Table creation/fork cost O(T + backed capacity) and growth
costs O(backed capacity). Range close/exec/teardown scan backed capacity and
update the bitmap in O(log64 capacity) per closed descriptor, never scanning
O(last) for an unbounded close_range endpoint. Table identity uses a non-wrapping generation plus
authority identity; exhausted IDs fail closed.

Signed/EL1/host integration bindings and performance ratios are **not claimed**.
The director owns those later gates. No existing runtime behavior changes.

## Venue responsibilities

- Serialize each complete core operation with exclusive access to the Core.
  This lock covers tables **and shared OFDs**; a table-only lock is insufficient
  for forked tables that share offsets. No blocking I/O belongs inside it.
  Host and EL1 must share one authority and its synchronization, not copy it.
  Constructor identity allocation belongs to one initialization venue; do not
  independently construct authorities in separately linked address spaces and
  exchange their IDs. IDs are not persistent serialization identifiers.
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
- A get snapshot does not retain an OFD. Finish offset/flag transactions under
  the lock; asynchronous I/O and SCM_RIGHTS need a future owned pin mechanism.
  This core counts descriptor references only and is not wired into I/O yet.
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
  NoMemory to ENOMEM. StaleTable is a venue ownership bug, not a guest errno.
  Resource exhaustion differs from the per-table soft fd ceiling. Existing
  descriptors remain usable after lowering the soft limit, including dup2 onto
  self, fork and close-on-exec above the new limit. A storage request is not
  a guest error: provision backing and retry, or report a genuine venue
  allocation failure. T and O remain venue-selected authority object counts;
  their exhaustion is NoMemory, distinct from descriptor backing and limits.

Run `cargo test -p carrick-fd-core` and
`cargo clippy -p carrick-fd-core --all-targets -- -D warnings` for this revision.
The earlier bare-metal check is not rerun for this crate-scoped review fix.
