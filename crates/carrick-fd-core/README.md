# Descriptor substrate (checkpoint 3.1)

`Core<T, F, O>` owns T fixed-capacity descriptor tables and O shared open file
 descriptions. F is 1..=4096 and is also the maximum advertised RLIMIT_NOFILE
hard ceiling for this instance. No `std`, `alloc`, dependency, host lock, host
fd, syscall, or venue binding is present. The workspace's `crates/*` membership
includes this crate automatically. Larger/growable tables are not implemented.

## Contract: fd-core-lifecycle-v1

Authority: Linux man-pages [dup(2)](https://man7.org/linux/man-pages/man2/dup.2.html),
[F_DUPFD](https://man7.org/linux/man-pages/man2/F_DUPFD.2const.html),
[F_GETFD](https://man7.org/linux/man-pages/man2/F_GETFD.2const.html),
[F_GETFL](https://man7.org/linux/man-pages/man2/F_GETFL.2const.html),
[close_range(2)](https://man7.org/linux/man-pages/man2/close_range.2.html).
Existing Carrick references: `dispatch/fs/close_dup.rs`, `dispatch/fs/locks.rs`,
`kernel/objects.rs`. No Linux kernel sources were used.

VM-free binding: this crate's unit tests. Scale points: 65, 130, 4096 fds;
fully populated, descending single holes, sparse holes, and every minimum.
Allocation examines at most two leaf bitmap words and one summary word;
lookup indexes one table slot and one OFD slot. No loops on the open, dup,
dup2/3, close, get/set flags or offset paths. OFD allocation is a free-list
pop. All operations, including fork, allocate zero heap objects: the crate
cannot link an allocator because it imports neither `alloc` nor `std`.
Cold table creation/fork are O(T + F); range close/exec/teardown are O(F),
never O(last) for an unbounded close_range endpoint. Table identity uses a
non-wrapping generation plus authority identity; exhausted IDs fail closed.

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
  self, fork and close-on-exec above the new limit. Never advertise a limit > F.

Run `cargo test -p carrick-fd-core` and
`cargo check -p carrick-fd-core --target aarch64-unknown-none` for the local proof.
