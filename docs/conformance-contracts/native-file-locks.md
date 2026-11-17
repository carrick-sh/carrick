# kernel.native.file-locks

Contract: [`conformance-contracts/contracts/native-file-locks.toml`](../../conformance-contracts/contracts/native-file-locks.toml).
Issue: #231 (apt: `Could not get lock /var/lib/apt/lists/lock - open (38:
Function not implemented)`).

## Guest surface

`fcntl(2)` `F_GETLK`, `F_SETLK`, `F_SETLKW`, `F_OFD_GETLK`, `F_OFD_SETLK`,
`F_OFD_SETLKW`, and `flock(2)`, on a native process's ring descriptor of a
host file.

## Linux authority

- fcntl(2): a record lock belongs to the process (Linux keys it on the files
  table); another owner's conflicting lock refuses `F_SETLK` with `EAGAIN`
  and `F_GETLK` reports it with its holder's pid (`-1` for an OFD lock);
  `F_SETLKW` waits and is interrupted by a signal; a close of ANY
  descriptor of the file releases the closer's record locks, and so does
  exit, and exec closing a close-on-exec descriptor of the file (execve(2)
  keeps record locks otherwise). The `struct flock` is copied in once, at
  the call. A blocked `F_SETLKW` whose descriptor another thread closed or
  replaced goes on with its open file description; once the lock is free
  it returns `EBADF` holding nothing (native oracle, Linux 6.12). A read lock needs a readable description, a write lock a writable
  one (`EBADF`).
- fcntl(2) ranges (native oracle, Linux 6.12.115, x86_64): a base or a
  range end past the largest file offset is `EOVERFLOW` (`l_start =
  i64::MAX, l_len = 2`; `(i64::MAX, 1)` succeeds); a range starting before
  offset 0 is `EINVAL` (`(-1, 1)`, `(5, -6)`, `(i64::MAX, i64::MIN)`).
  Refusal order: an `O_PATH` descriptor is `EBADF` before the `struct
  flock` is read (not `EFAULT`); `F_GETLK` refuses an `l_type` other than
  `F_RDLCK`/`F_WRLCK` first, then the base and range; `F_SETLK` checks the
  range before its `l_type` and before the description's access mode; an
  OFD command's nonzero `l_pid` is `EINVAL` after both. flock(2) refuses
  an unknown operation (`EINVAL`) before it looks at the descriptor.
- A lock that cannot be allocated is `ENOLCK` (fcntl(2), flock(2)). Linux
  has no fixed table; Carrick's has `IPC_FILE_LOCKS` records, so a set (or
  an unlock that must split a range) that finds no free record answers
  `ENOLCK` with nothing changed. That is a true capacity limit (the call
  holds the table's exclusion, so it is never contention).
- fcntl(2), OFD locks: owned by the open file description, `l_pid` must be
  zero, released on the description's last close.
- flock(2): owned by the open file description, a separate family from
  fcntl locks; a conversion is not atomic; released on the last close. A
  blocked flock whose descriptor was replaced takes the lock (0) and holds
  it until the description's last reference, its own call's, ends (native
  oracle). OFD locks and flocks of descriptions kept across exec stay.

## Carrick invariant

Locks are compat-zone state, owned by the ring, never by a host fd (a host
fd would make every guest process one lock owner). One neutral table
(`carrick-fd-core::record_lock::LockTable`) lives in the IPC directory and is
serialized by the `FileLocks` IPC object's lock. A lock names its file by a
typed `FileIdentity` (device and inode of the guest's stat), which the
carrier stamps on the description before any descriptor names it; its owner
is a descriptor table (`LockOwner::Table`) or one description incarnation
(`LockOwner::Description(OfdKey)`). Owner liveness is the descriptor
authority's: a retired table or a released description never blocks.

A blocking request is an owned `IpcOpKind::FileLockWait` operation pinning
its description: it enrols on the lock object's `Readable` lane under the
table lock, then parks, releasing its execution capacity. Every release
publishes that lane; the woken call takes its operation back before any
descriptor lookup and probes once. Contention is never an errno.

The operation keeps the request decoded at entry (`RawLockRequest`: kind
and range), and a rerun takes exactly that lock, never a re-read of user
memory. Routing a woken call asks for its retained operation before the
descriptor's current object, so a sibling's close or dup2 of the number
cannot strand the operation or its description pin. When nothing blocks a
record lock, before it is taken, the descriptor is asked under the lock
table's exclusion whether it still names the pinned description
(`Authority::names_pinned`); if not, the call returns `EBADF` with nothing
taken. A close that retires the descriptor after that answer releases the
table's record locks under the same exclusion, so after the lock exists.
No lock is ever taken and then given back, so a full table can never leave
a lock held that the guest was told it does not hold.

The owner's descriptor authority waits with a `ShortLockWait`
(`EL1_WAIT`, bound through `waits_out_writers`, which accepts no other
policy): a busy descriptor-table writer is waited out, never refused. An
fd authority `Contended` on this path is therefore a broken invariant, not
an errno or a counted ENOSYS; a bounded policy cannot be bound here
without a type error.

close(2) and the descriptor a dup2/dup3 replaces release the record locks
of the file the retirement returned (`carrick_fd_core::Retired`), read in
the same descriptor-table acquisition that vacated the number, never of a
file sampled apart from it.

## IPC layout change (ABI version 9)

The directory gains, after the pipe allocator store, one
`OfdIdentityRecord` per OFD record and the lock table (a header and
`IPC_FILE_LOCKS` records). `IPC_MAGIC` moves to version 9 and the layout
facts fold `record_lock::LAYOUT_FACTS` into `IPC_LAYOUT_HASH`; a version-8
magic or hash is refused at attach
(`el1_ipc_file_lock_layout_refuses_the_previous_abi`). `IPC_DIRECTORY_BYTES`
stays inside `EL1_IPC_DIRECTORY_SPAN` (a compile-time assertion), which
both ISAs map.

## Existing-mechanism inventory

- `carrick-kernel/src/dispatch/fs/locks.rs` (`LogicalRecordLocks`): the
  host dispatcher's arbiter for host-dispatched tasks (the ARM run root).
  It stays the root's owner; its blocking flock
  (`wait_flock_interruptibly`) and `F_SETLKW` (`wait_set_interruptibly`)
  loops wait on a condvar with a 10 ms timeout, which this contract does not
  extend or copy. Retiring it onto the neutral table is a follow-up.
- `carrick-sched-core::object_wait`, the IPC operation arena and
  `ipc::park`/`snapshot`: the existing readiness wait used by pipes, epoll
  and single-description poll, reused for `FileLockWait`.
- `carrick-fd-core` deferred release (`DeferredRelease`), the retired-OFD
  and retired-table drains in `carrick-kernel::el1_ipc`: reused for the
  description's last reference and for exit.

## Witnesses

- ARM: `serial_host_arm_fork_children_contend_record_locks_and_flock_in_the_ring`
  (production ARM dispatch of two live fork children; red: every call -38).
- ARM, #2452 review: `serial_host_arm_woken_lock_waiters_take_the_request_they_parked_with`
  (the request survives a rewrite of the caller's `struct flock`),
  `serial_host_arm_lock_waiter_goes_on_with_its_description_after_a_sibling_replaces_its_fd`
  (routing by the retained operation; `EBADF` for F_SETLKW, 0 for flock),
  `serial_host_arm_close_releases_record_locks_of_the_file_it_retired` and
  `serial_host_arm_dup_releases_record_locks_only_of_a_displaced_file` (a
  sibling's change of the table played at the `close_retire_hold` test hold),
  and `native_exec_pipe_tests::serial_host_native_fork_exec_ends_record_locks_on_close_on_exec`
  (the production exec service's close-on-exec sweep).
- ARM, #2452 re-review: `serial_host_review_record_lock_overflow_matches_linux`
  (`(i64::MAX, 2)` is `EOVERFLOW`; controls `(i64::MAX, 1)` 0 and `(-1, 1)`
  `EINVAL`; red on 820b8bb11: -22),
  `serial_host_arm_record_lock_range_and_refusal_order_match_linux` (the
  oracle's range table and refusal order) and
  `serial_host_arm_replaced_lock_waiter_with_a_full_lock_table_answers_ebadf`
  (a stale rerun on a full table answers `EBADF` holding nothing; red on
  3f83746a7: `ENOLCK`).
- x86: `serial_host_root_and_fork_child_contend_record_locks_and_flock`
  (production KVM CPL0, the run root and its fork child, against the native
  oracle; red: fcntl x10 and flock x4 refused), and
  `serial_host_exec_close_on_exec_ends_record_locks_and_keeps_flock_and_ofd_locks`
  (a fork child execs: its record lock ends, its flock and OFD lock stay,
  byte for byte with the native oracle), and
  `serial_host_fork_child_record_lock_ranges_and_refusal_order_match_native`
  (`native_record_lock.S -DRANGES`: the overflow rows and refusal order,
  byte for byte with the native oracle; red on 820b8bb11).

## Not served

`l_whence` `SEEK_CUR`/`SEEK_END` and descriptions the carrier did not stamp
stay a counted ENOSYS (so their `EINVAL`/`EOVERFLOW` range answers, which
need the description's offset or size, are not given either, including an
`F_SETLK` with a bad `l_type` and such a base); `F_SETLKW` reports no
`EDEADLK`.
