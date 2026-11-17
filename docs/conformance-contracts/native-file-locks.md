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
  exit. A read lock needs a readable description, a write lock a writable
  one (`EBADF`).
- fcntl(2), OFD locks: owned by the open file description, `l_pid` must be
  zero, released on the description's last close.
- flock(2): owned by the open file description, a separate family from
  fcntl locks; a conversion is not atomic; released on the last close.

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
- x86: `serial_host_root_and_fork_child_contend_record_locks_and_flock`
  (production KVM CPL0, the run root and its fork child, against the native
  oracle; red: fcntl x10 and flock x4 refused).

## Not served

`l_whence` `SEEK_CUR`/`SEEK_END` and descriptions the carrier did not stamp
stay a counted ENOSYS; `F_SETLKW` reports no `EDEADLK`.
