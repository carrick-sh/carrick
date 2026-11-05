# Native child descriptor family (#1678): incomplete implementation

The existing `kernel.el1.ipc-fd-authority` contract covers this family.
Linux authority is dup(2), fcntl(2), close(2), and close_range(2). Fork copies
slots and descriptor flags while sharing open descriptions and pipe state.
Carrick must keep one descriptor namespace and settle each mutation once.

The production-entry two-child fixture already exercises dup, dup3 with
O_CLOEXEC, F_DUPFD, F_GETFD/F_SETFD, F_GETFL/F_SETFL and close. This slice
extracts its setup for two additional defect-baseline witnesses:

- `serial_host_native_child_pipe_size_commands_lack_ring_handler` calls
  F_GETPIPE_SZ and F_SETPIPE_SZ with 12288 and 131072. Each currently returns
  Forward without changing the input fd. Acceptance must instead serve them,
  with Linux capacities 65536, 16384 and 131072 respectively.
- `serial_host_native_child_close_range_lacks_ring_handler` calls close_range
  for descriptors 0..4. It currently returns Forward and leaves fd 4 live in
  both children. Acceptance must instead serve it, removing fd 4 in only the
  calling child's table.

The successful targets were run before implementation on admitted main
`81c091aef5e8aaff3e5e770127c6e31c2b7a03f1` with only the fixture extension:
`just test-el1-native --only serial_host_native_child`. Both failed with
`left: Forward`, `right: Served` (GETPIPE_SZ command 1032 and close_range).
The committed assertions restore that measured defect baseline. They do not
call the final native unclaimed-capture policy or assert errno 38. No carrier
service, capacity result or full acceptance is proved by this baseline.

Backed-pipe growth, range CLOEXEC/UNSHARE, cancellation, concurrent close/reuse,
and signed execution remain unproved. The implementation is unfinished; keep
this branch draft and do not promote its allowlist.

## Independent review: prerequisites

Review found no need for a second descriptor path. It identified P1 gaps that
must be resolved in the crossing-owner design before implementing new wire
layouts or cross-crate lock ordering, as AGENTS.md requires:

1. The ring descriptor owner has no pipe-size fcntl arm. Existing pipe capacity
   mutation and host pool allocation belong to `IpcZone::resize_pipe` in
   `crates/carrick-kernel/src/el1_ipc.rs`. Do not duplicate its algorithm in
   ring, cap requests at the default size, or claim unbacked-only success as
   complete support. A proposed typed host-file capacity service must retain
   the authenticated caller/table/description or select its admission point
   explicitly. Numeric fd re-resolution after close/reuse must not redirect a
   previously admitted operation. Review the wire encoding before coding it.
2. Plain range close must reuse filtered IPC release, delegated binding
   settlement and host close effects from the existing close owner. The raw
   fd-core range callback runs under the table lock and cannot reenter that
   authority to perform these effects.
3. UNSHARE needs a process-runtime resource transition. Existing
   `Aarch64NativeProcessService::fork_fd_table` can prepare the copied fd-map,
   descriptor table and owned IPC mapping, but does not publish a calling
   process's successor resource identity. Updating only CurrentTask or the IPC
   map breaks the graph's ownership. Design reserve/prepare/commit/rollback
   with exact task generation and old table identity before implementation.

The proposed pipe service should reuse the existing authenticated HostFile
record and ticket, rather than raw fcntl forwarding. Its storage ordering must
preserve the current allocator protocol: sample the object under its lock,
release it, provision storage, release the allocator lock, replace storage and
publish readiness under the object lock, release it, deliver wakes, then
reclaim retired storage. No allocator or object lock survives carrier execution
or a guest park. Both ISA clients need a shared service binding.

The UNSHARE transaction's actual graph/resource/fd-map/IPC-map acquisition and
publication order remains unresolved. Admission refusal must retain the
operation on its existing release notification; cancellation before commit
reclaims the prepared successor, and cancellation after commit settles it once.
A separate independent review of that order is still required. No wire or
lock-order change is implemented here.

Director-owned signed smoke, complete EL1 population comparison, and the Mac
`dupclosestdin`/`fcntlpipesz` root-versus-child census and Linux oracle remain
required. This Linux fixture cannot substitute for them.
