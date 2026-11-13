# x86 fd and IPC parity (#1756, #2269, #2107, #1959)

This lane builds on #2153's NativeIpcExecution, rather than constructing an
x86 IPC owner. Linux authority is the read, write, readv, writev, pipe2,
fcntl and epoll_wait manual pages. No outside implementation source is used.

## Existing mechanisms and routes

Locations below describe the design baseline; they are navigation references,
not a generated or enforced line-pinned inventory.

| Guest syscall (x86 number) | ARM ring owner | x86 baseline on #2153 |
| --- | --- | --- |
| read (0), write (1) | `crates/carrick-el1-linux/src/ipc.rs:446` serve_ipc_with_signals, admit/run | Source-backed entries use the same engine via `dispatch.rs:4390` ipc_transfer_native; no-source entries decline, counted ENOSYS under strict routing. Fork-child EIO in #1756 still needs reproduction. |
| readv (19) | No admitted route in `crates/carrick-personality-linux/src/dispatch.rs:703`; shared engine does not admit 65 | Counted ENOSYS; needs shared vector-input/copyout ownership, not x86 implementation. |
| writev (20) | `crates/carrick-el1-linux/src/ipc.rs:1099`, retained vector cursor in shared admit/run | Same NativeIpcExecution engine on source-backed entries. |
| pipe2 (293) | `crates/carrick-el1-linux/src/dispatch.rs:4788`, shared descriptor namespace and pipe core | Served through same owner; CLOEXEC settlement on exec needs two-process witness. |
| close (3), dup (32), dup2 (33), dup3 (292) | `crates/carrick-el1-linux/src/dispatch.rs:5137`, duplicate_owned_ipc and settle_native_release | Shared zone descriptor owner; root host descriptions preserve delegated ownership. |
| fcntl (72): DUPFD, GETFD/SETFD, GETFL/SETFL | `crates/carrick-el1-linux/src/dispatch.rs:5238`, shared fd authority; root host descriptions retain host FileTable | Published shared namespaces, including the tested CLI root, serve these commands. A borrowed host-only namespace can decline with counted ENOSYS. Main reaches the redirected write before failing; preserve one owner per description. |
| epoll_create1 (291), epoll_ctl (233) | `crates/carrick-el1-linux/src/dispatch.rs:4788`, shared epoll core | Shared descriptor/epoll owner. |
| epoll_pwait (281), epoll_pwait2 (441) | `crates/carrick-el1-linux/src/ipc/epoll.rs:117`, serve_with and retained park/report | #2153 serves both through NativeIpcExecution; do not duplicate. |
| epoll_wait (232) | ARM uses canonical epoll_pwait, same epoll owner | Unknown at ring decoder (`crates/carrick-personality-linux/src/entry.rs:13`); host-only shim cannot serve a zone epoll. Normalize four input arguments to pwait with NULL mask in the shared decoder. |

## Acceptance and boundaries

Use real KVM production pool witnesses: two live pipe peers with exact bytes;
CLOEXEC exec-status EOF; root save/redirect/restore including fd and status
flags; legacy wait with garbage unused registers to prove normalization.
Existing `kernel.ipc.epoll-zone` contracts own epoll behavior and work bounds.
Every wait retains its owned operation and releases execution capacity; no
host readiness pipe, polling, retries or enlarged budget is introduced.

The scoreboard comparison must use current GitHub main and final head on this
VM, outside tmpfs. It includes py-version/thread/fork/subproc, node-version/child,
and go-version/hello, with exact next-stop stderr for failures.

Do not edit the other lanes' fault, prepared-page or owed-return settlement
functions (#2263, #2266, #2250). A successful IPC probe does not establish that
these independent lifecycle/memory blockers have landed.

## Implemented shared correction and evidence limits

Legacy x86 wait normalization now discards the two non-arguments and retains
native identity 232 while selecting the canonical pwait owner. Pipe readv now
shares imported vector custody with writev; one range walker supplies gather
and scatter, and the neutral transaction records only delivered bytes. A later
scatter fault leaves undelivered pipe bytes intact. Vector calls never enter
the scalar host-file fallback with an iovec address interpreted as a buffer.

Real KVM passes all five family bindings: exact scalar child-to-parent byte,
readv scatter, exec-failure report followed by EOF, root fd/status flags and
redirect/restore, and legacy epoll wake with garbage non-argument registers.
The pool root's fcntl already passed before this lane changed production code;
it cannot demonstrate the reported CLI-root refusal. No crossing change is
justified by that pool result alone.

The successful-exec CLOEXEC and exhausted-default-pool gaps are recorded in
`followup-1.md` and `followup-2.md`. The failed-exec witness does not claim that
x86 exec replacement is implemented. Signed ARM, Docker differential and
artifact promotion are not established by these KVM or VM-free tests.

The existing legacy host continuation also consumes retained vector metadata.
It prepares all destination ranges in one bounded owner permit before locking
the source, then scatters through the same range walker and pipe transaction.
This preserves one consuming source lease across vectors, including aliases,
without one guest syscall or one preparation per tiny vector. Fixed-record
copyout keeps its stack arrays and existing prefix policy; stream-vector
storage uses the same preparation and commit owner. A real destination fault
selects a bounded secured prefix, and no bytes outside that prefix are consumed.
The handback bindings cover retained progress, one owner refusal followed by
success, metadata preservation, real faults, reclamation, and 1/64/1024 tiny
vectors with exactly one valid preparation.
The retained host consumer is
`crates/carrick-kernel/src/kernel/continuation/ipc.rs:785` (`complete_handback`);
its range preparation is the existing copyout owner, generalized for both
array and vector storage at
`crates/carrick-kernel/src/dispatch/copyout.rs:302` (`prepare_outputs`).
