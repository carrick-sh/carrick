title: x86 fexecve / execveat(fd, "", AT_EMPTY_PATH) from a native child has no witness
parent: #2273

The x86 child exec path seals the caller's ring descriptor table from
`ipc::guest_venue(slot)` / `native_exec_table` as ARM does, so the host loader can
resolve a descriptor-named executable (#1530). No KVM witness drives it. If the
x86 IPC venue has no execution binding (cf.
`in_zone_child_pipe_write_without_ipc_execution_is_counted_enosys_in_ring`),
fexecve returns the loader's counted ENOSYS rather than running the file.

Acceptance: a KVM witness in which a fork child opens a static ELF and fexecve's
it. The witness must either run the successor or show the exact counted refusal.
