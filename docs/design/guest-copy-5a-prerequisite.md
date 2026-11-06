# Slice 5a: native sendfile witness prerequisite

Issue #1695 requires a production-entry, VM-free EL1 native-process witness
for `sendfile` with an explicit offset, refusing user copy once and then
completing without advancing offsets twice. This note records an unresolved
prerequisite; it does not claim implementation or acceptance of slice 5a.

The neutral `carrick_core::personality::CopyOutcome` protocol is present.
However, the native host-file venue has no `sendfile` operation:

- `carrick-personality-linux/src/native_host_file.rs` decodes
  `HostFileCall` and stages `HostFileOp` records. Neither has a sendfile
  variant; the wire operations live in `carrick-core-abi/src/host_file.rs`.
- `carrick-el1-linux/src/dispatch.rs` calls that decoder from
  `native_host_file_stage`. An unclaimed native call cannot use the host
  syscall dispatcher as a fallback.
- `carrick-el1-linux/src/native_process_runtime/service.rs` returns ENOSYS
  for a refused generic Crossing. A supplied generic Crossing is quarantined:
  no generic host syscall dispatcher owns native semantics.
- The existing production sendfile offset copies are in
  `carrick-kernel/src/dispatch/fs/sendfile.rs`, outside that native path.

Consequently, changing those existing host copy sites cannot demonstrate the
requested native-process witness. The next implementation needs one explicit
choice: extend the native service/ring implementation to serve sendfile, or
use a production `SyscallDispatcher` witness for the existing host operation.
The former introduces a service interface and needs the separate interface
design review required by AGENTS.md for wire layouts. Neither choice has been
made in this slice. A test-only dispatch bridge would hide the missing
production route and would not prove the claim.

`getdents64` has a native service path already. Its carrier invokes
`read_directory` using `DirectoryReadCaller::CarrierBuffer`, consuming entries
into the service reply. The ring then copies that reply into user memory.
`native_host_file::complete` accepts a boolean output callback, and native
service completion collapses `copy_syscall_output` with `is_ok()`. Migrating
that boundary must retain the completed reply across NotYet and repeat only
its user copy. Reissuing the carrier request would consume directory entries
twice. The host dispatcher's existing owner-memory directory continuation is
a different path and cannot stand in for this native completion witness.

No runtime behavior, copy-debt ceiling, contract budget, or routing allowlist
is changed by this note. Red/green witnesses, ISA builds, signed execution
and the slice's acceptance gates remain outstanding.
