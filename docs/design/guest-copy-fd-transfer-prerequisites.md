# Slice 5a production witness prerequisites

Issue #1695 requires migration onto #1691's `UserCopy` / `CopyOutcome` and
production-entry, VM-free EL1 native-process witnesses for `getdents64` and
`sendfile` offset copies. The following is a scope blocker, not evidence of
completion or a proposal for another copy outcome type.

## Current production paths

- `carrick-personality-linux/src/crossing.rs` classifies `Getdents64` and
  `Sendfile` as permanent crossings, with in-ring admission disabled.
- `native_host_file.rs` can stage `HostFileCall::Getdents64` through
  `HostFileOp::Getdents64`. Its reply completion still takes a boolean copy
  callback. Migrating this common completion seam also affects the native
  host-file staging family assigned to slice 3.
- Neither `HostFileCall` nor `HostFileOp` has a sendfile operation. The
  production implementation is the host dispatcher's
  `dispatch/fs/sendfile.rs`, using `CurrentMmMemory`, not core `UserCopy`.
- Host directory dispatch already prepares owner output and retains the
  directory description, lease and cursor on a memory wait. Its existing
  owner-refusal coverage is not an EL1-native sendfile witness.

Consequently a test invoking a newly invented native helper cannot prove the
requested production sendfile behavior. Converting a `NotYet` result to a
boolean or replaying a committed host transfer would also violate the task.

## Decision needed before implementation

Choose the production venue for this slice's sendfile witness:

1. Exercise the existing host dispatcher in a VM-free harness, retaining
   transfer completion and offset-output authority through its existing
   owner-memory continuation. This changes the issue's EL1-native witness
   criterion, and needs an agreed bridge to the core typed copy interface.
2. Add sendfile to the shared native host-file protocol and service entry,
   then exercise it through the EL1 native-process harness on both ISA
   adapters. This adds service and protocol scope beyond copy-site migration;
   the protocol interface needs the design review required by AGENTS.md.

Either choice must coordinate the shared native-host-file completion seam
with slice 3, leave #1672 IPC and slice 2 lifecycle copies alone, and retain
#1691's single outcome type. The required witness must refuse an offset copy
once, release its real owner dependency, then complete with one transfer and
one offset advance. Directory refusal must similarly preserve the unread
entries until output is secured.

No red/green witness or guest-copy-debt reduction is claimed by this note.
