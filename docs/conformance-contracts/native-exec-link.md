# Native executable links (part of #1862)

Contract: `process.exec.native-exe-link`.

`readlinkat(2)` returns at most the supplied positive buffer size, without a
NUL. `proc_pid_exe(5)` identifies the executed object and appends ` (deleted)`
when its name is unlinked. The executable belongs to the MM: fork inherits
its live object, while threads and vfork share the MM until exec.

The native loader already returns `ExecSource`. Preparation converts it to
`CurrentExecutable` in the dispatcher's existing executable registry. Its
reference is retained in the prepared image and then in the successor's
`ForkHostBackingCustody`. Cancellation drops preparation, adoption transfers
custody, fork clones it, and retirement drops it. No ring capability row or
exec manifest field is added. `ExecutableIdentity` is only the neutral
carrier's opaque retention interface to that existing object.

The root fork seed additionally captures the root dispatcher's current
executable beside the filesystem seed. Its short-lived CPU slot is qualified
by the stopped execution identity and consumed at fork reservation. This is
part of the existing `RootOnlyState::RootForkSeed` retirement obligation;
remove it when the host-served root is removed.

Canonical syscall 78 stages a path record with the caller's access context.
The carrier receives the executable from the authenticated caller MM, and
uses the shared readlink target lookup under `NativeFsAuthority`. The ring
copies only the completed reply bytes. The output allocation is bounded by
PATH_MAX and the caller's positive signed buffer size. There is no polling,
new wait, host-task syscall fallback, or crossing allowlist change.

Non-`/` roots and foreign or other proc/fd magic links remain counted
refusals. Ordinary symlinks use the same VFS implementation. The x86 decoder
already desugars `readlink` to `readlinkat`; the x86 carrier has no native exec
custody yet and supplies no executable identity. That remains a seam.

## Evidence

The first commit is the requested witness from `0a2481914e`, adapted only to
exclude the separate timed-futex changes. The corrected pre-fix fixture at
`d5bf064f0` reaches Forward, then fails because `native_unstaged_exit` returns
Declined instead of its expected Refused(Served). This is not an errno-38
observation. Earlier buffer-length failures are fixture errors, not semantic
red evidence.

The native fixture must model the production host-file staging and service
continuation after the normal family's unclaimed result. The physical adapter
retains a real executable reference and calls the carrier dispatcher, and
checks the bytes passed to the MM copy boundary. It does not execute ELF
instructions or prove the HVF preparation/adoption transport.

Kernel venue tests exercise simultaneous distinct executable holders,
inheritance, root rename/unlink publication, truncation, and drop lifetime.
These are custody/venue proofs, not substitutes for live vfork/thread/exec
population tests. Signed native Go, full lifecycle population witnesses,
Docker differential and runtime ratios remain required for acceptance.
