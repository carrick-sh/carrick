# Native exec child executable link (#1862)

`process.exec.native-exe-link` requires `/proc/self/exe` to select the
exec successor's image rather than the carrier/root executable. The
VM-free binding forks through the production native process owner, consumes
an authenticated exec reply, and dispatches readlinkat while both processes
remain live. It requires the executed path and zero forwarding.

The futex portion uses `kernel.futex.contention`: a timed child wait must
retain its original deadline across owner-copy refusal, enroll once and
wake exactly one waiter. The scheduler's existing per-record timer owns
expiry; ancestry cannot decide whether a deadline is allowed.

Signed execution and the real go-build row remain director-owned.

## Deferred design: live executable authority

The red readlink witness is deliberately not a conformance pass. A native
exec successor has no executable object in its ring task row; the host
`CurrentExecutable` implementation already retains the loaded object and a
shared dentry display updated by namespace rename and unlink. Neither the
carrier root's `ProcState` nor exec's pathname or argv[0] is the child's
executable authority.

A follow-up should return a typed executable-object capability with successful
exec preparation, bound to that exact successor MM and service identity.
The ring task row owns it after the exec adoption cut, fork inherits it, a
failed exec preserves the old capability, and final task retirement releases
it. A carrier lookup may read the retained object's display but must never
infer identity from the host process. The capability must keep the existing
`CurrentExecutable` object/display registry alive, so rename, directory
rename and unlink continue to update every holder. Exec cancellation must
release the proposed capability; successful replacement must release the
predecessor only after successor adoption. Late replies for an old MM or a
reused TaskKey must fail exact identity validation.

One possible ABI is two nonzero words (handle and generation) in the sealed
`ExecSuccessorManifest`, included in its digest and authenticated by the
existing service identity/receipt. A typed native file request would carry
that capability plus the readlink output capacity; the ring would own
copyout and its returned byte count, including truncation without a NUL.
No large by-value pathname belongs on EL1/CPL0 stacks. This is a proposal,
not an implemented or independently reviewed layout.

Required witnesses before adopting that design: two live processes with
different executable identities; failed exec retaining the previous identity;
exec through a relative path and through a symlink; fork inheritance; rename
and directory rename updating both holders; unlink appending ` (deleted)`
while the retained image remains usable; output truncation and owner-copy
suspension; cancelled preparation and final retirement reclaiming exactly
one capability; stale reply rejection after MM/record reuse. Reuse the
existing executable authority and resolver rather than adding a second procfs
path parser. Signed real go-build and native ARM Docker remain the director's
evidence, as does the separate post-exit hang.

## x86 seam

The shared syscall table classifies canonical futex as the same family, but
`El1PendingFamilies::futex` currently requires an ARM frame and forwards an
x86 frame. The host-native x86 `NativeLane` explicitly disables timed waits.
Neither is fixed by removing the ARM adapter's stale host-record check.
The follow-up must supply a native x86 scheduler venue to the existing
neutral futex client, using its per-record timer owner and ISA clock/timer
transport, rather than copying Linux futex policy into the carrier. The
executable-capability proposal must likewise be neutral; the x86 successor
must inherit/adopt the same task-owned capability when native exec is wired.
CPL0/KVM build or entry-test success alone does not prove this shape served.
