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
remove it when the host-served root exits or its predecessor MM retires on
image replacement, including a seed left by a refused fork reservation.

Canonical syscall 78 stages a path record with the caller's access context.
The carrier receives the executable from the authenticated caller MM, and
uses the shared readlink target lookup under `NativeFsAuthority`. The ring
copies only the completed reply bytes through the existing owned copyout
continuation. A busy copy retains those bytes until its owner can resume;
an inaccessible destination returns errno 14. Unused buffer tails are never
accessed. The output allocation is bounded by the existing 64 KiB record
budget and the caller's positive signed buffer size. There is no polling,
new wait queue, host-task syscall fallback, or crossing allowlist change.

Non-`/` roots and foreign or other proc/fd magic links remain counted
refusals. Ordinary symlinks use the same VFS implementation. The x86 decoder
already desugars `readlink` to `readlinkat`; the x86 carrier has no native exec
custody yet and supplies no executable identity. That remains seam #1903.

## Evidence

The native fixture drives fork, exec adoption, shared syscall dispatch,
host-file staging and the retained service continuation. The physical adapter
retains a real executable reference and calls the carrier dispatcher. It
checks exact copyout bytes, zero generic forwarding, a busy copy followed by
success, a copy fault returning errno 14, truncation, and errno 22 for zero
or negative buffer sizes. It does not execute ELF
instructions or prove the HVF preparation/adoption transport. The staging
witness for an unmapped unused buffer tail is red before the copyout change.

Kernel venue tests exercise simultaneous distinct executable holders,
inheritance, root rename/unlink publication, truncation, and drop lifetime.
The HAL retirement entry preserves executable custody through quarantine
and releases it after reclamation. The HVF cancellation crossing's existing
witness also checks executable retention returns to baseline; it needs the
macOS lane. The relative/symlink/failed-exec loader witness is also behind
`platform-macos`; a Linux test filter selects zero tests and is not evidence
for it. These are custody/venue proofs, not substitutes for live
vfork/thread/exec population tests. Signed native Go, full lifecycle
population witnesses, Docker differential and runtime ratios remain required
for acceptance.

## Round 3 semantic red

The dispatch/copyout fixture is a lower-layer control, not prepare/adopt
coverage. With only the READLINKAT routing arm in
`carrick-personality-linux/src/dispatch.rs::route_shared` temporarily
removed, the repaired control reaches the real fork/exec successor syscall:

```text
CARGO_BUILD_JOBS=3 cargo test -p carrick-el1-linux --lib serial_host_native_fork_exec_child_readlink_exe -- --nocapture --test-threads=1
exit 101
assertion left == right failed: native child readlinkat(/proc/self/exe):
expected executable bytes; negative result is Linux errno
left: -38
right: 16
```

The control now returns the production refusal's result to the semantic
assertion instead of failing on its route first. Its SVC syndrome and
scheduler activation are the corrected head fixture, and it reaches errno
**38**, not Declined or a non-runnable record. Restore the routing arm after
this mutation; no production mutation is committed. Durable worker log:
`/var/lib/carrick-conductor/evidence/1862-r3/semantic-red.log`.

## Production lifecycle bindings (round 3)

The six `carrick-conformance-next::native_exe_lifecycle` cases replace the
supplied-object controls as the production population witnesses. The
fixture forks two children and actually execs distinct copies, one by a
relative pathname and one via a final symlink. Each child reads its own
link before acknowledging startup. They remain live while separate cases
exercise real fork inheritance, vfork/shared-MM, two live threads, failed
exec, and root rename/unlink. No host test binds executable custody.
The fixture README names the precise preparation-binding mutation and
signed commands.

Native Linux x86_64 ran all six fixture scenarios successfully and the
AArch64 musl fixture compiled. These qualify the choreography, not the
Carrick lifecycle. The production capability and physical adopt path are
macOS/AArch64-gated; this worker cannot execute the new guest cases or the
binding-removal experiment. Their signed green and mutation red results
remain **unverified**, as does the native arm64 Docker bless. Do not count
Linux fixture controls or a cross-check as either result.
