# Scope correction: what `ca96024a` did and did not close

`ca96024a` ("fix(runtime): restore mmap failure atomicity on the E1
refusal path") closes with the claim "No errno can newly originate after
the address/scrub steps on the candidate route." That claim is
**overstated**, and per the honest-status rule the correction is recorded
here, in the same spirit as the correction that commit itself made to
`f2a42bc3`'s body.

## What `ca96024a` DID close (red-first)

The regression E1 introduced: the candidate fallback routed through
`snapshot_private_mmap_file`, whose stricter HostFile arm could return
EIO (fstat failure) or EBADF at a point after `next_mmap_address` and the
`zero_anonymous_reuse` scrub, on every lane whose backend refuses the
lowering (linux4k, all VMM lanes). Repro'd by
`mmap_private_hostfile_refusal_with_unstattable_fd_keeps_legacy_success`
(refusing backend + dead host fd): EIO on the broken tree, legacy
zero-filled success after. The fallback is now bit-compatible with the
pre-E1 eager HostFile arm (best-effort `pread`, `let _ = n;` in both).

## What it did NOT close

Two TOCTOU EBADF rechecks remain in the candidate phase-2 block
(`crates/carrick-runtime/src/dispatch/mem.rs`, the
`let Some(open_file) = this.open_file(fd.0) else` and
`let OpenDescription::HostFile { .. } = &*open else` arms, ~:2708-2716
at `ca96024a`). Both return `EBADF` after
`next_mmap_address` / `zero_anonymous_reuse` /
`prepare_mmap_locked_range` have run, and both are reachable when a
sibling guest thread closes or `dup2`s the fd between the phase-1
candidate check and the phase-2 recheck — `io.open_files` is a separate
RwLock, unserialized against the mem lock the dispatch holds, so the
window is real.

## Why this is a pre-existing class, not an E1 regression

The pre-E1 general path carried the same shape: its eager bytes block's
own `EBADF` return (`85ec0f4c:2451+`) also executed after
`next_mmap_address` and the reuse scrub, so a failed mmap could already
leave a scrubbed reused range behind. E1 neither introduced nor widened
that window; it inherited it, and `ca96024a` reduced the candidate
route back to exactly the inherited surface.

## Disposition

The class fix — an audit of every errno return in the mmap dispatch that
can execute after address-space commitment, in both the candidate and
general paths, with rollback or reordering plus red-first coverage — is
filed as its own task by the review ("Close mmap failure-atomicity
TOCTOU gaps") and is deliberately not implemented in the Task-5 line.
Until it lands, `ca96024a`'s guarantee should be read as: *the candidate
route adds no failure surface beyond the pre-E1 eager path's own.*
