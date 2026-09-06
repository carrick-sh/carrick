# macOS cap-std retirement acceptance

This checkpoint targets macOS/HVF. The parked branch is accepted only after
full serial runtime tests and the fs/stat/link guest family on both libc lanes,
plus glibc launches and Python coherence/performance loops. No performance
claim or ecosystem floor is established by the host tests below.

## Authority review

The historical 88 host-authority diagnostics were position changes, not 88 new
host APIs. The acceptance inventory and main both contain 628 review IDs with
identical classifications. Source positions are reconciled only after committing
source, then committed before lint. The compiler catalog does not enumerate raw
`openat`/`mkdirat`/`unlinkat` leaves; their authority is reviewed here explicitly.

| Boundary | Classification and authority |
| --- | --- |
| Scratch root acquisition (`ContainedExtractor::open`, backend constructors) | Declared backing: caller-authorized scratch directory, opened once as an owned directory fd. |
| Layer namei component traversal | Declared backing: root fd and validated single components; no-follow directory opens, bounded symlink expansion, absolute targets restart at scratch root. Escaping parent traversal is refused. |
| Layer create/link/delete/whiteout | Declared backing: authenticated parent fds and validated leaves. Whiteout suffixes reject empty, dot, dot-dot and slash before recursive deletion. Root opaque whiteout clears the held root fd. |
| Metadata and guest xattrs on macOS | Declared backing: exact inode opened relative to authenticated parent, using O_SYMLINK and O_NONBLOCK; no ambient root-path reconstruction. |
| Directory enumeration and cache | Declared backing: independently opened directory descriptions prevent shared seek-offset corruption. Shared topology generations invalidate attached aliases after mutations; disabling the cache retains fd-relative namei. |
| fd administration | Declared substrate/backing according to owner: clone/close/fstat/fchmod operate only on held descriptors; they do not reinterpret guest identities as host targets. |

Non-macOS final-symlink metadata is fail-closed and not qualified here. Further
cross-platform work is deferred per the campaign's macOS/performance scope.

## Host regression evidence

The actual-layer root opaque-whiteout test failed before its fix because a
lower-layer file survived. Rootfs module: 74 passed. Streaming integration:
5 passed. Full serial macOS runtime library: 2465 passed, 2 ignored.
Durable local logs are under `target/conformance/eco-resume/` in the acceptance
worktree: `root-opaque-red.log`, `rootfs-green.log`,
`rootfs-streaming-green.log`, and `runtime-full-serial-host.log`.

Earlier red-first checks reproduced absolute and relative symlink escape,
whiteout parent deletion, directory-header fidelity failures, metadata alias
escape and cache/offset defects. The dot-dot tar entry was already refused;
it remains a guard, not a newly failing test. The ordinary directory symlink
case is positive compatibility coverage.

Guest gates, artifact identity, and performance receipts remain pending.
