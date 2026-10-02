# Stage 2a namespace checkpoint (partial)

Base: `00ed7a580d2ddf24d71b6bccfc1abc1cc4d19c83`, branch `work/stage2a`.
This is a VM-free implementation checkpoint, **not milestone 0 acceptance**.
No cache ownership has moved. No Docker phase or signed guest has run.

## Open census and deletion

`carrick-vfs::serial_host::test_namespace_open_work` measures repeated writable
regular-file opens with and without truncation at 1/8/32/128 requests, with
0/128 unrelated directories. It retains all descriptions and proves independent
offsets, real backend opens, returned size, and zero warm dentry parent opens.

Before the change, both populations gave the following per-request counts:

| Operation | Backend opens | Metadata calls | Identity calls | Parent opens |
| --- | ---: | ---: | ---: | ---: |
| Writable open | 1 | 2 | 0 | 0 |
| Truncating open | 1 | 3 | 1 | 0 |

The new `metadata + identity <= 3*n` assertion failed first at one truncating
open: observed 4, budget 3. The baseline census without that tighter assertion
ran every scale/population pair; all counts were linear in request count.

`HostFsBackend::open_raw_fd` and `open_raw_fd_with_metadata` now use the
existing descriptor-relative guest-open primitive for truncation too.
This deletes the `resolve_following` leaf pre-stat from ordinary truncating
opens. A destructive open requires a contained parent before `O_TRUNC`;
leaf symlinks still take the rerooting resolver. The byte-exact spelling guard
runs before a destructive open. Returned metadata comes from the opened fd.

After the change, truncating opens use 1 open, 2 metadata calls and 1 identity
call per request at every scale/population pair. Writable non-truncating counts
are unchanged. There is no CPU-saving claim from this instrumented census.

These are the existing macro-routed open/stat and identity counters. They are
**not an exhaustive host syscall count**: rename/unlink, xattrs, close, fcntl,
and path visits need additional scoped measurement before acceptance.

The existing mutation census on the base recorded zero warm opens and:

- Same-parent rename: `4*n` metadata calls.
- Cross-parent rename: `4*n + 1` metadata/identity calls.
- Unlink: `n` metadata calls.

## Open acceptance work

The contract descriptor now includes openat and invokes the open census from
the existing mutation fixture. Its signed binding remains explicitly unresolved.
Required work still includes the two-live-process scale/population matrix for
same/unrelated parents, hardlink no-op, NOREPLACE, exchange, lower-layer
copy-up/whiteout, archive rollback, unlink-open and directory rename; exact
host-call/path-visit measurements; signed structural binding and both-libc
namespace/path probes; reviewed retirement of superseded admitted/trusted
paths; clean-tree inventory/lint verification; and the director's oracle,
native macOS control and paired ecosystem campaign.

## Coordinator resolution deletion

`admitted_parent_resolution_is_once_per_operation` failed red-first with 256
resolver invocations for 128 operations. It also checks that topology admission
already holds before resolution and through publication. The duplicate pass
and `same_anchors` retry loop have been removed; the resolver is now `FnOnce`.
The original pinned capabilities survive reservation waiting and publication.
Same-parent reservations still exclude each other, unrelated parents progress,
and directory/symlink changes retain exclusive topology admission.

The former synthetic test that swaps resolver output between calls modeled a
second resolution, not an admitted topology writer. It is replaced by checks
for exclusive topology admission spanning resolution and publication; retained
capability lifetime and reservation-error tests remain. This does not claim
cross-carrier external-writer coherence.

Verification so far: final `just test-kernel` and `just fmt-check` passed;
the final VFS suite passed all 305 tests after the coordinator deletion. The first broad
`just test` stopped on the intentional 256-versus-128 red. The subsequent full
`just test` passed, including the parallel/serial VFS partition and the host
runtime/platform suites. No signed acceptance is implied by these results.
