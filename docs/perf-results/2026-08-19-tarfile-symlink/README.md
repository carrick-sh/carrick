# `..` inside a symlink TARGET was collapsed lexically

`cpython-tarfile` had one diverging row,
`TestExtractionFilters.test_parent_symlink`. It is a path-traversal test, so the
divergence is security-relevant, not cosmetic.

## The divergence

The archive builds, inside the extraction directory:

    current -> .
    parent  -> current/..
    parent/evil        (a file written THROUGH the symlink)

`reducers/parent-symlink.py` reduces it to the path resolution alone:

| | `realpath parent` | `parent/evil` lands at |
|---|---|---|
| docker | `…/outerdir` | `outerdir/evil` |
| carrick (before) | `…/outerdir` | **`outerdir/dest/evil`** |
| carrick (after) | `…/outerdir` | `outerdir/evil` |

Note `realpath` agreed even while the open did not — Python computes it in
userspace from `readlink`, so it exercised a different path than the kernel walk.
A reducer that had checked only `realpath` would have reported no bug.

## Cause

`canonicalize_following` expands a relative symlink target by joining it onto the
directory holding the link with `join_rootfs_path`, which collapses `..`
LEXICALLY. For `parent -> current/..` that cancels `..` against `current` and
lands back at `dest`, where Linux resolves `current` to the directory holding it
and then climbs to that directory's PARENT.

The tree already knew about this bug shape — `resolve_at_path` carries a comment
saying "`join_rootfs_path` collapses `..` LEXICALLY, before symlink resolution, so
it gets this wrong" and routes around it via `resolve_dotdot_symlink_aware`. But
that guard fires only when the INPUT path contains `..`. Here the `..` is inside
the LINK'S TARGET, which the guard never inspects, so the fast lexical path was
taken.

## Fix

`join_symlink_target` routes a target containing `..` through the existing
symlink-aware walk and keeps the cheap lexical join for every other target, which
is almost all of them.

The two are mutually recursive — the symlink-aware walk canonicalizes each
symlink intermediate it meets — so a cycle like `a -> b/..`, `b -> a/..` could
recurse until the stack died. LTP stacks ~43 links on purpose (`stat03`,
`lstat02`, `truncate03`). A thread-local depth budget caps it at Linux's
MAXSYMLINKS and reports ELOOP, which is what Linux reports.

## Verified

- reducer matches the oracle exactly (`outerdir/evil`);
- `test_tarfile` whole suite: run=619, **SUCCESS**, 0 failures;
- ELOOP-sensitive LTP cases unaffected: `stat03` 6/0, `lstat02` 6/0, `open13`
  14/0, `readlink03` 8/0. `truncate03` is 7/1, and that row PREDATES this change —
  `ltp-truncate03` is `incomplete` with 1 diverging row in both `closure-v9` and
  `closure-v10`;
- `just ci` green (3,913 tests).
