# Demoting cap-std: eliminate the `--fs host` containment-walk amplification

> **Status: PLAN (2026-07-03).** Design for a deliberate, probe-gated refactor.
> Grew out of the inotify09 perf work: every `--fs host` amplification problem
> (the ~291× `test_glob` walk, the `watch_fds` re-walk, the inotify write-path
> stat) has the SAME root — cap-std enforces containment by re-opening every
> path component. We keep caching *around* it; this removes the root.

## Root cause

macOS has no `openat2(RESOLVE_BENEATH)`, so cap-std's rooted `Dir` enforces the
sandbox by walking the path **component by component**, opening each with
`O_NOFOLLOW` on **every** fs op. For a K-component path that is O(K) host
`openat`+`close` per guest op — measured ~291 host opens per guest open on
`test_glob` (see `docs/fs-host-capstd-amplification.md`). It is TOCTOU-tight but
pathologically slow, and it is the shared cause of the whole amplification class
(glob / go-build / apt / inotify).

## The fix is NOT new security — it is the existing primitive, applied wider

`HostFsBackend::fast_open_contained(rel, follow) -> (OwnedFd, stat, kind)`
already provides the same escape-safety in ~1 host `openat`:

1. ONE `openat(root_fd, rel, ...)` — the kernel walks intermediates (symlinks
   ARE followed).
2. `fcntl(fd, F_GETPATH)` — read the real on-disk path of the result.
3. Byte-compare against `root_prefix + "/" + rel`. ANY divergence (an
   intermediate symlink the kernel followed, a Unicode alias, a sandbox escape)
   ⇒ reject and fall through to the exact cap-std slow path.

This is escape-SAFE: an out-of-root result is rejected BEFORE the fd is used, so
no data crosses the boundary. It is already the default for stat/lookup
(`fast_real_stat`, `CARRICK_FAST_FS` default ON). The amplification only
survives where ops still call cap-std `Dir` methods directly. **Demoting cap-std
= routing those remaining ops through `fast_open_contained` (or a new
`open_parent_contained`), keeping cap-std only as (a) the root `Dir` handle and
(b) the exact fallback when F_GETPATH-verify rejects.**

## Conversion pattern

| Guest op | Today (walks) | After |
|---|---|---|
| open a file by path (read/write) | `self.dir.open_with(rel)` | `fast_open_contained(rel, follow)` → use the fd |
| create / write-create | `self.dir.open_with(O_CREAT)` | `open_parent_contained(parent)` → `openat(pfd, leaf, O_CREAT\|O_NOFOLLOW, mode)` |
| mkdir | `self.dir.create_dir(rel)` | `open_parent_contained` → `mkdirat(pfd, leaf, mode)` |
| unlink / rmdir | `self.dir.remove_file/remove_dir` | `open_parent_contained` → `unlinkat(pfd, leaf, flags)` |
| rename | `self.dir.rename(a,b)` | `open_parent_contained(a)`, `open_parent_contained(b)` → `renameat(afd, an, bfd, bn)` |
| symlink | `self.dir.symlink(t, l)` | `open_parent_contained(l)` → `symlinkat(t, pfd, ln)` |
| read_dir | `self.dir.read_dir(rel)` | `fast_open_contained(rel, follow=true, O_DIRECTORY)` → `fdopendir` |
| lookup_kind / resolve_following | `self.at(rel)` + `dir.symlink_metadata` | `fast_open_contained` (already fd-centric) |

**New helper** `open_parent_contained(&self, rel: &Path) -> Option<OwnedFd>`:
`fast_open_contained(parent_of(rel), follow=true, O_DIRECTORY)` — the parent
chain is verified beneath root; the final component is then acted on with a
single `*at` call. The leaf op uses `O_NOFOLLOW` where the guest semantics
require not following a final symlink (open without O_NOFOLLOW to match Linux
final-symlink-following, with a post-open F_GETPATH-verify of the leaf).

## Sites (~30, from `git grep 'self\.dir\.\|self\.at('` in `fs_backend.rs`)

- **stat/lookup** — already fd-centric via `fast_real_stat`. Residual:
  `lookup_kind`, `resolve_following` still `self.at()` + cap-std
  `symlink_metadata`. (Convert in Stage 5.)
- **open-by-path** — the read/write open path.
- **create/write** — `create_file`, `create_file_from_rootfs`, the write path.
- **mutations** — `make_dir`, `remove_entry`, `mark_deleted`, `rename_overlay_entry`,
  `exchange_overlay_entries`, `symlink`, `create_fifo/socket/device`.
- **read_dir** — directory listing + `watch_fds`' child scan.

## Security preservation + the GATE

Every stage MUST keep green, and each is the acceptance test for that stage:
- `crates/carrick-cli/tests/perf_support/xboundary.rs` — the escape-boundary probe.
- the `symlinkmknod` probe-oracle cases (`crates/carrick-cli/tests/probe-oracle/*`).
- the full fs conformance + the 255 conformance/security/atime probes named in
  `docs/fs-host-capstd-amplification.md` (that doc's Phase-1/2 gate).
- `just ci` (clippy no-panic gate — the `F_GETPATH` path must not `unwrap`).

The escape-safety argument to preserve at EVERY site: **no fd derived from a
guest path is used until its real on-disk path is verified beneath
`root_prefix`.** `fast_open_contained` already does this; the parent-fd pattern
extends it (verify the parent chain, then a single-component `*at`).

## Staged, TDD, probe-gated execution

Each stage: (1) RED — a fast probe that walks N× today (e.g. a `glob` /
`open`-loop fixture), assert the host-`openat` count via `carrick trace`; (2)
convert the site(s); (3) GREEN — host-open count drops to O(1)/op; (4) run the
security gate above.

1. **Helpers.** Add `open_contained` (thin over `fast_open_contained`) +
   `open_parent_contained`. No behavior change; unit-test containment reject.
2. **open-by-path** → `open_contained`. Gate. (Biggest single win: `test_glob`
   140s→ target native.)
3. **create/write** → `open_parent_contained` + `openat`. Gate.
4. **mkdir/unlink/rename/symlink/mknod** → `open_parent_contained` + `*at`. Gate.
5. **read_dir + lookup_kind + resolve_following** → fd-centric. Gate.
6. **Demote.** cap-std `Dir` retained only as the root handle + exact fallback;
   delete now-dead per-component walkers. Re-render the support matrix; full
   conformance vs Docker.

## Non-goals / caveats

- Keep cap-std as the **fallback** (F_GETPATH-verify rejects → exact slow path):
  correctness for the symlink/alias edge cases the fast path declines.
- This does NOT change inotify09's remaining floor — that is now the HVF vmexit
  cost (5 syscalls/loop × 3M loops), NOT cap-std. The demotion is the class-fix
  for glob/go-build/apt; inotify09 wants a clock_gettime EL1 fast-path instead.
- Linux/KVM keeps `openat2(RESOLVE_BENEATH)` where available — this is the
  macOS-lane fix.
