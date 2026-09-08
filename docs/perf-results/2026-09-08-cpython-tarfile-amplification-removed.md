# cpython-tarfile: the path-resolution amplification, measured before and after

Follow-up to [`2026-09-07-cpython-tarfile-attribution.md`](2026-09-07-cpython-tarfile-attribution.md),
which named the mechanism. This file records the fix's receipts.

## The instrument

`scripts/dtrace/tarfile-host-syscall-breakdown.d` under `carrick trace
--require-script-exit`, on the same reducer both times:

```
carrick trace --require-script-exit -s scripts/dtrace/tarfile-host-syscall-breakdown.d -- \
  run --fs host localhost:5050/cpython-test:3.12.13 \
  /usr/local/bin/python3 -m unittest -v test.test_tarfile.NoneInfoExtractTests_Tar
```

Both runs completed the guest workload inside the script's 120 s bound
(`Ran 7 tests ... OK`), so the counts cover the whole workload, not a window.
The workload is deterministic: **the guest issued the same number of calls on
both binaries** (2699 `unlinkat`, 2401 `mkdirat`, 8714 `newfstatat`), which is
what makes the per-operation ratios comparable rather than merely suggestive.

- BEFORE: `c21978acd` (branch point, pre-WIP), binary `7f671eb862d1f4a5…`,
  host load at start `{9.44 11.83 18.55}`.
- AFTER: `3c3155917`, binary `2ada89bd5bef0d86…`, host load at start
  `{3.61 13.62 20.17}`.

The script **perturbs** (it brackets every host syscall), so the wall times
below are same-instrument figures, not a clean ratio; the *counts* are the
citable result. Other agents were running guests on this host throughout.

## Host syscalls per guest syscall

| guest syscall | guest calls | host `openat`/op BEFORE | AFTER | host `fstatat64`/op BEFORE | AFTER |
|---|---:|---:|---:|---:|---:|
| `unlinkat` (35)   |  2,699 | **212.81** | **6.41** | **162.59** | **6.89** |
| `mkdirat` (34)    |  2,401 | **123.54** | **7.91** | **124.36** | **7.71** |
| `openat` (56)     |  9,499 |      31.75 |     1.44 |      31.06 |     0.48 |
| `newfstatat` (79) |  8,714 |      24.08 |     0.41 |      24.46 |     0.27 |
| `getdents64` (61) | 16,838 |       3.56 |     3.27 |       3.18 |     3.11 |
| `fstat` (80)      | 12,006 |       0.00 |     0.00 |       1.80 |     1.80 |

Total host syscalls issued while servicing guest fs syscalls:
**3,190,240 → 503,294 (6.34x fewer)**. Reducer wall time under the tracer:
114.751 s → 7.788 s.

The BEFORE column independently reproduces the attribution's measurement
(211.6 / 160.3 for `unlinkat`, 125.2 / 125.3 for `mkdirat`) on a different day
and a different reducer scope, which is the strongest available evidence that
both are reading the same mechanism.

## What changed

`remove_entry_checked` answered a directory removal with
`fs_resolve_cache::bump_dir_generation()` + `drop_dir_cache()`. Both
`DirCacheEntry` and `StatCacheEntry` are stamped with that shared generation, so
one `rmdir` invalidated every cached dirfd and every cached leaf stat **in every
process, including the one that did the removal and was about to walk the same
tree again**. `shutil.rmtree` therefore re-walked its whole path from the
sandbox root on essentially every subsequent operation.

The bump is required and is kept — a sibling host process must not keep serving
a dirfd for a path a later `mkdir` re-creates as a different inode, and a dirfd
follows its inode, so identity revalidation cannot see it.
`evict_dir_cache_subtree_restamping` instead drops the removed subtree from both
caches and re-stamps every survivor with the generation this process just
established. `bump_dir_generation` returns that value; re-stamping with it
rather than a fresh `current_dir_generation()` read is what makes it sound,
because a sibling's interleaved bump leaves our survivors at the older value and
correctly invalidates them.

Alongside it, on the `DentryCache` side, a child's upper and lower dirfds are
now opened relative to the parent dentry's fd instead of via
`backend.dir_fd_for(rel_full)` from the deepest cached ancestor, and a name
absent from the lower layer is remembered per parent (`lower_negatives`) so the
upper-vs-lower probe happens once rather than per operation.

## The unit-test invariant

`HostFsBackend::path_walk_host_opens` counts the host `openat` calls spent
walking a path in `dir_fd_for_hops` and its post-reclaim retry — exactly what
`namei_leaf` -> `dir_fd_for(parent)` pays.
`warm_dir_cache_bounds_path_walk_opens_per_guest_op` drives 20 warm
create/remove operations under `pkg/a/b`:

| variant | walk opens for 20 warm ops |
|---|---:|
| `bump_dir_generation()` + `drop_dir_cache()` (pre-fix) | 12 |
| bump, subtree evict, **no** re-stamp | 12 |
| bump, subtree evict, **with** re-stamp (shipped) | **0** |

The middle row is the one that isolates the mechanism: the bump is not the
problem, the remover paying its own alarm is.

## Conformance

`target/debug/carrick-conformance --tier full --workers 1
--carrick-timeout-cap-s 0 --require-cached-oracle`, 19 suites, exit 0,
`OK: no regressions`, `19 cached oracle(s)` / 0 Docker runs:

`cpython-tarfile` MATCH 611/611, `cpython-subprocess` MATCH 297/297,
`ltp-unlink05/07/08/09/10`, `ltp-unlinkat01`, `ltp-mkdir02/03/04/05/09`,
`ltp-mkdirat01/02`, `ltp-rename01`, `ltp-rmdir01/02/03` all MATCH.

`cpython-tarfile` reported 30,304 ms against a 4,765 ms cached oracle
(**6.36x**), versus the attribution's 75,581 ms / 15.86x on the pre-WIP
baseline. **That ratio is NOT citable**: the run started at load
`{13.46 21.10 23.75}` and a sibling agent's conformance gate — including its own
`cpython-tarfile` — ran concurrently. The MATCH verdicts stand; the ratio needs
a quiet-window re-measurement.

## What is not proven

1. **The brief's bar of <=2 host opens per warm guest `unlinkat`/`mkdirat` is
   not met.** The achieved figures are 6.41 and 7.91 host `openat` per
   operation. The <=2 bound holds only for the *path walk* inside
   `dir_fd_for_hops` (0 for 20 warm operations, asserted by the unit test); the
   remaining ~6-8 opens per operation are issued elsewhere in the dispatch path
   and have not been attributed. `getdents64` at 3.27 host `openat` per call is
   now the largest unattributed multiplier in the reducer and was barely moved
   by this work.
2. **Cached negative dentries are no longer revalidated on the `--fs host`
   lane.** The parked work narrowed the `fstatat` revalidation of a
   parent-generation-valid negative dentry to `self.is_shared`, and
   `HostFsBackend::is_shared()` is hardcoded `false`, so it never runs there. A
   file created by a host process *outside* carrick under a directory carrick
   has a negative dentry for will now stay invisible to the guest until the
   parent generation moves. No suite in this run has an external writer, so
   nothing here proves the change safe; it is recorded as a known behaviour
   change, not as verified.
3. **The cross-process dirfd contract is argued, not tested.** There is no test
   in the tree that runs two host processes against one `--fs host` root and
   removes a directory in one while the other holds its dirfd. The re-stamp is
   written to preserve the documented contract, and the argument is in
   `evict_dir_cache_subtree_restamping`'s own doc comment, but a rule that lives
   in a comment is a bug that has not happened yet.
4. **`DirEntry::lower_probed` is set conservatively.** A child whose lower probe
   was attempted and failed while the parent *did* have a lower fd is recorded
   as un-probed, so it is probed again. Correct, but a missed elimination.
