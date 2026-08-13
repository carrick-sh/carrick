# KN — carrick's own namei, measured; and the correction it forces

**Recorded 2026-08-13.** KN is the phase `hybrid.md` ranks first: carrick
owns path resolution, with a directory cache, instead of delegating it to
cap-std's containment walk. This is its evidence document, and it carries a
correction that matters more than the win.

## Provenance

| Field | Value |
| --- | --- |
| Baseline commit | `53c5e2d1f` |
| Candidate commit | `8d6696a94` |
| Signed binary SHA-256 (candidate) | `423b5c937ea65e03121b3caaae9e2bc1e60319ae8c68345e0c1c0ab4af5b69a5` |
| Signed binary LC_UUID (candidate) | `203B4B7C-E0EE-36E5-9CD5-F257C82C6E00` |
| Host | macOS 27.0 `26A5406e`, Darwin 27.0.0 arm64, Apple M4, 10 logical (4P + 6E) |
| Image | `localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b` |
| Backend | `--exec-backend hvpatch` |
| Fixture | `scripts/perf/native_go_build.py`, 5 samples per arm, cold `GOCACHE` |

**Untraced.** These are `/usr/bin/time`-class figures on the shipped signed
binary — the clean authority this tree uses for retention. Docker was not
running any workload; carrick and Docker were never concurrent. The perf
fixture now records its `exec_backend`, so these arms cannot be confused with
the `native` lane's history.

## Measured

Medians of 5 samples each.

| arm | user | sys | CPU | workload window |
| --- | ---: | ---: | ---: | ---: |
| baseline `53c5e2d1f` | 2.351 | 1.864 | 4.223 | 2,051 ms |
| A1 — directory cache, fast paths only | 2.408 | 1.849 | 4.288 | 2,054 ms |
| **A2 — every path against a cached parent** | 2.436 | **1.627** | **4.094** | **1,946 ms** |
| A2 vs baseline | +3.6% | **−12.7%** | **−3.1%** | **−5.1%** |

Per-sample windows: baseline `[1993, 2051, 2079, 2039, 2122]`, A2
`[1972, 1916, 1954, 1947, 1945]`. **The distributions do not overlap** —
baseline's fastest sample is slower than A2's slowest — so the window result
is not noise.

### Reading the split

The win is entirely in **system** time, −0.237 s of 1.864 s, which is the
signature of issuing fewer host syscalls rather than faster ones. The
**user** side pays +0.085 s for the cache itself: a lock, a hash of the parent
path, and an `Arc` clone on every path operation. Net −0.129 s CPU.

**A1 is the instructive negative.** Building the cache and using it only from
the two fast-path opens changed nothing (+1.5% CPU, +0.1% window): those paths
were already single `openat` calls, so the cache only removed their
`F_GETPATH`. The entire win arrived with A2, when `HostFsBackend::at` began
handing every caller a cached parent and a single leaf component. That is the
same lesson the earlier `open_raw_fd` attempt taught
([ledger](2026-08-13-hvpatch-build-amplification-ledger.md)): five separate
call sites entered one walk, so nothing short of fixing the shared resolver
moves it.

## The correction: host-syscall COUNT is not CPU, and the ledger's ranking overstated this lever

The amplification ledger ranked path resolution first because it is **55.4% of
host syscalls**, with `openat` amplifying 32.78x. `hybrid.md` adopted that
ranking. The arithmetic that ranking implies does not survive contact with the
measurement.

Removing a large share of those syscalls moved **12.7% of system time and 3.1%
of total CPU**. Working backwards: the whole `sys` bucket is 1.864 s against
~360,000 host syscalls, which would be 5.2 µs per syscall — far above what a
macOS syscall costs. So **`sys` is not mostly syscalls.** Under HVF the guest
executes inside `hv_vcpu_run`, which is a kernel call, and page faults and VM
work land in `sys` too. A large fraction of that bucket is therefore guest
execution and fault handling that no amount of syscall elimination touches.

The honest ceiling: even driving every remaining path-resolution syscall to
zero looks worth **single-digit percent** of the build, not a multiple. Against
a bar that requires removing ~1.97 CPU-s of overhead, KN is necessary hygiene
and a real win, but it is **not** the phase that reaches 2.3 CPU-s.

This does not make the work wrong — it is a retained win, it removes a
third-party crate from a hot kernel path, and it fixed a real coherence bug
(below). It makes the *ranking* wrong, and `hybrid.md` is corrected to say so:
**rank by measured CPU, never by syscall count.** A count-based ledger says
where the calls are, not where the time is.

## Correctness, which is the other half of this phase

Containment became **structural rather than audited**. Every cached directory
is reached by opening ONE component at a time with `O_NOFOLLOW | O_DIRECTORY`,
starting at the sandbox root, so no symlink is ever traversed and no
resolution can leave the root — precisely the property cap-std's manual walk
provides, kept and then cached. Two consequences:

- the hot path issues **no `F_GETPATH` at all**; that check exists to audit a
  traversal and there is none to audit;
- a cached entry can never have been reached THROUGH a symlink, so re-pointing
  a symlink cannot make one stale, which is why the invalidation set is only
  rename, exchange and directory removal.

**A shipped coherence bug is closed.** The stat cache's parent anchors were
invalidated by an in-process clear, which cannot see a rename performed by a
SIBLING carrick process — the field documentation admitted this residual
window. Entries now carry the directory generation, which lives in a
`MAP_SHARED` word, so a rename in any process invalidates them in every
process.

**The second generation word is load-bearing.** A dirfd is invalidated only by
an operation that can re-point an existing directory path. Sharing the
existing path-resolution generation would have flushed the cache on every file
creation — thousands per build — and repaid the walk every time.
`dir_cache_survives_a_file_create_and_unlink_storm` pins this.

### Gates

- `carrick-runtime` lib tests: **1,551 passed, 0 failed** (serially, per the
  `just test` recipe).
- Cold `go build` completes on the signed binary, `BUILD_OK`, exit 0, on every
  sample of both arms.
- New unit tests: reuse, the create/unlink storm, rename invalidation, and
  refusal of a symlink that escapes the sandbox.
- New probe `conformance-probes/src/bin/dirrenamecache.rs` asserts the
  guest-visible shape against the Docker oracle, including the sharp
  rename-then-recreate case — a stale dirfd would report the moved directory's
  child under a freshly-created empty directory.
- `fsescapeguard`, the existing security invariant for this fast path, is
  unchanged and remains the regression guard for containment.

## The gate's syscall clause: measured, and NOT met

Taken after this document was first written, once AMP1 was taught to measure
the kernel lane at all
([ledger](2026-08-13-hvpatch-kernel-lane-amp-ledger.md)):

| guest op | pre-KN | post-KN | gate |
| --- | ---: | ---: | ---: |
| `openat` | 32.78 | **17.75** | ≤ 2.0 |
| `newfstatat` | 13.84 | **7.07** | ≤ 2.0 |
| `mkdirat` | 90.96 | **45.18** | ≤ 2.0 |
| overall | 4.71x | **3.28x** | ≤ 2.0x |

**Roughly halved, gate not met.** KN is recorded as a partial: the mechanism is
right, the CPU win is retained, and the remaining factor is real work still to
do. The dominant host call inside every path-op window is still `openat`, so
something is still walking — the leaf, the fallback cases, or a prefix the
cache could not serve.

That ledger also priced the clause honestly: all path operations together cost
384 ms of the 1,014 ms of host-syscall CPU, so meeting the gate exactly is
worth **under 8%** of the build. It confirms the correction above from a second
instrument.

## What is NOT established here
- **No claim about the remaining walk.** How often `at` still falls back —
  a symlinked intermediate, a missing parent, a probe of a non-existent
  directory — is unmeasured. Negative results are deliberately not cached, so
  a repeated probe of a missing directory still re-pays its descent.
- **Nothing about CPython, Node.js or Rust workloads**, which are unmeasured on
  this change. Node remains blocked on hvpatch for an unrelated reason
  ([node blocker](2026-08-13-hvpatch-node-blocker.md)).

## Next architectural question — answered, by the ledger

The question this document closed on was whether `sys` is dominated by host
syscalls or by something else. The AMP1 census answers it: **faults.** 279,987
`as_fault` and 230,298 `zfod` on one build, of which 150,749 land inside
`mmap` service windows at 76.7 zero-fill faults per guest `mmap` — while
`mmap`'s host-syscall amplification is already 1.04x. At this tree's own
measured per-fault cost that is on the order of the entire overhead the goal
must remove.

The next lever is therefore fault reduction on the kernel lane, and the first
step is naming what touches those pages. See
[the ledger](2026-08-13-hvpatch-kernel-lane-amp-ledger.md).
