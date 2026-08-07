# Exec-close diagnosis: ~1,108 host `close(2)` per guest `execve` — root cause and fix

**Date:** 2026-08-06 (diagnosis and fix), rename-correctness follow-up 2026-08-07
**Scope:** closes the open question named by
[`2026-08-06-build-lane-amplification-ledger.md`](2026-08-06-build-lane-amplification-ledger.md)
§4: 74,253 of guest `execve`'s 85,038 in-window host calls (87.3%) were host
`close` — **7.4% of every host syscall in a cold `go build`**, the largest
single count lever in that ledger, left as a named open question for
Task 5/6. This document is the committed diagnosis record, promoted from the
session's SDD report
(`.superpowers/sdd/2026-08-06-move3-amplification-ledger/task-close-diagnosis-report.md`,
gitignored — `.superpowers/sdd/.gitignore` is `*`) so the fix's only
diagnosis and receipts survive the ledger rather than living only in an
untracked file.
**Lane:** shipped default — Darwin/AArch64 native DSR (`--exec-backend native`).

## 1. Root cause

Each cached leaf in the `--fs host` stat cache opened its **own** host
parent dirfd, so one directory with N cached children pinned N identical
dirfds — a live census showed 1,138 open directory fds over **44 distinct
directories** (759 of them the same `go/src/runtime`, a **25.9x**
duplication). The cache's **clear-on-fork**
(`crates/carrick-runtime/src/fs_backend.rs:2479-2482`, pre-fix line
numbers) then closed all of them one at a time in every fork child,
draining anchors allocated one-per-entry at `fs_backend.rs:2557-2579`.
Because a `go build` fork child's first stat is the `check_exec_target` of
the `execve` it was forked to perform
(`crates/carrick-runtime/src/dispatch/fs/access.rs:290` ←
`crates/carrick-runtime/src/native_darwin.rs:1373`
`load_native_execve_image`), the entire sweep landed inside the guest
`execve` service window — exactly where the amplification ledger's
`dominant by count` column (`close`, 74,253) surfaced it.

`stat_cache_get_or_fill` clears the whole map when `cache_pid != getpid()`
— carrick COW-forks for guest `clone`/`fork`, so the child inherits the
map plus the parent's dup'd fds and must not trust them; that fork
coherence requirement is real and is not weakened by the fix below. The
clear was O(cache **entries**) host closes; it only ever needed to be
O(cache **directories**).

Four bounded, `CARRICK_RUN_ID`-stamped DTrace captures (phase bracket, fd
histogram, per-episode, call-site) independently reproduced the 74,253
figure to the digit, placed every close between the guest `execve`
service-entry and the matching host `execve`, and showed `errno == 0` on
all of them — ruling out a blind `EBADF` sweep. One hypothesis was tested
and refuted: with `CARRICK_FS_TRUSTED_LANE=0` the sweep was unchanged, so
the trusted-dirfd lane (`try_open_trusted_dir`/`try_trusted_dirfd_openat`)
is not the source.

## 2. Per-exec accounting

| work | count | why |
|---|---:|---|
| `stat_cache` anchors dropped by the clear-on-fork | ~1,138 | one `Arc<OwnedFd>` per cached LEAF, 25.9x more than the 44 directories they anchor |
| genuinely paired opens/closes in the exec service | ~40 | loader planning, capsule, path resolution |
| host `execve` | 1 | 1:1 with the guest call |

Classification:
- **Not required by the guest's Linux semantics** — Linux `execve` closes
  the *guest's* CLOEXEC fds, not carrick's private stat-cache anchors.
- **Required by carrick's design in principle, cheaper mechanism
  available** — the clear-on-fork itself is real fork coherence, but its
  cost was proportional to cache *entries* when it only needed to be
  proportional to *directories*.
- **Pure waste** — 1,094 of the 1,138 anchors were redundant host dirfds on
  directories another live cache entry already anchored.

Worth recording separately: the anchors are opened `O_CLOEXEC`, so on the
exec path the kernel would have dropped every one of them for free.
Skipping the sweep entirely on an about-to-exec child is a second,
independent change that trades on knowing the child's future, and it is
deliberately not taken here (see §5).

## 3. The fix (landed)

**Intern the parent dirfd per parent directory, held weakly.**
`crates/carrick-runtime/src/fs_backend.rs` gained a
`parent_fds: Mutex<HashMap<PathBuf, Weak<OwnedFd>>>`. The fill path
upgrades an existing anchor for `rel.parent()` before opening one, and
publishes only a containment-proven fd (`fd_contained_under` still runs on
every fresh open); the clear-on-fork clears the intern map too (documented
lock order `stat_cache` → `parent_fds`, the only site holding both);
bounded like `stat_cache` at 4,096 entries, pruning only already-dead
weaks.

`Weak` is the load-bearing choice: an anchor still dies with the last
`stat_cache` entry that trusts it, so lifetimes are unchanged from the
pre-fix design and only the *duplication* is removed. A strong intern map
would have been a different, less-safe change — it would keep an anchor
alive past its last entry and widen the staleness window the per-hit
revalidation (`fstatat(e.parent_fd, name)`) exists to bound.

**Rename-correctness follow-up.** The first cut unpublished anchors on the
fork clear but not on `rename_overlay_entry` / `exchange_overlay_entries`
— whose whole purpose is that "a cached fd silently follows the inode …
the single case the per-hit revalidation can't detect." A rename racing
the fill path's unlocked publish-then-verify window could hand a
moved-directory's anchor to every later fill under the old path. Both
rename sites now route through `drop_stat_cache_after_rename`, which
clears both maps under the documented lock order, restoring the
pre-intern exposure exactly.

Commits: `dce3266a` (`perf(runtime): intern one host dirfd per stat-cache
directory`), `85ec0f4c` (`fix(runtime): unpublish interned anchors on
rename`).

## 4. Verification receipts

Signed build
`a04e0fc6a20c4052fdf907682c4e9c53f13758e13c95c58bc51336212e939076`
(`just build`), same image/fixture/instrument
(`scripts/dtrace/native-exec-close-attribution.d`) as the pre-fix capture,
`CARRICK_RUN_ID` stamped, zero survivors, no Docker workload in the window.

**Per-exec host closes inside the guest `execve` window** (one capture each
— a count reduction on a deterministic fixture is citable from a single
capture per the plan's rule):

| | execs | total closes | per exec | median | max |
|---|---:|---:|---:|---:|---:|
| before | 67 | 74,253 | 1,108.3 | 1,177 | 1,184 |
| after | 67 | **5,404** | **80.7** | 84 | 90 |

**13.7x fewer**, `errno=0` throughout, identical exec count — removing
**68,849 host syscalls** from the build, 6.8% of the E0 run's 1,007,670
total host calls (essentially all of the 7.4% the ledger attributed to this
lever).

**Independent mechanism check** — live `lsof` census of the long-lived `go`
driver process, untraced:

| | max open fds | DIR fds | distinct dirs | duplication |
|---|---:|---:|---:|---:|
| before | 1,204 | 1,138 | 44 | 25.9x |
| after | **112** | **49** | 48 | **1.02x** |

Other gates: `cargo test -p carrick-runtime --lib
stat_cache_anchors_one_parent_dirfd_per_directory` — red before
(`left: 24, right: 1`), green after; `just conformance-quick` — **OK: no
regressions** (`go-build`, `cpython-subprocess`, `cpython-glob`, `node-*`,
the LTP set — the gate that matters for a change in the `--fs host`
resolution path); `just ci` — exit 0 (43 suites, 0 failures), including the
rename-correctness fix round's red-first receipts (dropping the
`parent_fds` clear from `drop_stat_cache_after_rename`, or leaking a strong
ref at insert, each fails exactly one of the three
`stat_cache_*`/`rename_leaves_*` tests; the restored tree passes all
three).

Wall is **not** claimed: the instrument perturbs 2–4x on this lane; this
entry's currency is counts.

## 5. Not taken here

**Skip the sweep entirely on the exec path.** The anchors are opened
`O_CLOEXEC`, so a plain `execve` would reclaim them for free — but the
clear is demand-driven and the demand *is* the exec path's first stat, so
fork-coherence and "let exec clean up" are entangled, not separable by a
caller hint. Three documented ways a child that stats can still not exec
(`load_native_execve_image` ENOENT/ENOEXEC, `validate_native_reexec_fd_state`
rejection, `begin_guest_exec` failure) each leave the child running live
with an inherited, parent-stamped cache — precisely the fork-coherence
violation the clear exists to prevent. One anchor is also not actually
`O_CLOEXEC` today (the empty-parent branch takes a plain `dup(2)`, which
does not copy `FD_CLOEXEC`), so any version of this follow-on needs that
fixed first. And the remaining prize is small: 80.7 closes/exec is 0.54%
of the run, 12.7x smaller than the 6.8% this fix already banked. A sound
version — a *poisoned*, not eagerly *cleared*, cache on a pid change — is
written down as a design, not built; it converts a one-line clear into a
two-owner state machine and is a separate task.

**`carrick debug`, not `lsof`.** The fd census that cracked this was an
ad-hoc `lsof` poll. Per AGENTS.md's "extend ourselves" rule, an
fd-population census belongs in `carrick debug` beside the other censuses;
not built here.

**The instrument stays a bare `.d` script**, not a `TraceProfileKind`.
`scripts/dtrace/native-exec-close-attribution.d` carries the full
three-part durable-artifact header and is smoke-tested, but per AGENTS.md
a new `.d` should arrive as a `carrick trace --profile` with a Rust parser
and validator; that promotion was out of scope for this diagnosis.
