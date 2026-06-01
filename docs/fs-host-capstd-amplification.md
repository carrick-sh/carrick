# `--fs host` open amplification: cap-std re-resolution (~291× host opens/guest open)

**Status:** Phases 1+2 IMPLEMENTED + verified (2026-06-01). Phase 1 (path-based getxattr)
is unconditional; Phase 2 (`fast_lstat_contained` openat+F_GETPATH) is **opt-in
`CARRICK_FAST_FS=1`, default OFF** — it aggravates the multithreaded-fork HVF wedge
(see the "UPDATE" section at the bottom — that is the authoritative current state; the
"default on" mentions in the mid-sections below are superseded). With `CARRICK_FAST_FS=1`:
test_glob TIMEOUT→MATCH (140s→48s; host opens 999,646→405,926). Non-creating stat/lookup
only; writes/creates stay on cap-std.

## The pathology (empirical, via `carrick trace`)

Workload: `glob.glob('/usr/local/lib/python3.12/**', recursive=True)` (3,255 files) on `--fs host`.

| metric | value |
|---|---|
| guest `openat` (Linux nr 56) | 3,335 |
| **host `open()` carrick issued** | **999,646** (971,841 while servicing a guest openat) |
| host `close()` | 999,612 |
| host stat | 135,094 ; host xattr | 74,643 |
| **amplification** | **~291 host opens per single guest open** |
| `openat` wall-time | **8.37 s = ~98%** of all syscall time; ~2 ms/guest-open |

`test_glob` completes in **140 s** (SUCCESS — the *result* matches Docker; it just blows the 90 s
sweep timeout). Docker runs it in seconds. The entire gap is this amplification.

Trace scripts: `scripts/glob-syscall-profile.d` (per-syscall wall-time), `scripts/glob-openat-drill.d`
(host-open attribution by in-flight guest syscall + ustack).

## Mechanism (why 291×) — verified against cap-primitives-4.0.2 source

1. **cap-std on macOS has no `openat2`/`RESOLVE_BENEATH`**, so it uses the "manually" resolver
   (`cap-primitives-4.0.2/src/fs/manually/open.rs`): a component-by-component walk, opening each
   path component with `openat(O_NOFOLLOW)` (+ a stat on ENOTDIR). LINEAR in depth (K opens for K
   components), keeps a dir-fd stack — NOT quadratic. So one cap-std op on a K-deep path ≈ K host opens.
2. **carrick issues 5–6 cap-std full re-walks per guest open** (`crates/carrick-runtime/src/fs_backend.rs`):
   - `lookup` → `symlink_metadata(rel)` (fs_backend.rs:1377)
   - `metadata` → `symlink_metadata(rel)` again (fs_backend.rs:1377) — **REDUNDANT, same path**
   - `resolve_following` → `symlink_metadata(rel)` (fs_backend.rs:887)
   - `read_mode_xattr` → `with_entry_fd` → cap-std `open_with(O_EVTONLY)` (fs_backend.rs:1127→1115)
   - `read_socket_xattr` → `with_entry_fd` → another cap-std open (fs_backend.rs:1144→1115)
   - `open_raw_fd` → cap-std `open_with` RW, then RO on failure (fs_backend.rs:1751–1752) — 2 attempts
   Each is a fresh component-by-component walk. ~6 walks × (deep python paths) × retries ≈ 291.
   Reconciliation: 999,646 / (6 walks × 3,335) ≈ **45 host opens per cap-std walk** (deep paths + retries).

## The unlock — carrick already does its own containment

`fs_backend.rs::normalize`/`normalize_raw` (lines 361–396) reject `Component::Prefix`, strip leading
`/`, and reject `..` that escapes root. `real_stat` (2269–2294) MANUALLY resolves symlinks with a
40-hop ELOOP guard and re-normalizes absolute targets relative to the guest root. Every backend
method calls `normalize(path)?` first. So **cap-std's per-component re-walk is belt-and-suspenders** —
the relative path handed to cap-std is already `..`/absolute-safe by construction.

**Threat model:** the guest is UNTRUSTED Linux code; carrick runs as the invoking user's uid; the
rootfs scratch dir is the SOLE protection. A rootfs escape = read/write the user's home, SSH keys,
etc. So whatever replaces cap-std MUST still prevent escape.

## macOS-native fast resolve (no openat2/RESOLVE_BENEATH)

Chosen: **`openat(root_fd, rel, flags)` + `fcntl(fd, F_GETPATH)` containment check** (~2 host syscalls
vs ~291). The kernel resolves the whole multi-component path in ONE openat; F_GETPATH returns the
opened inode's real absolute path; verify it is under the cached `root_prefix`, else close+reject.
This catches escapes the kernel's resolution would otherwise allow, and is immune to a carrick
normalize() bug.

## CRITICAL security finding (adversarial review) — scope the fast path to NON-CREATING opens

A naive `openat(root_fd, "link/file", O_CREAT|O_NOFOLLOW)` where an INTERMEDIATE component `link` is a
symlink to outside the root **creates the file OUTSIDE the sandbox** — `O_NOFOLLOW` only guards the
FINAL component; the kernel traverses intermediate symlinks. F_GETPATH then detects it, but for
`O_CREAT` the damage (a file created outside) is already done before the check (PROVEN empirically by
the reviewer: `openat(root,'link_to_outside/file.txt',O_CREAT|O_NOFOLLOW)` → F_GETPATH =
`/tmp/sandbox_outside/file.txt`). cap-std is safe because its per-component walk rejects the
intermediate symlink.

**Therefore:** the fast path is SAFE only for **non-creating reads / opendirs** (O_RDONLY,
O_DIRECTORY, no O_CREAT/O_WRONLY): F_GETPATH catches the escape BEFORE any byte is read and nothing is
created; on containment-fail, close the fd and fall back to cap-std. **Writes/creates keep the cap-std
path.** This still captures the entire glob win (the 3,335 guest opens are opendirs).

## Phased implementation plan (feature-gated `CARRICK_FAST_FS`, default OFF until proven)

- **Phase 1 — fast non-creating open.** Add `root_fd` (dup of the cap-std Dir fd) + cached
  `root_prefix` (F_GETPATH at construction) to `HostFsBackend` (fs_backend.rs:730/782). In the
  read/opendir open path, when NOT creating and the flag is on: `openat(root_fd, rel, flags)` +
  F_GETPATH containment; any failure → fall back to cap-std. Writes/creates unchanged.
- **Phase 2 — collapse the xattr peeks.** Replace the 3 `with_entry_fd` opens (read_mode/socket/owner
  xattr) with PATH-BASED `getxattr(abs, name, …)` (no open; `sandbox_abs_path` + the existing
  `symlink_get_u32_xattr` pattern already do this for symlinks). getxattr does not bump atime, so the
  O_EVTONLY atime-preservation property is preserved — but VALIDATE empirically (mailbox.Maildir.clean
  / a utime+stat probe) before landing.
- **Phase 3 — dedupe** the redundant `symlink_metadata` (lookup + metadata stat the same path).
- **Phase 4 — Unicode guard.** Add `name_matches_on_disk` to the open path (cap-std did this
  implicitly via the per-component walk; the fast path must do it explicitly to keep NFC/NFD ENOENT
  parity with Linux).

## Verification gate (red-first; do NOT skip)

1. **Escape probe (security):** a guest creates `link → /tmp/outside`, then `open("link/x", O_RDONLY)`
   and `open("link/x", O_CREAT)` — BOTH must fail (ENOENT/EACCES), file must NOT appear outside. Must
   pass with the flag ON and OFF.
2. **Perf probe:** `carrick trace` host-open/guest-open ratio drops from ~291 to ~1–2 (the
   `glob-openat-drill.d` attribution).
3. **No regression:** all `conformance-probes` fs probes MATCH; CPython `test_glob` (target: <90 s →
   MATCH), `test_stat`, `test_posix`, `test_os`, `test_subprocess` parity unchanged; the atime probe
   for Phase 2.
4. test_glob is the success metric: timeout → MATCH.

## IMPLEMENTED (2026-06-01) — Phases 1+2 landed, test_glob TIMEOUT→MATCH

- **Phase 1** (commit c086d77): path-based `getxattr` for the mode/socket/owner
  xattr peeks (`path_get_u32_xattr`), eliminating the `with_entry_fd` opens.
  999,646 → 622,909 host opens; test_glob 140s → 103s. No atime regression
  (getxattr is metadata, like O_EVTONLY).
- **Phase 2** (commit 43c396d): `fast_lstat_contained` — one `fstatat` +
  `openat`+`F_GETPATH` containment — wired into `lookup`/`metadata`/`real_stat`
  (the calls `open_dispatch` makes ~3× per guest open). 622,909 → **405,926**
  host opens; **test_glob 140s → 48s → MATCH** (under the 90s sweep timeout).
  Reads/opendirs only; writes/creates stay on cap-std (the O_CREAT escape).
  Feature-gated `CARRICK_FAST_FS` (default on). Falls back to cap-std for
  symlink leaves / FIFOs / escapes / errors.

Verified no regression: 251 lib tests; test_stat/io/fileio/tempfile/glob MATCH;
test_posix unchanged (1 unrelated feature-skip); test_subprocess DIFF=2
(unchanged, benign) and faster (75s→56s); 9 fs probes MATCH; fsescapeguard
(security) MATCH with the flag on.

Remaining (lower priority): the `read_dir`/`layered_directory_entries` walk and
`open_raw_fd` (file opens) still use cap-std; the remaining ~405k opens are
mostly there. Not needed for test_glob (now MATCH); a future increment for
file-read-heavy workloads. The xattr peeks during directory listing already use
the Phase-1 fast getxattr.

## UPDATE (2026-06-01) — default flipped to OFF (fork-wedge aggravation)

The full 41-module sweep flagged test_fork1 → CARRICK_TIMEOUT. Isolation
(commit 2a3e43a):
- fast-fs ON: test_fork1.test_threaded_import_lock_fork hangs ~2/3 of runs.
- fast-fs OFF (cap-std): hangs ~1/4 — i.e. the multithreaded-fork-from-nested HVF
  wedge (the campaign's #1 Heisenbug, see project_cpython_conformance_campaign)
  is INTERMITTENT IN THE BASELINE; fast-fs's extra openat/close-per-stat churn
  just perturbs syscall timing in the fork window and roughly doubles the rate.

Decision: `fast_lstat_contained` (Phase 2) is now **default OFF**, opt-in
`CARRICK_FAST_FS=1`. When off it returns immediately → cap-std path, byte-identical
to pre-Phase-2. **Phase 1 (path-based getxattr) stays unconditional** — it REMOVES
opens (less churn), so it can only reduce wedge probability, and kept every fs
parity/probe green.

Net: default is fork-safe (baseline) but test_glob is TIMEOUT again by default;
`CARRICK_FAST_FS=1` gets test_glob 140s→48s MATCH for fork-light fs-heavy
workloads. The fast path is also a **near-deterministic reproducer of the #1
fork-wedge** — the highest-value next step is to fix that HVF wedge (which would
let fast-fs go default-on AND unblock the broader multithreaded-fork conformance),
using this as the repro.

## UPDATE 2 (2026-06-01) — fork-wedge FIXED, fast-fs back to default ON

The fast path was a near-deterministic reproducer for the #1 fork-wedge, and that
cracked it. Root cause (commit cf5f6e0, runtime.rs fork-quiesce loop): the forking
thread captured `others = kicker.count()-1` ONCE; vCPUs that EXIT mid-quiesce drop
the kicker count, so `others` went stale-HIGH and `while !wait_quiesced(others)`
spun forever (gated diag: `others=4 paused=2 kicker=3`). Fix = recompute `others`
live each iteration; the post-loop `VCPU_LIVE>1` 5s-abort still gates the real
teardown (no HV_BUSY risk).

With the wedge fixed, **fast-fs is back to default ON**. Verified: test_fork1
14/14 no-hang (8 fast-on + 6 baseline), test_glob MATCH by default (48s),
fsescapeguard MATCH, 251 lib tests. The remaining read_dir/open_raw_fd cap-std
walk is still a future increment (not needed for test_glob).
