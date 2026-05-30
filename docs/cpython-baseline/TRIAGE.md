# CPython 3.12.13 regression-suite parity: carrick vs Docker linux/arm64

Workload: CPython's own `Lib/test` regression suite (the goal's forcing function),
run under `python3 -m test -v --randseed 0 <module>` on `python:3.12` (Debian
trixie, glibc 2.41) under **carrick** and **Docker linux/arm64** (the oracle),
diffed per test-id. Harness: `scripts/cpython-parity.py`. The CPython test suite
is stripped from the official python images, so the matching `Lib/test` is
mounted on PYTHONPATH (see harness header). Data: `baseline.jsonl`.

Baseline date: 2026-05-30. First baseline AFTER the CTR_EL0 fix (commit afd6ca2)
that unblocked glibc-2.41 startup. ~40 representative modules across the goal's
areas (fork/exec, threads, signals, fs+locking, sockets, select/poll/epoll, mmap,
subprocess, os/io) + pure-compute sanity modules.

## Per-module verdicts

| module | verdict | docker n/result · carrick n/result | ndiff |
|---|---|---|---|
| `test_math` | MATCH | d=78/SUCCESS c=78/SUCCESS | 0 |
| `test_array` | MATCH | d=814/SUCCESS c=814/SUCCESS | 0 |
| `test_collections` | MATCH | d=97/SUCCESS c=97/SUCCESS | 0 |
| `test_decimal` | MATCH | d=647/SUCCESS c=647/SUCCESS | 0 |
| `test_grp` | MATCH | d=4/SUCCESS c=4/SUCCESS | 0 |
| `test_pwd` | MATCH | d=3/SUCCESS c=3/SUCCESS | 0 |
| `test_errno` | MATCH | d=3/SUCCESS c=3/SUCCESS | 0 |
| `test_contextlib` | MATCH | d=90/SUCCESS c=90/SUCCESS | 0 |
| `test_binascii` | MATCH | d=69/SUCCESS c=69/SUCCESS | 0 |
| `test_random` | MATCH | d=101/SUCCESS c=101/SUCCESS | 0 |
| `test_heapq` | MATCH | d=50/SUCCESS c=50/SUCCESS | 0 |
| `test_fileio` | MATCH | d=93/SUCCESS c=93/SUCCESS | 0 |
| `test_selectors` | MATCH | d=121/SUCCESS c=121/SUCCESS | 0 |
| `test_fork1` | MATCH | d=2/SUCCESS c=2/SUCCESS | 0 |
| `test_wait4` | MATCH | d=2/SUCCESS c=2/SUCCESS | 0 |
| `test_memoryview` | MATCH | d=144/SUCCESS c=144/SUCCESS | 0 |
| `test_subprocess` | DIFF | d=320/SUCCESS c=1/FAILURE | 321 |
| `test_json` | DIFF | d=174/SUCCESS c=107/None | 68 |
| `test_posix` | DIFF | d=166/SUCCESS c=166/FAILURE | 45 |
| `test_mmap` | DIFF | d=41/SUCCESS c=1/None | 41 |
| `test_tempfile` | DIFF | d=115/SUCCESS c=115/FAILURE | 32 |
| `test_signal` | DIFF | d=53/FAILURE c=37/None | 32 |
| `test_io` | DIFF | d=642/SUCCESS c=630/None | 26 |
| `test_glob` | DIFF | d=18/SUCCESS c=18/FAILURE | 15 |
| `test_hashlib` | DIFF | d=78/SUCCESS c=71/None | 8 |
| `test_posixpath` | DIFF | d=87/SUCCESS c=87/FAILURE | 5 |
| `test_base64` | DIFF | d=35/SUCCESS c=35/FAILURE | 5 |
| `test_fcntl` | DIFF | d=11/SUCCESS c=11/FAILURE | 4 |
| `test_stat` | DIFF | d=16/SUCCESS c=16/FAILURE | 2 |
| `test_struct` | DIFF | d=38/SUCCESS c=38/FAILURE | 1 |
| `test_itertools` | DIFF | d=140/SUCCESS c=140/FAILURE | 1 |
| `test_time` | DIFF | d=62/SUCCESS c=62/FAILURE | 1 |
| `test_select` | DIFF | d=6/SUCCESS c=6/FAILURE | 1 |
| `test_thread` | DIFF | d=24/SUCCESS c=24/FAILURE | 1 |
| `test_resource` | DIFF | d=11/SUCCESS c=11/FAILURE | 1 |
| `test_pty` | DIFF | d=4/SUCCESS c=4/FAILURE | 1 |
| `test_wait3` | DIFF | d=3/SUCCESS c=3/FAILURE | 1 |
| `test_socket` | CARRICK_TIMEOUT | d=732/SUCCESS c=404/None | 438 |
| `test_os` | CARRICK_TIMEOUT | d=337/FAILURE c=305/None | 97 |
| `test_threading` | DOCKER_TIMEOUT | d=141/None c=199/FAILURE | 75 |
| `test_pipe` | BOTH_EMPTY | d=0/FAILURE c=0/FAILURE | 0 |

## Excluded (not real carrick gaps)
- `test_threading` — **DOCKER_TIMEOUT**: the oracle itself hung at 200s (LinuxKit
  VM). Not comparable; re-run with a longer oracle timeout or smaller slices.
- `test_pipe` — not a 3.12 module name (both sides "no tests"); harness artifact.

## Root-caused clusters (ranked by leverage)

### 1. Fork→execve **EINVAL** in forked children (THE dominant cluster)
A child created by `fork`/`vfork` (CPython `subprocess`/`_posixsubprocess`)
intermittently gets **errno 22 (EINVAL) from `execve`**. Trace (test_subprocess
setUpModule): parent clones two children for the SAME target — child A execve's
ret=0, child B execve's ret=-22. Single-threaded at that point (setUpModule), so
it is NOT multithreading per se; it is a race/state bug in carrick's
fork→execve path. `load_execve_image` only ever returns ENOENT, so the EINVAL
originates elsewhere in the fork/execve machinery — under investigation.
Reliable repro: `python -m test test_subprocess` (fails in setUpModule:
`subprocess.run(['/usr/bin/true'])` → `OSError [Errno 22]: '/usr/bin/true'`).
Standalone `subprocess.run([...])` works; only fails under the regrtest context.
- Modules: **test_subprocess** (crashes after setUpModule → 321 diffs),
  **test_base64** TestMain (5), **test_struct** (1), **test_itertools** (1),
  **test_posixpath** test_import (1), and the lockf children in **test_fcntl**.
- Leverage: enormous — `script_helper`/`subprocess` underpins a large fraction
  of the whole suite. **Top priority.**

### 2. Multithreaded thread-start / fork hang
With a background thread present (e.g. regrtest's faulthandler timeout thread),
`Thread.start()` can hang in `_started.wait()` (a newly cloned thread never
schedules), and subprocess spawns can deadlock. Aligns with the known carrick
multithreaded-fork issues (Go os/exec). Likely related to cluster 1.
- Modules: **test_os** (CARRICK_TIMEOUT/hang), **test_io** (crash partway),
  **test_hashlib** (crash partway), **test_json** (crash on deep recursion path).

### 3. lstat/fstat inode-identity → shutil.rmtree refuses
`shutil.rmtree(dir)` raises "Cannot call rmtree on a symbolic link" because
`samestat(os.lstat(path), os.fstat(os.open(path)))` is FALSE for a regular dir —
i.e. lstat(path) and fstat(fd) disagree on st_ino/st_dev. The failed tearDown
leaves the tempdir, so every later setUp hits `FileExistsError` (EEXIST). Plain
lstat/islink on a simple dir is CORRECT (reduced), so it's the path-vs-fd
identity that diverges.
- Modules: **test_glob** (15, all from this cascade), **test_posixpath**
  (islink/realpath), parts of **test_tempfile**, **test_stat**.

### 4. fcntl gaps
`F_SETPIPE_SZ`/`F_GETPIPE_SZ` (F_SETPIPE_SZ → EINVAL; needs per-pipe size
tracking) and `F_NOTIFY`+`DN_MULTISHOT` (aarch64 Linux accepts; carrick EINVALs;
dnotify has no macOS equivalent — accept-as-noop is the conformance option).
- Module: **test_fcntl** (pipesize + 64-bit).

### 5. Misc single-test diffs (per-module, lower leverage)
test_time, test_resource, test_pty, test_thread, test_wait3, test_select — 1 each;
triage individually.

## Reducers (durable gates)
- `conformance-probes/src/bin/ctrel0.rs` — EL0 CTR_EL0/DCZID/cache-ops (landed).
- TODO: `forkexecveloop` (cluster 1), `statfdidentity` (cluster 3),
  `fcntlpipesize` (cluster 4).
