# Attribution: CPython `test_tarfile` Conformance Ratio (~15.9x → 12.9x Residual)

## 1. Overview & Workload Context

- **Workload**: `cpython-tarfile` (`test_tarfile`, 619 tests, 611 passed, 8 skipped)
- **Host load during attribution baseline**: `16.32 15.29 11.95` (and `{18 21 20}` during previous run)
- **Total Suite Execution Time**:
  - Docker Oracle (cached): **4,765 ms** (4.77 s)
  - Carrick (`main` baseline before WIP): **75,581 ms** (~**15.86x**, load `{18 21 20}`)
  - Carrick (WIP commit `b4a8fa2e1`): **61,400 ms** (~**12.88x**, load `{18 21 20}`)
  - Carrick (current session test run): **83,292 ms** (~**17.48x**, load `{20.25 14.48 10.17}`)

The suite runs under `--fs host` where the guest filesystem mutations are mirrored to a host directory tree using Carrick's overlay and dentry caching infrastructure.

---

## 2. Slowest Tests by Name (Carrick Durations)

From `test_tarfile` under `python3 -m unittest -v --durations 30` (host load `16.32 15.29 11.95`):
*(Note: Docker per-test numbers are not recorded — Docker is not run in this lane; the suite-level Docker oracle is cached at 4,765 ms).*

| Rank | Test Name | Carrick Duration | % of Suite Time |
|---|---|---|---|
| 1 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_gname` | 4.481 s | ~3.5% |
| 2 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_mode` | 4.406 s | ~3.4% |
| 3 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_uid` | 4.396 s | ~3.4% |
| 4 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_uid` | 4.313 s | ~3.4% |
| 5 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_mtime` | 4.264 s | ~3.3% |
| 6 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_gname` | 4.260 s | ~3.3% |
| 7 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_gname` | 4.249 s | ~3.3% |
| 8 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_uid` | 4.100 s | ~3.2% |
| 9 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_mtime` | 4.090 s | ~3.2% |
| 10 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_mode` | 4.070 s | ~3.2% |
| 11 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_mtime` | 4.063 s | ~3.2% |
| 12 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_gid` | 3.985 s | ~3.1% |
| 13 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_uname` | 3.948 s | ~3.1% |
| 14 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_gid` | 3.926 s | ~3.1% |
| 15 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_ownership` | 3.903 s | ~3.0% |
| 16 | `test.test_tarfile.NoneInfoExtractTests_Tar.test_extractall_none_ownership` | 3.899 s | ~3.0% |
| 17 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_ownership` | 3.887 s | ~3.0% |
| 18 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_mode` | 3.867 s | ~3.0% |
| 19 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_gid` | 3.846 s | ~3.0% |
| 20 | `test.test_tarfile.NoneInfoExtractTests_FullyTrusted.test_extractall_none_uname` | 3.504 s | ~2.7% |
| 21 | `test.test_tarfile.NoneInfoExtractTests_Default.test_extractall_none_uname` | 3.385 s | ~2.6% |
| 22 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_gid` | 3.329 s | ~2.6% |
| 23 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_mtime` | 3.264 s | ~2.5% |
| 24 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_gname` | 3.178 s | ~2.5% |
| 25 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_mode` | 3.126 s | ~2.4% |
| 26 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_uname` | 2.968 s | ~2.3% |
| 27 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_uid` | 2.826 s | ~2.2% |
| 28 | `test.test_tarfile.NoneInfoExtractTests_Data.test_extractall_none_ownership` | 2.771 s | ~2.2% |
| 29 | `test.test_tarfile.TestExtractionFilters.test_realpath_limit_attack` | 0.634 s | ~0.5% |
| 30 | `test.test_tarfile.CommandLineTest.test_test_command_verbose` | 0.531 s | ~0.4% |

**Key Finding**: The 28 `NoneInfoExtractTests_*` test methods account for **~105.7 s out of 128.5 s** total test wall time (**>82%** of the entire suite). Each test extracts the full 39-member test archive into a temporary directory (`extractall`) and tears it down with `shutil.rmtree` upon exit.

---

## 3. Host-Syscall Breakdown per Guest Operation

Measured via `scripts/dtrace/tarfile-syscall-latency.d` and `scripts/dtrace/tarfile-host-syscall-breakdown.d` across a single `NoneInfoExtractTests` test class (39 members extracted × 8 cycles = 312 extractions + 7 `rmtree` deletions; host load `16.32 15.29 11.95`):

| Guest Syscall (Linux ABI) | Guest Calls | Total Wall ns | Avg ns / Guest Op | Dominant Host Syscalls | Host Calls per Guest Op |
|---|---|---|---|---|---|
| `unlinkat` (nr 35) | 336 | 1,365,573,449 ns | 4,064,207 ns (4.06 ms) | `openat` (71,103), `fstatat64` (53,866), `close` (18,409), `unlinkat` (636) | **~211.6 host openat**, **~160.3 host fstatat** |
| `mkdirat` (nr 34) | 300 | 680,324,157 ns | 2,267,747 ns (2.27 ms) | `openat` (37,563), `fstatat64` (37,591), `close` (1,192), `mkdirat` (300) | **~125.2 host openat**, **~125.3 host fstatat** |
| `openat` (nr 56) | 1,134 | 602,562,565 ns | 531,360 ns (531 µs) | `openat` (1,248), `fstat64` (1,134), `fcntl` (1,134) | ~1.10 host openat |
| `newfstatat` (nr 79) | 1,004 | 297,784,495 ns | 296,598 ns (296 µs) | `fstatat64` (1,004), `openat` (18) | ~1.00 host fstatat |
| `getdents64` (nr 61) | 1,816 | 194,220,998 ns | 106,950 ns (107 µs) | `getdirentries64` (1,816), `fstat64` (1,816) | ~1.00 host getdirentries64 |
| `fstat` (nr 80) | 1,473 | 21,631,684 ns | 14,685 ns (14.7 µs) | `fstat64` (1,473) | 1.00 host fstat64 |
| `close` (nr 57) | 1,418 | 8,171,214 ns | 5,762 ns (5.8 µs) | `close` (1,418) | 1.00 host close |
| `write` (nr 64) | 99 | 3,786,914 ns | 38,252 ns (38.3 µs) | `write` (99) | 1.00 host write |
| `read` (nr 63) | 362 | 3,711,372 ns | 10,252 ns (10.3 µs) | `read` (362) | 1.00 host read |
| `mmap` (nr 222) | 66 | 3,555,671 ns | 53,874 ns (53.9 µs) | In-process VM allocation | 0 host syscalls (VMM memory manager) |
| `munmap` (nr 215) | 39 | 1,815,662 ns | 46,555 ns (46.6 µs) | In-process VM deallocation | 0 host syscalls (VMM memory manager) |

---

## 4. The Named Mechanism Explaining the Residual (12.9x)

**Mechanism Name**:
`Path resolution amplification via redundant ancestor re-walks and cross-layer directory descriptor misses in dentry/namei`

**The Number**:
- **~211 host `openat` calls + ~160 host `fstatat64` calls per single guest `unlinkat`**
- **~125 host `openat` calls + ~125 host `fstatat64` calls per single guest `mkdirat`**
- In total, **>108,000 host `openat` and >91,000 host `fstatat64` calls** are performed across 336 `unlinkat` and 300 `mkdirat` operations in a single 39-file extraction test class.

### Why this happens:
1. **Redundant full-path re-walk via `backend.dir_fd_for(rel_full)` instead of `parent_fd` relative open**:
   In `crates/carrick-runtime/src/vfs/dentry.rs`:
   - During `construct_positive_from_stat` (line 1284, 1287), `populate_child_from_backend` (lines 1522, 1599), and lower-rootfs directory insertion (line 1727), child upper directory descriptors are populated by calling `backend.dir_fd_for(Path::new(rel_full))`.
   - Even though the parent directory's file descriptor (`parent_fd`) is already open and held in memory, `dir_fd_for(rel_full)` re-walks the entire path starting from the deepest cached ancestor in `dir_cache`, executing `libc::openat(current, component, O_DIRECTORY | O_NOFOLLOW)` for every intermediate component.

2. **Cross-layer descriptor misses on lower rootfs paths**:
   - In `dentry.rs` line 1287: when looking up an entry in the lower rootfs (`is_lower == true`), Carrick calls `backend.dir_fd_for(Path::new(rel_full))` on the **upper** overlay backend.
   - Because the lower-layer path does not exist in the upper overlay, every component walk in `dir_fd_for` fails with `ENOENT`. On each negative openat return (`raw < 0`), `dir_fd_for` follows up with a `libc::fstatat(..., AT_SYMLINK_NOFOLLOW)` to verify if the failing component was a symlink (line 2961).
   - This creates a paired `openat` + `fstatat` storm returning `ENOENT` for every component on every lookup of lower rootfs directories (e.g. `/usr`, `/lib`, `/usr/local/lib/python3.12/...`).

3. **Repeated lower-layer probing in `construct_positive_from_stat`**:
   - When extracting files under `/tmp/extractall_none/...`:
   - The root `/tmp` directory exists in the lower image and has a `lower_dir_fd`.
   - Every file and directory created in the temporary extraction directory repeatedly probes `parent_lower_fd` with `openat(pfd, name_c, O_DIRECTORY)` to see if an overlay lower counterpart exists.
   - For newly extracted directories under `/tmp` that are purely upper-overlay entries, this generates hundreds of failing host `openat` calls against the lower `/tmp` directory descriptor.

4. **Directory cache invalidation and re-walk amplification**:
   - Every `unlinkat` and `mkdirat` calls `namei_leaf(rel)` in `HostFsBackend`.
   - `namei_leaf` calls `self.dir_fd_for(parent)`.
   - When directories are created or removed during `tarfile.extractall` and `shutil.rmtree`, cached directory entries are invalidated or not yet populated, triggering full component re-walks.

Eliminating these redundant path walks and cross-layer probes directly addresses the dominant source of latency in `test_tarfile`, unlocking the path from 12.9x down towards the target landing bar.
