# CPython parity — remaining clusters + carrick-runner improvements

Empirical wave-2 triage (2026-06-01, clean-room: Docker oracle + man pages). Current: ~33/41 tracked modules MATCH (was 16). Remaining gaps + the runner/hermeticity improvements the audit surfaced.


## test_socket (188 ndiff split: 224 UDPLITE + 32 IPv6 cmsg)
- **failures:** 224 errors (UDPLITE protocol not supported on macOS) + 32 failures (IPv6 ancillary data dropped)
- **root_cause:** Two systemic issues: (1) macOS socket() call for IPPROTO_UDPLITE returns EPROTONOSUPPORT; carrick passes the protocol number through unchanged. (2) recvmsg_inner translates ONLY SCM_RIGHTS cmsg from host to guest; all other cmsg types (IPv6 ancillary data) are silently dropped from the host msg_controllen buffer.
- **systemic:** True
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/net.rs` ~490: In host_socket_install, after the host socket() call fails with EPROTONOSUPPORT for unsupported protocols (e.g., IPPROTO_UDPLITE), synthesize a socket by backing it with an alternative protocol (e.g., IPPROTO_UDP for UDPLITE) and add a flag/marker to the OpenDescription to emulate the missing protocol's behavior, or reject unsupported protocols with a clear error message. Since UDPLITE is rarely used, returning ENOPROTOOPT/EPROTONOSUPPORT is acceptable and matches macOS native behavior.
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/net.rs` ~3399-3401: In recvmsg_inner, after parsing SCM_RIGHTS fds from the host control buffer, also translate and preserve OTHER cmsg types (IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS, IP_RECVTOS, etc.) from host to Linux layout and write them to the guest's msg.control buffer. The host message may contain multiple cmsg headers; enumerate all of them and rebuild a guest-layout control buffer with ALL translated cmsg types, not just SCM_RIGHTS.
- **runner_improvement:** Update test_socket test harness to skip UDPLITE tests on carrick (or accept EPROTONOSUPPORT as expected), since macOS doesn't support UDPLITE natively. For IPv6 cmsg, the harness is already correct; just the carrick handler needs to forward those messages.
- **risk:** The IPv6 cmsg fix is moderate risk: it requires parsing and rebuilding the cmsg buffer from host to guest layout, with proper alignment and truncation handling (MSG_CTRUNC flag). The UDPLITE protocol gap is low risk (it's rarely used; returning the host error is acceptable).

## test_posix ndiff=5: test_chmod_dir_symlink, test_fexecve, test_lchown, test_setpgroup (both Spawn/SpawnP variants)
- **failures:** test_chmod_dir_symlink: chmod(symlink, mode) doesn't follow symlink to change target's mode. Expected: stat(target).st_mode == new_mode, Actual: unchanged. Root cause: chmod_at() calls resolve_at_path() which intentionally doesn't follow final component; needs explicit symlink follow for fchmodat (no AT_SYMLINK_NOFOLLOW) vs fchmodat2 (respects flag).

test_fexecve: execve(fd, argv, env) with fd as first arg returns ENOSYS. Expected: child exec succeeds, Actual: Errno 38 (ENOSYS). Root cause: execve handler at src/dispatch/proc.rs:1591 expects pathname string, not fd; needs detection of fd vs path and separate handling path.

test_lchown: lchown(symlink, uid, gid) loses the uid/gid value (wraps to 0). Expected: lstat(symlink).st_uid == 2147483648 after lchown(..., 2147483648, ...), Actual: 0. Root cause: with_entry_fd() at src/fs_backend.rs:1083 cannot open symlink without O_NOFOLLOW flag; open() follows symlink, fails on dangling target, fsetxattr never runs. Secondary: large uid cast from u64→u32 is correct but xattr write fails.

test_setpgroup (x2): posix_spawn with setpgroup=os.getpgrp() causes child exit code 127. Expected: child execs successfully, Actual: 127 (command not found). Root cause: setpgroup parameter is parsed but not applied to execve arguments or process group management; child likely can't find executable or PATH resolution fails post-fork.
- **root_cause:** Four distinct systemic issues: (1) symlink-following for chmod/chown ops not controlled by flags (2) execve FD mode unsupported (3) xattr writes on symlinks fail due to open() not accepting O_NOFOLLOW (4) posix_spawn setpgroup not properly integrated into fork/exec path.
- **systemic:** True
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/fs.rs` ~1642: Modify chmod_at() to accept follow_symlinks parameter. After resolve_at_path(), if follow_symlinks=true, use resolve_following() or equivalent to dereference symlink before calling set_mode(). fchmodat (line 5853) passes follow_symlinks=true, fchmodat2 (line 5865) passes follow_symlinks=(flags & AT_SYMLINK_NOFOLLOW == 0).
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/proc.rs` ~1591: Modify execve() to detect if pathname_addr is a file descriptor. Check if path starts with '/' or contains '.' (heuristic) vs testing if it's a valid fd number via this.fd_is_valid(). If fd, read /proc/self/fd/<fd> or use fd table to resolve target path, then execve. Return ENOSYS only if fd mode is truly unsupported.
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/fs_backend.rs` ~1083: Modify with_entry_fd() to accept follow_symlinks parameter and pass O_NOFOLLOW to OpenOptions when follow_symlinks=false. Update write_owner_xattr() at line 1167 to pass nofollow flag (callers at fs.rs:5822 already have nofollow flag computed). For symlinks with AT_SYMLINK_NOFOLLOW, use O_NOFOLLOW so open succeeds on symlink itself.
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/proc.rs` ~1613: In clone() handler, check for CLONE_NEWPID/CLONE_NEWPGRP equivalents or detect posix_spawn context. Extract setpgroup from spawn_attrs if present and apply via setpgid() or setsid() after fork before exec. Ensure child process group is set per spawn_attrs.setpgroup before execve().
- **runner_improvement:** Carrick test harness should validate xattr writes succeed for symlinks via a dedicated probe; test mode/owner isolation (follow vs nofollow). Add fixture for large uid/gid (2^31+) to catch truncation bugs. Exec-with-fd detection should check fd.is_valid() + /proc/self/fd lookup, not heuristics. posix_spawn attrs (setpgroup, setsigmask, etc.) should be wired through clone handler and verified in child via /proc/self or signal delivery tests.
- **risk:** chmod/chown symlink fixes affect symlink-heavy workloads (apt, package managers); execve-fd is lower risk (rare path, gated by fd validity). Symlink xattr writes on host backend affect all stat() calls on symlinks; must test --fs host parity. setpgroup affects process group tests; must verify job control / signal routing unchanged.

## test_tempfile
- **failures:** ndiff=1: test_collision_with_existing_directory. When trying to open a directory with O_CREAT|O_EXCL, carrick returns errno 21 (EISDIR/"Is a directory") instead of the correct errno 17 (EEXIST/"File exists"). The test mocks candidate names ('aaa', 'aaa', 'bbb'), creates a directory 'tmpaaa' via mkdtemp, then tries to create a file with the same name 'tmpaaa' via open(..., O_CREAT|O_EXCL). Linux returns EEXIST so tempfile retries with the next name 'bbb'. Carrick returns EISDIR, which is unexpected.
- **root_cause:** In crates/carrick-runtime/src/vfs/rootfs.rs, the open_for_dispatch function checks writable_request BEFORE checking want_create && want_excl. When opening an existing directory (in either overlay or rootfs), it returns EISDIR for writable requests, but should return EEXIST first if O_EXCL is set. The spec requires checking EEXIST before EISDIR: per Linux open(2), EEXIST (file exists + O_EXCL) takes priority over EISDIR (directory + write access).
- **systemic:** False
- **fix** `crates/carrick-runtime/src/vfs/rootfs.rs` ~200: In the overlay directory case (line 200), add a check for want_create && want_excl BEFORE the writable_request check. If both are true, return Err(LINUX_EEXIST) immediately.
- **fix** `crates/carrick-runtime/src/vfs/rootfs.rs` ~296: In the rootfs directory case (line 296), add the same check: if want_create && want_excl is true, return Err(LINUX_EEXIST) BEFORE processing the directory. This ensures EEXIST is returned before EISDIR.
- **runner_improvement:** Test suite already catches this via CPython regrtest: test_tempfile.TestMkstempInner.test_collision_with_existing_directory. Re-run via: CARRICK_RUN_ID=rcb-$$ target/release/carrick run localhost:5050/cpython-test:3.12.13 --raw --fs host /usr/local/bin/python3 -m test test_tempfile 2>&1 | grep -A 5 test_collision_with_existing_directory
- **risk:** Low. The fix is localized to two match arms in open_for_dispatch, where we add an earlier check. The order of errno returns is purely spec-driven (EEXIST before EISDIR); this aligns carrick with Linux behavior.

## test_glob PASSES but takes 131s vs Docker 0.3s (440x slower)
- **failures:** test_glob takes 131 seconds under carrick (depth=30) vs 0.3 seconds on Docker — a 440x slowdown. Profiling shows: native stat() 0.01ms/iter vs carrick 1.62ms/iter (162x slower), native listdir() 0.02ms/iter vs carrick 1.68ms/iter (84x slower)
- **root_cause:** PATHOLOGICAL XATTR READS IN DIRECTORY ENUMERATION: The HostFsBackend::metadata() function (line 1271 in fs_backend.rs) calls two xattr-reading functions for every file during directory enumeration:

1. Line 1315: `read_mode_xattr(&self.dir, rel, meta.is_dir())` — opens the file with O_EVTONLY to read the guest-mode xattr
2. Line 1337: `read_socket_xattr(&self.dir, rel)` — opens the file with O_EVTONLY again to check for the socket-marker xattr

Each `read_*_xattr` call invokes `with_entry_fd` (line 1083), which performs a real `open()` syscall (with O_EVTONLY on macOS, line 1111-1120). This happens inside layered_directory_entries (line 2362 in fs_backend.rs), which is called for EVERY openat(directory) syscall.

During glob expansion of a deep directory tree (30 levels), Python's glob module:
1. Opens each directory level
2. For each directory, lists entries via getdents64
3. For each entry, carrick's metadata() opens it TWICE (once for mode, once for socket check)
4. The pattern expansion requires iterating through all levels

Result: N_entries × 2_opens_per_entry × depth_levels = hundreds of O_EVTONLY opens, each ~1.6ms on macOS HVF with --fs host.

MemoryBackend has no xattr reads (lines 532-560) — metadata is pure HashMap lookup — confirming the xattr opens are the bottleneck (--fs memory runs in 0ms for the same test).
- **systemic:** True
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/fs_backend.rs` ~2362: In layered_directory_entries(), avoid calling metadata() which triggers xattr opens. Instead, construct RootFsMetadata from the already-available (name, RootFsEntryKind) pairs returned by child_names() and deleted_child_names(), without opening files. The child_names() iteration at line 2392 already provides kind information; use it directly instead of deferring to metadata(). For files/dirs where mode/socket-marker xattr is not available during lazy enumeration, fall back to safe defaults (mode 0o644 for files, 0o755 for dirs, assume non-socket) — the xattrs are guest-set metadata that can be read on-demand by stat/fstat, not needed during listdir.
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/fs_backend.rs` ~2392-2458: Replace the per-entry metadata() call with direct RootFsMetadata construction from the (name, kind) tuple. The overlay.child_names(dir) iteration (line 2392) already returns the kind; use that to build metadata without opening files:

For RootFsEntryKind::File | RootFsEntryKind::CharDevice: use overlay.metadata(&path).map(|m| m.size).unwrap_or(0) for size ONLY (single metadata call, no xattr opens for directories), or skip size (getdents64 ignores it anyway).

For RootFsEntryKind::Directory / Symlink / Socket / Fifo: size is always 0 and mode defaults suffice during enumeration.

Keep the normalization of paths but move xattr-driven mode/socket-check to the stat(2) handler or on-demand metadata() path, not the listdir path.
- **runner_improvement:** **Perf fix**: Change HostFsBackend::metadata() to accept an optional flag (e.g., `for_enumeration: bool`) that skips xattr opens when called from layered_directory_entries. Or refactor layered_directory_entries to NOT call metadata() at all — instead, build RootFsMetadata entries directly from the (name, kind) pairs, with safe defaults for mode/size:\n\n```rust\nfor (name, kind) in overlay.child_names(dir) {\n  if seen.contains(&name) || deleted.contains(&name) { continue; }\n  let path = joined(dir, &name);\n  let normalized = normalize(&path).unwrap_or_default();\n  // NO metadata() call here — construct directly from kind:\n  let metadata = match kind {\n    RootFsEntryKind::File => RootFsMetadata {\n      path: normalized,\n      kind,\n      mode: 0o644,  // default; actual mode lives in xattr, read on stat()\n      size: 0,      // getdents ignores size; stat() will read it if needed\n    },\n    RootFsEntryKind::Directory => RootFsMetadata {\n      path: normalized,\n      kind,\n      mode: 0o755,\n      size: 0,\n    },\n    // ... etc\n  };\n  out.push(RootFsDirEntry { name, metadata });\n}\n```\n\nThis eliminates 2 opens per entry during getdents, reducing glob runtime from 131s→<1s (440x speedup back to parity with Docker)."
- **risk:** **Low**: The xattr mode/socket-marker is guest-set metadata that is read on-demand by fstat/stat(2). Skipping it during getdents64/readdir does not change the correctness of the returned entry kinds (File, Dir, Symlink, etc.) — the kind is already known from the FsBackend. Mode defaults (0o644, 0o755) are Linux-standard fallbacks; stat(2) will read the true xattr-stored mode if the guest queries it. Socket marker is checked only when the guest calls stat/fstat on the specific entry, not needed during enumeration. This matches Linux behavior: getdents64 returns inode numbers and d_type, NOT full stat metadata.

## test_mmap CARRICK_TIMEOUT (cascade)
- **failures:** test_around_2GB, test_around_4GB, test_large_filesize hang indefinitely; test_large_offset, test_access_parameter also timeout. Tests create sparse files of 2-4GB and mmap with MAP_SHARED|PROT_READ. Carrick hangs/OOM allocating all file bytes into a single Vec in the dispatcher.
- **root_cause:** **Line 490 in crates/carrick-runtime/src/dispatch/mem.rs allocates the entire file into a single byte vector (`vec![0; length_usize]`) for every mmap syscall that doesn't match the fast-path conditions.** For a 2GB sparse file, this tries to allocate 2GB of host RAM at once, causing an extended pause (page-zeroing) or OOM. The mmap syscall blocks in the dispatcher during this allocation, appearing as a hang to the guest. This affects file-backed mmap calls that fall through from the MapHostAlias fast-path (lines 369-435) — which only triggers if the file fd can be dup'd AND offset is 16KiB-aligned AND it's MAP_SHARED (not MAP_PRIVATE). When any condition fails, the code falls back to the slow path which eagerly allocates.
- **systemic:** False
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mem.rs` ~369-435: Extend the MapHostAlias fast-path condition (line 369-435) to accept offsets that are not 16KiB-aligned by removing or relaxing the `offset.is_multiple_of(hvf_page)` check at line 372. Alternatively, or in addition, check file size before allocating: if a non-anonymous file-backed mmap with a dup-able fd would allocate > ~128MB, take the MapHostAlias path instead of line 490 allocation.  RECOMMENDED: Remove line 372 check entirely — the HVF stage-2 mapping for the alias does not require 16KiB alignment of the host file offset; pread/mmap from the runtime will handle any offset. If alignment is truly needed for the IPA side, align only the IPA (`alias_len`), not the guest-visible file offset.
- **fix** `/Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/dispatch/mem.rs` ~490: Add a guard before `let mut bytes = vec![0; length_usize]`: if the mapping is file-backed (not MAP_ANONYMOUS), not MAP_FIXED, and the file is > some threshold (e.g., 64MB or 256MB), attempt to dup the fd and return MapHostAlias instead of allocating. This provides a safety net for cases where the strict 16KiB alignment prevents the fast path.
- **runner_improvement:** **Danger: memory-model bug.** The dispatcher's mmap handler conflates dispatch-side buffer allocation with guest-side page allocation. For large file-backed mmaps, the dispatcher has no business buffering the file; the runtime's hv_vm_map + dup fd is the right model. **Systemic risk:** Any mmap test with length > physical RAM will hang. **Adoption lever:** Gate large-file tests (>512MB) behind an environment flag or skip condition in the conformance harness; document the workaround. **Long-term:** Refactor the mmap syscall to eagerly partition large files into smaller hv_vm_map'd chunks (e.g., 256MB windows) instead of buffering.
- **risk:** **HIGH (blocking conformance).** The test suite includes standard CPython mmap tests that create files up to 4GB. Hanging on these tests blocks Python conformance progress. **Intermediate workaround:** Skip or reduce the size of test_around_2GB, test_around_4GB, test_large_filesize, test_large_offset in the conformance runner (add a gate in `tests/conformance.rs` or the probe harness). **Permanent fix:** Remove the 16KiB offset alignment check (line 372) or add the fallback allocation guard (second fix above). Both are low-risk Rust changes (no syscall contract change, MapHostAlias already proven by shared-aperture file maps).

## Cross-cutting RUNNER / hermeticity improvements (user BOLO)

- **Directory-enumeration xattr cost**: HostFsBackend readdir does 2 `open(O_EVTONLY)` xattr reads per entry; each host open through `--fs host` is ~1.6ms. CORRECTION (verified 2026-06-01): the readdir-path fix alone did NOT speed up test_glob — glob is **stat()-dominated** (per-path `metadata()` → mode-xattr open). Real fix needs path-based `getxattr` (no open+fgetxattr+close) and/or a mode-xattr cache; profile stat-vs-listdir first.
- **mmap eager-alloc**: file-backed mmap >~fast-path falls to `vec![0; length]` (dispatch/mem.rs ~490) — a 2-4GB mmap allocates 2-4GB host RAM → hang/OOM (test_mmap). Route large file mmaps through MapHostAlias (dup fd + hv_vm_map), don't buffer.
- **UDPLITE**: macOS has no IPPROTO_UDPLITE — a fundamental platform limit (224 test_socket errors). Either back with UDP (lossy) or accept as unsupportable; not a carrick bug.
- **Workflow isolation lesson**: root-cause subagents must be read-only (Explore) or `isolation:'worktree'` — an edit-capable general-purpose agent corrupted the shared tree this session.
## CORRECTED test_socket analysis (empirical, 2026-06-01) — "what is the macOS version?"

The earlier "188 = mostly UDPLITE platform limit" was wrong/dismissive. A clean
standalone run (randseed 0) gives **2 systemic, FIXABLE causes** (145 consistent
fails; the ~43 extra in the parallel sweep — testHostnameRes/testSockName/SCTP —
were flaky-under-load: SCTP actually SKIPS on both sides, hostname/sockname pass
standalone):

### 1. IPv6 RFC 3542 ancillary cmsg — 32 FAIL (`RecvmsgRFC3542AncillaryUDP6Test` etc.)
`assertEqual(len(ancdata), 1)` → `0 != 1`: recvmsg returns ZERO cmsg.
**macOS HAS this feature** (RFC 3542) — gated behind `#define __APPLE_USE_RFC_3542`,
with DIFFERENT constant values than Linux:
| option | macOS | Linux |
|---|---|---|
| IPV6_RECVHOPLIMIT | 37 | 51 |
| IPV6_HOPLIMIT (cmsg) | 47 | 52 |
| IPV6_RECVTCLASS | 35 | 66 |
| IPV6_TCLASS (cmsg) | 36 | 67 |
| IPV6_PKTINFO | 46 | 50 |
| IPV6_RECVPKTINFO | 61 | 49 |
**Fix (darwin-native, principled):** (a) in `setsockopt` (net.rs ~2687), when
level==IPPROTO_IPV6 translate the guest's Linux IPV6_RECV* optname → the macOS
value before the host setsockopt (mirror the existing SO_REUSEADDR→REUSEPORT
special-case). (b) in `recvmsg_inner` (net.rs ~3355), stop forwarding ONLY
SCM_RIGHTS — enumerate ALL host cmsg headers, translate cmsg_type macOS→Linux
(47→52, 36→67, 46→50) and rebuild the guest control buffer with proper
CMSG_ALIGN + MSG_CTRUNC. Why native-macOS-Python passes but linux-python-under-
carrick fails: native uses macOS values (37/47); carrick passes Linux 51 → macOS
treats it as a different/invalid option so the cmsg is never enabled, AND drops
it on the way out.

### 2. UDPLITE — 113 ERROR (`Basic/Recvmsg/Sendmsg*UDPLITE*Test`)
`socket(AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE=136)` fails at setUp.
**macOS has NO UDPLITE** (no constant, no protocol). Native-macOS-Python SKIPS
these (its socket module never defines IPPROTO_UDPLITE); only the LINUX guest
tries them. The only macOS backing is a plain UDP socket.
**Fix (substitute):** in `host_socket_install` (net.rs ~480), map
protocol==IPPROTO_UDPLITE(136)→UDP (proto 0/IPPROTO_UDP), store the original
proto on the HostSocket, and accept the SOL_UDPLITE(136) cscov setsockopts
(UDPLITE_SEND_CSCOV=10/RECV_CSCOV=11) as no-ops. Flips the send/recv/recvmsg
UDPLITE tests (they're the UDP tests re-run with IPPROTO_UDPLITE); the few that
assert partial-checksum-coverage *behavior* won't pass (macOS can't do it).

TAKEAWAY (runner theme): test_socket's gap is carrick not translating Linux
socket semantics onto the macOS stack — same class as the SO_REUSEADDR→REUSEPORT
and multicast→ENODEV fixes already landed. Both fixes are real net.rs work; do
the cmsg translation first (principled, uses macOS's real RFC 3542).

## test_posix progress (2026-06-01) — 4 fails → 1

Landed this session (each red-first + verified, no regressions):
- **chmod follows a final symlink** (chmod_at → canonicalize_following) — test_chmod_dir_symlink. probe chmodfollowsymlink.
- **execveat(2)** (was unregistered → ENOSYS) for fexecve/os.execve(fd); AT_EMPTY_PATH recovers the dir fd's path (open_path extended to HostFile). probe fexecveprobe.
- **ns-init process group = ns-pgid 1** — getpgrp returned the host pgid (shell's group) so posix_spawn(setpgroup=getpgrp()) → child setpgid failed → 127. Recorded init_host_pgid; host_to_ns_pgid maps it→1, new ns_to_host_pgid maps 1→the real host group; setpgid translates its pgid arg as a GROUP. probe setpgidparentgroup.

### FIXED: test_lchown (symlink owner) — 2026-06-01 (lchown a symlink → the LINK's own owner)
carrick stores guest owners in xattrs (not root on macOS). For a symlink the
xattr must live on the LINK. MECHANISM CONFIRMED (raw C): path-based
`setxattr/getxattr(path, "user.carrick.uid", ..., XATTR_NOFOLLOW=1)` sets/reads
the link's own xattr (target untouched). cap-std CANNOT do it via `O_SYMLINK`
(its per-component O_NOFOLLOW conflicts → open fails). Get the abs path with
`fcntl(dir.as_raw_fd(), F_GETPATH)` + join(rel).
DONE (commit): symlink_get/set_u32_xattr (path-based setxattr/getxattr XATTR_NOFOLLOW,
abs path via fcntl(dir_fd,F_GETPATH)) +
threaded a `symlink: bool` through read/write_owner_xattr + set_owner/get_owner.
set_owner detects symlink; get_owner + the metadata path read the link's owner
(split from FIFO). LESSON: the first probe used /tmp (different routing) and
FAILED, prompting a PREMATURE revert — but the ACTUAL test_posix.test_lchown
uses a CWD/rootfs path → HostFsBackend.set_owner, where the fix works. Always
test the real oracle, not just a probe whose path may route elsewhere. Probe
lchownsymlink now uses CWD-relative paths. test_posix behavioral fails 4→0.
Remaining ndiff=3 are SKIPS (feature availability, not bugs): RWF_HIPRI
(preadv2 hint), SEEK_HOLE/SEEK_DATA (test_fs_holes), /proc/self/ns/uts
(test_unshare_setns — procfs ns-symlink gap).
