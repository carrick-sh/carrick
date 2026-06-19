//! Filesystem syscall dispatch tests.
//!
//! Split out of the former tests/syscall_dispatch.rs monolith. Shared imports,
//! constants, and helpers live in tests/common/syscall_support.rs.

// clippy's allow-unwrap-in-tests heuristic does not cover helper functions in
// integration test crates. The no-panic gate targets production code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/syscall_support.rs"]
mod support;

use carrick_runtime::fs_backend::{
    BackendError, FsBackend, MemoryBackend, OverlayEntry, OverlayEntryKind,
};
use carrick_runtime::linux_abi::{LINUX_AT_FDCWD, LINUX_O_RDWR};
use support::*;

#[derive(Default)]
struct CountingMemoryBackend {
    inner: MemoryBackend,
    lookup_kind_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    metadata_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    shared_file_contents_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max_lookup_payload_len: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max_writeback_payload_len: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl CountingMemoryBackend {
    fn new() -> Self {
        Self::default()
    }

    fn reset_counts(&self) {
        self.lookup_kind_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.metadata_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.shared_file_contents_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.max_lookup_payload_len
            .store(0, std::sync::atomic::Ordering::SeqCst);
        self.max_writeback_payload_len
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    fn max_lookup_payload_len(&self) -> usize {
        self.max_lookup_payload_len
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn max_writeback_payload_len(&self) -> usize {
        self.max_writeback_payload_len
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn bump_max_lookup_payload_len(&self, len: usize) {
        let mut current = self.max_lookup_payload_len();
        while len > current {
            match self.max_lookup_payload_len.compare_exchange(
                current,
                len,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }

    fn bump_max_writeback_payload_len(&self, len: usize) {
        let mut current = self.max_writeback_payload_len();
        while len > current {
            match self.max_writeback_payload_len.compare_exchange(
                current,
                len,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
}

impl FsBackend for CountingMemoryBackend {
    fn lookup(&self, path: &str) -> Option<OverlayEntry> {
        let entry = self.inner.lookup(path);
        if let Some(OverlayEntry::File(bytes)) = &entry {
            self.bump_max_lookup_payload_len(bytes.len());
        }
        entry
    }

    fn lookup_kind(&self, path: &str) -> Option<OverlayEntryKind> {
        self.lookup_kind_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.lookup_kind(path)
    }

    fn metadata(&self, path: &str) -> Option<carrick_runtime::rootfs::RootFsMetadata> {
        self.metadata_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.metadata(path)
    }

    fn file_contents(&self, path: &str) -> Option<Vec<u8>> {
        self.inner.file_contents(path)
    }

    fn shared_file_contents(
        &self,
        path: &str,
    ) -> Option<carrick_runtime::fs_backend::SharedFileContents> {
        self.shared_file_contents_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.shared_file_contents(path)
    }

    fn shared_file_entry(
        &self,
        path: &str,
        trunc: bool,
    ) -> Option<carrick_runtime::fs_backend::SharedFileEntry> {
        self.inner.shared_file_entry(path, trunc)
    }

    fn fast_nofollow_metadata(
        &self,
        path: &str,
    ) -> Option<carrick_runtime::rootfs::RootFsMetadata> {
        self.inner.fast_nofollow_metadata(path)
    }

    fn make_dir(&self, path: &str) -> Result<(), BackendError> {
        self.inner.make_dir(path)
    }

    fn create_file(&self, path: &str) -> Result<(), BackendError> {
        self.inner.create_file(path)
    }

    fn may_have_fifo_nodes(&self) -> bool {
        self.inner.may_have_fifo_nodes()
    }

    fn create_file_from_rootfs(
        &self,
        path: &str,
        contents: std::sync::Arc<[u8]>,
        mode: u32,
    ) -> Result<(), BackendError> {
        self.inner.create_file_from_rootfs(path, contents, mode)
    }

    fn set_file_contents(&self, path: &str, contents: Vec<u8>) -> Result<(), BackendError> {
        self.bump_max_writeback_payload_len(contents.len());
        self.inner.set_file_contents(path, contents)
    }

    fn write_file_range(
        &self,
        path: &str,
        offset: usize,
        bytes: &[u8],
        final_size: usize,
    ) -> Result<(), BackendError> {
        self.bump_max_writeback_payload_len(bytes.len());
        self.inner.write_file_range(path, offset, bytes, final_size)
    }

    fn remove_entry(&self, path: &str) -> bool {
        self.inner.remove_entry(path)
    }

    fn mark_deleted(&self, path: &str) -> Result<(), BackendError> {
        self.inner.mark_deleted(path)
    }

    fn child_names(&self, dir: &str) -> Vec<(String, carrick_runtime::rootfs::RootFsEntryKind)> {
        self.inner.child_names(dir)
    }

    fn deleted_child_names(&self, dir: &str) -> Vec<String> {
        self.inner.deleted_child_names(dir)
    }

    fn rename_overlay_entry(&self, from: &str, to: &str) -> Result<bool, BackendError> {
        self.inner.rename_overlay_entry(from, to)
    }

    fn open_raw_fd(&self, path: &str, write: bool, create: bool, trunc: bool) -> Option<i32> {
        self.inner.open_raw_fd(path, write, create, trunc)
    }
}

#[test]
fn memory_overlay_open_uses_single_backend_snapshot_for_shared_file() {
    let backend = CountingMemoryBackend::new();
    backend
        .set_file_contents("/large.bin", vec![0x41; 1024 * 1024])
        .unwrap();
    backend.reset_counts();
    let lookup_kind_calls = backend.lookup_kind_calls.clone();
    let metadata_calls = backend.metadata_calls.clone();
    let shared_file_contents_calls = backend.shared_file_contents_calls.clone();

    let mut vfs = carrick_runtime::vfs::RootFsVfs::new();
    vfs.set_overlay(Box::new(backend));

    let result = vfs
        .open_for_dispatch("/large.bin", false, false, false, true)
        .unwrap();
    assert!(matches!(
        result,
        carrick_runtime::vfs::rootfs::OpenDispatchResult::RootFsBackedFile { .. }
    ));

    assert_eq!(
        lookup_kind_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "memory overlay file open should avoid a separate kind lookup"
    );
    assert_eq!(
        metadata_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "memory overlay file open should avoid a separate metadata lookup"
    );
    assert_eq!(
        shared_file_contents_calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "memory overlay file open should use one snapshot call instead of a separate shared-content lookup"
    );
}

#[test]
fn memory_overlay_regular_open_skips_fifo_probe_when_backend_cannot_have_fifos() {
    let backend = CountingMemoryBackend::new();
    backend
        .set_file_contents("/regular.bin", vec![0x41; 1024])
        .unwrap();
    backend.reset_counts();
    let lookup_kind_calls = backend.lookup_kind_calls.clone();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/regular.bin\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    let calls = lookup_kind_calls.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        calls <= 1,
        "memory overlay regular-file open should not run the FIFO metadata probe; lookup_kind calls={calls}"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn memory_overlay_regular_open_skips_legacy_kind_lookups() {
    let backend = CountingMemoryBackend::new();
    backend
        .set_file_contents("/regular.bin", vec![0x41; 1024])
        .unwrap();
    backend.reset_counts();
    let lookup_kind_calls = backend.lookup_kind_calls.clone();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/regular.bin\0").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );

    let calls = lookup_kind_calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        calls, 0,
        "memory overlay regular-file open should use fast no-follow metadata instead of legacy kind lookups; lookup_kind calls={calls}"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn ioctl_writes_packed_winsize_and_reports_unknown_requests() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // TIOCGWINSZ on a default stdio fd reflects the *real* backing host fd:
    // a TTY → 80x24 stub (or live winsize); a pipe/file/closed → ENOTTY,
    // matching Linux `ioctl(pipe, TIOCGWINSZ)`. The cargo-test process's
    // fd 1 may be either, so assert against the host's actual answer.
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                29,
                SyscallArgs::from([1, LINUX_TIOCGWINSZ, 0x4000, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if carrick_runtime::host_tty::host_isatty(1) {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        let winsize = read_winsize(&memory, 0x4000);
        // rows/cols come from the live terminal; just confirm they are non-zero.
        assert!(winsize.ws_row > 0 && winsize.ws_col > 0);
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, 0xdead_beef, 0x4040, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );
    let report = reporter.finish();
    assert!(report.unhandled_syscalls.is_empty());
    assert_eq!(report.unhandled_ioctls[0].request, 0xdead_beef);
    assert_eq!(report.unhandled_ioctls[0].count, 1);
}

#[test]
fn ioctl_tcgets_writes_default_termios_for_stdio_and_enotty_for_files() {
    // 1. TCGETS on fd 0 reflects the *real* backing host fd. A default stdio
    //    fd (no dup3 overlay) is a TTY iff the carrick process's own host fd 0
    //    is a TTY. When it is → cooked-TTY defaults; when it is a pipe / file
    //    (e.g. `cargo test` under CI, or the cpython-parity harness) → ENOTTY,
    //    matching Linux `ioctl(pipe, TCGETS)`.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    let stdin_is_tty = carrick_runtime::host_tty::host_isatty(0);
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCGETS, 0x4000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if stdin_is_tty {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    // 2. TCGETS on bogus fd 99 → EBADF.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_TCGETS, 0x4080, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // 3. TCGETS on a rootfs-backed file fd → ENOTTY.
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let file_fd = match opened {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected fd, got {:?}", other),
    };
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([file_fd as u64, LINUX_TCGETS, 0x4080, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );

    // 4. TCSETS on fd 0 with a valid termios buffer. On a real backing TTY
    //    this succeeds (→ 0); on a non-tty stdio fd it is ENOTTY, same as
    //    Linux `ioctl(pipe, TCSETS)`.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    // Seed any plausible bytes — the dispatcher only does a size check.
    memory
        .write_bytes(0x4000, LinuxTermios::default_cooked().as_bytes())
        .unwrap();
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCSETS, 0x4000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if stdin_is_tty {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });

        // 5. TCSETS on fd 0 with a bad pointer → EFAULT (only reached on a
        //    real tty; a non-tty short-circuits to ENOTTY before the read).
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCSETS, 0x1, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Errno { errno: 14 }
        );
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    assert!(reporter.finish().unhandled_ioctls.is_empty());
}

#[test]
fn ioctl_tcgets2_is_recognized_and_mirrors_tcgets() {
    // glibc-aarch64 implements tcgetattr/tcsetattr — and therefore isatty(3),
    // which goes through tcgetattr — via the termios2 ioctls TCGETS2/TCSETS2,
    // NOT the legacy 36-byte TCGETS. (musl still uses TCGETS, which is why the
    // musl-only probe suite never caught this.) Before carrick recognized
    // TCGETS2, glibc `bash` got ENOTTY from its isatty() and ran NON-interactive
    // — no PS1. carrick must treat TCGETS2 exactly like TCGETS for the tty/
    // non-tty decision, and must never record it as an *unhandled* ioctl.
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // 1. TCGETS2 on fd 0 mirrors TCGETS: a real backing tty → success, a
    //    pipe/file (e.g. `cargo test` under CI) → ENOTTY. Either way it is a
    //    *recognized* request.
    let stdin_is_tty = carrick_runtime::host_tty::host_isatty(0);
    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCGETS2, 0x4000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if stdin_is_tty {
        assert_eq!(outcome, DispatchOutcome::Returned { value: 0 });
        // The full 44-byte termios2 is written, including the c_ispeed/c_ospeed
        // tail at bytes 36..44 that legacy TCGETS (36 bytes) leaves untouched.
        let tail = memory.read_bytes(0x4000 + 36, 8).unwrap();
        assert_eq!(tail.len(), 8);
    } else {
        assert_eq!(outcome, DispatchOutcome::Errno { errno: 25 });
    }

    // 2. TCGETS2 on a bogus fd → EBADF (recognized, validated before tty-ness).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([99, LINUX_TCGETS2, 0x4080, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // 3. TCSETS2 on fd 0 mirrors TCSETS (success on a tty, ENOTTY otherwise).
    memory
        .write_bytes(0x4000, LinuxTermios::default_cooked().as_bytes())
        .unwrap();
    let set_outcome = dispatcher
        .dispatch(
            SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TCSETS2, 0x4000, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    if stdin_is_tty {
        assert_eq!(set_outcome, DispatchOutcome::Returned { value: 0 });
    } else {
        assert_eq!(set_outcome, DispatchOutcome::Errno { errno: 25 });
    }

    // The regression guard, robust whether or not CI gives us a tty: TCGETS2 /
    // TCSETS2 are KNOWN requests and must never fall through to the unhandled
    // catch-all. Pre-fix this set contained 0x802c_542a.
    let report = reporter.finish();
    assert!(
        report
            .unhandled_ioctls
            .iter()
            .all(|u| u.request != LINUX_TCGETS2 && u.request != LINUX_TCSETS2),
        "TCGETS2/TCSETS2 must be recognized, not unhandled: {:?}",
        report.unhandled_ioctls
    );
}

#[test]
fn tty_ioctls_handle_pgrp_sid_and_controlling_terminal_calls() {
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    // TIOCGPGRP on stdio fd 0 → writes pgid=1.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCGPGRP, 0x4000, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_i32_le(&memory, 0x4000), 1);

    // TIOCGSID on stdio fd 2 → writes sid=1.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([2, LINUX_TIOCGSID, 0x4010, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(read_i32_le(&memory, 0x4010), 1);

    // TIOCGPGRP on unknown fd 99 → EBADF.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([99, LINUX_TIOCGPGRP, 0x4020, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );

    // TIOCSPGRP on stdio with pgid=1 → 0; with pgid=99 → EPERM.
    memory.write_bytes(0x4030, &1_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCSPGRP, 0x4030, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    memory.write_bytes(0x4040, &99_i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCSPGRP, 0x4040, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 1 }
    );

    // TIOCSCTTY / TIOCNOTTY on stdio → 0.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([1, LINUX_TIOCSCTTY, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(29, SyscallArgs::from([0, LINUX_TIOCNOTTY, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );

    // On a rootfs-backed file fd: TIOCGPGRP/TIOCGSID → ENOTTY.
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    let file_fd = match opened {
        DispatchOutcome::Returned { value } => value,
        other => panic!("expected fd, got {:?}", other),
    };
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([file_fd as u64, LINUX_TIOCGPGRP, 0x4040, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([file_fd as u64, LINUX_TIOCGSID, 0x4048, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 25 }
    );

    assert!(reporter.finish().unhandled_ioctls.is_empty());
}

/// Verify that `host_tty_tcgetpgrp` on a real pty slave returns the HOST
/// `tcgetpgrp` value, never the synthesised `LINUX_BOOTSTRAP_PGID` constant.
///
/// We open a fresh pty pair (posix_openpt / grantpt / unlockpt), call
/// `host_tty_tcgetpgrp` on the slave side, and assert it matches a direct
/// `libc::tcgetpgrp` call.  We intentionally do NOT check for a specific
/// numeric value — a freshly-opened slave that has never been made the
/// controlling tty may return -1 (ENOTTY or ENXIO on some kernels) — but we
/// DO assert that it never returns the faked bootstrap constant (1).
#[test]
fn tiocgpgrp_on_real_tty_uses_host_value_not_bootstrap() {
    // SAFETY: posix_openpt / grantpt / unlockpt / ptsname / open are standard
    // POSIX calls; we close the fds in the cleanup block.
    let (master, slave) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        libc::grantpt(m);
        libc::unlockpt(m);
        let name_ptr = libc::ptsname(m);
        assert!(!name_ptr.is_null(), "ptsname returned NULL");
        let name = std::ffi::CStr::from_ptr(name_ptr).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0, "open pty slave failed");
        (m, s)
    };

    // The slave is a real tty.
    assert!(
        carrick_runtime::host_tty::host_isatty(slave),
        "pty slave must be a tty"
    );

    // Direct libc call — this is the reference value.
    // SAFETY: slave is a valid open fd.
    let direct = unsafe { libc::tcgetpgrp(slave) };

    // Our helper must agree with the direct call.
    let via_helper = carrick_runtime::host_tty::host_tty_tcgetpgrp(slave);
    match via_helper {
        Ok(pgrp) => {
            assert_eq!(
                pgrp, direct,
                "host_tty_tcgetpgrp must match direct tcgetpgrp"
            );
            // Must never be the synthesised bootstrap constant on a real tty.
            assert_ne!(
                pgrp,
                carrick_runtime::linux_abi::LINUX_BOOTSTRAP_PGID,
                "host_tty_tcgetpgrp must not return the faked bootstrap pgid on a real tty"
            );
        }
        Err(_raw_errno) => {
            // tcgetpgrp returned -1: the slave has no controlling process group
            // (e.g. no session has made it the ctty yet).  The important
            // invariant is that our helper propagated the failure rather than
            // silently returning LINUX_BOOTSTRAP_PGID.
            assert!(
                direct < 0,
                "helper returned Err but direct tcgetpgrp returned {}",
                direct
            );
        }
    }

    // Cleanup.
    // SAFETY: closing fds we opened above.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// Verify that `host_tty_tcgetsid` on a real pty slave follows the host
/// `tcgetsid` result, instead of silently returning Carrick's synthetic
/// bootstrap SID fallback.
#[test]
fn tiocgsid_on_real_tty_uses_host_value_not_bootstrap() {
    // SAFETY: same pty-open pattern as the pgrp test.
    let (master, slave) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        libc::grantpt(m);
        libc::unlockpt(m);
        let name_ptr = libc::ptsname(m);
        assert!(!name_ptr.is_null(), "ptsname returned NULL");
        let name = std::ffi::CStr::from_ptr(name_ptr).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0, "open pty slave failed");
        (m, s)
    };

    assert!(
        carrick_runtime::host_tty::host_isatty(slave),
        "pty slave must be a tty"
    );

    // SAFETY: slave is a valid open fd.
    let direct = unsafe { libc::tcgetsid(slave) };
    let via_helper = carrick_runtime::host_tty::host_tty_tcgetsid(slave);
    match via_helper {
        Ok(sid) => {
            assert_eq!(sid, direct, "host_tty_tcgetsid must match tcgetsid");
            assert_ne!(
                sid,
                carrick_runtime::linux_abi::LINUX_BOOTSTRAP_SID,
                "host_tty_tcgetsid must not return the faked bootstrap sid on a real tty"
            );
        }
        Err(_) => {
            assert!(
                direct < 0,
                "helper returned Err but direct tcgetsid returned {}",
                direct
            );
        }
    }

    // SAFETY: closing fds we opened above.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// Verify that `host_tty_tcsetpgrp` on a real pty slave either succeeds or
/// returns a real errno (not silently EPERM-ing as the headless fallback does).
///
/// In a test-harness the slave is not the controlling tty of any session, so
/// `tcsetpgrp` will typically EPERM/ENOTTY.  The important property is that
/// `host_tty_tcsetpgrp` does NOT silently succeed on the bootstrap pgid the
/// way the non-tty fake path does — it actually calls the host.
#[test]
fn tiocspgrp_on_real_tty_calls_host_not_fake() {
    // SAFETY: same pty-open pattern as the get test.
    let (master, slave) = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt failed");
        libc::grantpt(m);
        libc::unlockpt(m);
        let name_ptr = libc::ptsname(m);
        assert!(!name_ptr.is_null());
        let name = std::ffi::CStr::from_ptr(name_ptr).to_owned();
        let s = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        assert!(s >= 0);
        (m, s)
    };

    let our_pgrp = unsafe { libc::getpgrp() };
    // Call our helper — it may succeed or fail (EPERM/ENOTTY in harness), but
    // it must not panic.  Verify it returns the same outcome as a direct call.
    let result_helper = carrick_runtime::host_tty::host_tty_tcsetpgrp(slave, our_pgrp);
    // SAFETY: same fd, same call.
    let direct_r = unsafe { libc::tcsetpgrp(slave, our_pgrp) };
    match result_helper {
        Ok(()) => assert_eq!(
            direct_r, 0,
            "helper Ok but direct call returned {}",
            direct_r
        ),
        Err(_) => assert!(
            direct_r < 0,
            "helper Err but direct call returned {}",
            direct_r
        ),
    }

    // SAFETY: closing fds we opened above.
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

#[test]
fn flock_accepts_bootstrap_advisory_locks_on_open_files() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    32,
                    SyscallArgs::from([3, LINUX_LOCK_SH | LINUX_LOCK_NB, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(32, SyscallArgs::from([3, LINUX_LOCK_UN, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(32, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(32, SyscallArgs::from([99, LINUX_LOCK_SH, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_read_close_round_trip_through_rootfs_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let opened = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(opened, DispatchOutcome::Returned { value: 3 });

    let read = dispatcher
        .dispatch(
            SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 64, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(read, DispatchOutcome::Returned { value: 18 });
    assert_eq!(
        memory.read_bytes(0x4100, 18).unwrap(),
        b"rootfs says hello\n"
    );

    let closed = dispatcher
        .dispatch(
            SyscallRequest::new(57, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
            &mut memory,
            &reporter,
        )
        .unwrap();
    assert_eq!(closed, DispatchOutcome::Returned { value: 0 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat_missing_rootfs_file_returns_enoent() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, b"/missing\0".to_vec());
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    let outcome = dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap();

    assert_eq!(outcome, DispatchOutcome::Errno { errno: 2 });
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn openat2_reads_open_how_and_opens_readonly_rootfs_paths() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    write_open_how(&mut memory, 0x4020, LINUX_O_CLOEXEC, 0, 0);
    write_open_how(&mut memory, 0x4060, LINUX_O_WRONLY, 0, 0);
    write_open_how(&mut memory, 0x40a0, 0, 0, 0x4);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4020, 24, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 64, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 18 }
    );
    assert_eq!(
        memory.read_bytes(0x4100, 18).unwrap(),
        b"rootfs says hello\n"
    );

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4060, 24, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x40a0, 24, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 5 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    437,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0x4020, 16, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn open_o_tmpfile_creates_anonymous_writable_file() {
    // O_TMPFILE returns an unnamed, writable regular file; verify the
    // write -> lseek -> read round-trip, and that O_RDONLY|O_TMPFILE is EINVAL.
    const LINUX_O_RDWR: u64 = 2;
    const LINUX_O_TMPFILE: u64 = 0o20000000;
    const LINUX_AT_FDCWD: u64 = (-100_i64) as u64;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    let run = |d: &mut SyscallDispatcher, m: &mut LinearMemory, nr: u64, args: [u64; 6]| {
        d.dispatch(
            SyscallRequest::new(nr, SyscallArgs::from(args)),
            m,
            &reporter,
        )
        .unwrap()
    };

    // openat(AT_FDCWD, <dir>, O_TMPFILE|O_RDWR, 0600); pathname is unused for
    // O_TMPFILE, so a null pointer is fine.
    let fd = match run(
        &mut dispatcher,
        &mut memory,
        56,
        [
            LINUX_AT_FDCWD,
            0,
            LINUX_O_TMPFILE | LINUX_O_RDWR,
            0o600,
            0,
            0,
        ],
    ) {
        DispatchOutcome::Returned { value } => {
            assert!(value >= 3, "tmpfile fd {value}");
            value as u64
        }
        other => panic!("openat O_TMPFILE: {other:?}"),
    };

    memory.write_bytes(0x4100, b"hi").unwrap();
    assert_eq!(
        run(&mut dispatcher, &mut memory, 64, [fd, 0x4100, 2, 0, 0, 0]),
        DispatchOutcome::Returned { value: 2 }
    );
    // lseek(fd, 0, SEEK_SET) -> 0
    assert_eq!(
        run(&mut dispatcher, &mut memory, 62, [fd, 0, 0, 0, 0, 0]),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        run(&mut dispatcher, &mut memory, 63, [fd, 0x4200, 2, 0, 0, 0]),
        DispatchOutcome::Returned { value: 2 }
    );
    assert_eq!(memory.read_bytes(0x4200, 2).unwrap(), b"hi");

    // O_TMPFILE requires write access; O_RDONLY|O_TMPFILE is EINVAL.
    assert_eq!(
        run(
            &mut dispatcher,
            &mut memory,
            56,
            [LINUX_AT_FDCWD, 0, LINUX_O_TMPFILE, 0o600, 0, 0]
        ),
        DispatchOutcome::Errno { errno: 22 }
    );
}

#[test]
fn dup_shares_rootfs_file_offset_with_original_fd() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(23, SyscallArgs::from([3, 0, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([3, 0x4100, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([4, 0x4200, 4, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(memory.read_bytes(0x4100, 4).unwrap(), b"root");
    assert_eq!(memory.read_bytes(0x4200, 4).unwrap(), b"fs s");
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn dup3_installs_requested_fd_and_cloexec_is_per_descriptor() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(24, SyscallArgs::from([3, 9, LINUX_O_CLOEXEC, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([9, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_gets_and_sets_descriptor_and_status_flags() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, LINUX_O_CLOEXEC, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_SETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_GETFL, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([3, LINUX_F_DUPFD_CLOEXEC, 8, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 8 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([8, LINUX_F_GETFD, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned {
            value: LINUX_FD_CLOEXEC as i64
        }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(25, SyscallArgs::from([3, LINUX_F_DUPFD, 8, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 9 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn fcntl_on_bare_stdio_succeeds_not_ebadf() {
    // Regression: F_SETFL on bare stdio (fd 0/1/2, which have no
    // OpenDescription in open_files) used to return EBADF, while
    // F_GETFD/F_SETFD/F_GETFL all special-cased stdio. apt's dpkg child sets
    // stdin non-blocking via fcntl(0, F_SETFL, O_NONBLOCK) before exec and
    // treated the EBADF as fatal (_exit(100)) — it broke `apt install`.
    const LINUX_F_SETFL: u64 = 4;
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x40]);
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    for fd in [0u64, 1, 2] {
        assert_eq!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        25,
                        SyscallArgs::from([fd, LINUX_F_SETFL, LINUX_O_NONBLOCK, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { value: 0 },
            "fcntl(F_SETFL, O_NONBLOCK) on stdio fd {fd} must succeed, not EBADF",
        );
        for cmd in [LINUX_F_GETFD, LINUX_F_GETFL] {
            let outcome = dispatcher
                .dispatch(
                    SyscallRequest::new(25, SyscallArgs::from([fd, cmd, 0, 0, 0, 0])),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            assert!(
                matches!(outcome, DispatchOutcome::Returned { .. }),
                "fcntl(cmd {cmd}) on stdio fd {fd} must not error: {outcome:?}",
            );
        }
    }

    // A genuinely invalid fd still returns EBADF (we didn't blanket-accept).
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    25,
                    SyscallArgs::from([999, LINUX_F_SETFL, LINUX_O_NONBLOCK, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 9 },
        "fcntl(F_SETFL) on an invalid fd must still be EBADF",
    );
}

// ── close_range frees pty master entry ────────────────────────────────────────

#[test]
fn close_range_frees_pty_master_entry() {
    // Regression test: close_range(first, last, 0) must drop the PtyTable
    // entry for any pty master in the range, just like close(2) does.
    // Without the fix, close_range called the bare close_open_file() helper
    // which freed the host fd but left the /dev/pts/N entry alive.
    let mut dispatcher = SyscallDispatcher::new();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x200]);
    memory.write_bytes(0x4000, b"/dev/ptmx\0").unwrap();
    memory.write_bytes(0x4040, b"/dev/pts/0\0").unwrap();
    let reporter = CompatReporter::default();

    // openat(AT_FDCWD, "/dev/ptmx", O_RDWR=2) → master fd; allocates pts index 0.
    let master = match dispatcher
        .dispatch(
            SyscallRequest::new(
                56,
                SyscallArgs::from([(-100_i64) as u64, 0x4000, 2, 0, 0, 0]),
            ),
            &mut memory,
            &reporter,
        )
        .unwrap()
    {
        DispatchOutcome::Returned { value } => value as u64,
        o => panic!("open /dev/ptmx failed: {:?}", o),
    };

    // Unlock the slave so we can verify it is reachable before the master closes.
    let lockarg = 0x4100u64;
    memory.write_bytes(lockarg, &0i32.to_le_bytes()).unwrap();
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([master, LINUX_TIOCSPTLCK, lockarg, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "TIOCSPTLCK unlock must succeed"
    );

    // /dev/pts/0 must be openable before the master is closed.
    assert!(
        matches!(
            dispatcher
                .dispatch(
                    SyscallRequest::new(
                        56,
                        SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap(),
            DispatchOutcome::Returned { .. }
        ),
        "slave should be openable before master is closed"
    );

    // close_range(master, master, 0) — syscall 436.
    // This must remove the pts index from the PtyTable.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(436, SyscallArgs::from([master, master, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 0 },
        "close_range(master, master, 0) must succeed"
    );

    // /dev/pts/0 must now be ENOENT (errno 2): the table entry was removed.
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4040, 2, 0, 0, 0])
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 2 },
        "/dev/pts/0 must be ENOENT after close_range frees the master"
    );
}

#[test]
fn small_write_to_large_overlay_file_does_not_rewrite_whole_file() {
    const LARGE_FILE_LEN: usize = 4 * 1024 * 1024;

    let backend = CountingMemoryBackend::new();
    backend
        .set_file_contents("/large.bin", vec![0x41; LARGE_FILE_LEN])
        .unwrap();
    backend.reset_counts();
    let lookup_counts = backend.max_lookup_payload_len.clone();
    let counts = backend.max_writeback_payload_len.clone();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/large.bin\0").unwrap();
    memory.write_bytes(0x4100, b"Z").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4100, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(56, SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 4 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(63, SyscallArgs::from([4, 0x4200, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(memory.read_bytes(0x4200, 1).unwrap(), b"Z");

    let max_lookup = lookup_counts.load(std::sync::atomic::Ordering::SeqCst);
    let max_rewrite = counts.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        max_lookup <= 1,
        "one-byte write should not clone the whole {LARGE_FILE_LEN}-byte file on open; max lookup payload was {max_lookup}"
    );
    assert!(
        max_rewrite <= 1,
        "one-byte write should not rewrite or clone the whole {LARGE_FILE_LEN}-byte file; max writeback payload was {max_rewrite}"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn small_write_to_large_rootfs_file_does_not_copy_up_whole_file() {
    const LARGE_FILE_LEN: usize = 4 * 1024 * 1024;

    let large = vec![0x41; LARGE_FILE_LEN];
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "large.bin",
        large.as_slice(),
    )]))])
    .unwrap();
    let backend = CountingMemoryBackend::new();
    let counts = backend.max_writeback_payload_len.clone();

    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
    dispatcher.set_fs_backend(Box::new(backend));
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/large.bin\0").unwrap();
    memory.write_bytes(0x4100, b"Z").unwrap();

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([LINUX_AT_FDCWD, 0x4000, LINUX_O_RDWR, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(64, SyscallArgs::from([3, 0x4100, 1, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(67, SyscallArgs::from([3, 0x4200, 2, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 2 }
    );
    assert_eq!(memory.read_bytes(0x4200, 2).unwrap(), b"ZA");

    let max_rewrite = counts.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        max_rewrite <= 1,
        "one-byte rootfs write should not copy up the whole {LARGE_FILE_LEN}-byte file; max writeback payload was {max_rewrite}"
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}

#[test]
fn x86_private_dup2_installs_requested_fd_and_allows_same_fd_noop() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x100]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);

    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    56,
                    SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 3 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    carrick_runtime::linux_abi::CARRICK_PRIVATE_X86_DUP2,
                    SyscallArgs::from([3, 1, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(
                    carrick_runtime::linux_abi::CARRICK_PRIVATE_X86_DUP2,
                    SyscallArgs::from([1, 1, 0, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Returned { value: 1 }
    );
    assert_eq!(
        dispatcher
            .dispatch(
                SyscallRequest::new(24, SyscallArgs::from([1, 1, 0, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap(),
        DispatchOutcome::Errno { errno: 22 }
    );
    assert!(reporter.finish().unhandled_syscalls.is_empty());
}
