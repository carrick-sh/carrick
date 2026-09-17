//! VM-free public kernel backend coverage for Unicode / non-ASCII path operations.
//!
//! # Linux Oracle and Specification References
//! - Linux treats pathnames as opaque byte sequences; pathname resolution does not perform
//!   Unicode normalization folding (see Linux `path_resolution(7)`).
//! - Syscall behavior is verified against Linux man-pages:
//!   - `openat(2)`: byte-exact path resolution, `O_CREAT`, `O_RDONLY`, `O_RDWR`.
//!   - `write(2)` / `read(2)`: data stream I/O.
//!   - `unlinkat(2)`: removes directory entries; subsequent opens fail with `ENOENT`.
//!   - `newfstatat(2)` / `stat(2)`: inode status and link count verification.
//!   - `linkat(2)`: creates a new directory entry for an existing inode with exact bytes.
//!   - `renameat2(2)`: atomic replacement of target; existing open file descriptors retain
//!     access to replaced unlinked file data; source name is unlinked.
//!   - `mkdirat(2)` / `symlinkat(2)` / `readlinkat(2)`: directory creation and symlink targets
//!     preserve exact byte strings.
//! - Host macOS APFS is normalization-insensitive by default; Carrick VFS validates exact
//!   byte equality to guarantee Linux-exact behavior without normalization aliasing.
//! - macOS single-leaf query bounds: `getattrlistat(2)` (`ATTR_CMN_NAME`, `FSOPT_NOFOLLOW`)
//!   queries stored leaf bytes directly in O(1) without directory scans.

#[cfg(target_os = "macos")]
use std::sync::atomic::Ordering;

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_ENOENT, LINUX_O_CREAT, LINUX_O_RDONLY, LINUX_O_RDWR, LINUX_O_WRONLY,
};
use carrick_kernel_example::{ScriptedBackend, Step, slot, sys};
#[cfg(target_os = "macos")]
use carrick_vfs::fs_backend::FsBackend;
use carrick_vfs::fs_backend::HostFsBackend;

/// Linux `openat(2)`, `write(2)`, `read(2)`, `unlinkat(2)`.
///
/// Verifies round-trip creation, writing, reading, and unlinking of a non-ASCII
/// (UTF-8 encoded) leaf path. After `unlinkat(2)`, subsequent `openat(2)` must
/// return `ENOENT`.
#[test]
fn test_unicode_file_create_write_read_reopen_unlink() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        // Create and write to non-ASCII file "/café.txt" (openat(2), write(2))
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/café.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .save(0),
        ),
        Step::Sys(sys::write(slot(0), b"bonjour le cafe").ret(15)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        // Reopen for read and verify contents (openat(2), read(2))
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/café.txt", LINUX_O_RDONLY as i32, 0)
                .ret(3)
                .save(1),
        ),
        Step::Sys(sys::read(slot(1), 15).ret(15)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // Unlink the file (unlinkat(2))
        Step::Sys(sys::unlinkat(LINUX_AT_FDCWD, "/café.txt", 0).ret(0)),
        // Reopening after unlink must yield ENOENT (openat(2))
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/café.txt", LINUX_O_RDONLY as i32, 0).errno(LINUX_ENOENT),
        ),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"bonjour le cafe");
}

/// Linux `path_resolution(7)`, `openat(2)`, `newfstatat(2)`.
///
/// Under Linux, pathnames are exact byte sequences. A file created with NFC
/// spelling (`\u{00E9}`, UTF-8 `C3 A9`) must NOT match an NFD lookup
/// (`\u{0065}\u{0301}`, UTF-8 `65 CC 81`), and must return `ENOENT`.
#[test]
fn test_unicode_composed_vs_decomposed_alias_protection() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    // NFC: "café" (C3 A9), NFD: "cafe\u{0301}" (65 CC 81)
    let script = vec![
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/café_nfc",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .ret(3),
        ),
        Step::Sys(sys::close(3).ret(0)),
        // Open with NFD name must fail with ENOENT (no normalization aliasing)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/cafe\u{0301}_nfc",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_ENOENT),
        ),
        // Stat with NFD name must fail with ENOENT
        Step::Sys(sys::newfstatat(LINUX_AT_FDCWD, "/cafe\u{0301}_nfc", 0).errno(LINUX_ENOENT)),
        // Open with exact NFC name succeeds
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/café_nfc", LINUX_O_RDONLY as i32, 0).ret(3)),
        Step::Sys(sys::close(3).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `linkat(2)`, `openat(2)`.
///
/// Creating a hardlink with a non-ASCII name links to the target inode.
/// The new link's exact byte name is retained, and decomposed alias lookups
/// fail with `ENOENT`.
#[test]
fn test_unicode_hardlink_exact_name_retained() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/target_é",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .ret(3),
        ),
        Step::Sys(sys::close(3).ret(0)),
        // Create hardlink "/link_é" pointing to "/target_é" (linkat(2))
        Step::Sys(sys::linkat(LINUX_AT_FDCWD, "/target_é", LINUX_AT_FDCWD, "/link_é", 0).ret(0)),
        // Open hardlink under its exact NFC spelling succeeds (openat(2))
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/link_é", LINUX_O_RDONLY as i32, 0).ret(3)),
        Step::Sys(sys::close(3).ret(0)),
        // Decomposed spelling of the hardlink fails with ENOENT
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/link_e\u{0301}", LINUX_O_RDONLY as i32, 0)
                .errno(LINUX_ENOENT),
        ),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `renameat2(2)`, `openat(2)`, `read(2)`, `write(2)`.
///
/// Under Linux `renameat2(2)`:
/// 1. Renaming atomically replaces an existing target file.
/// 2. File descriptors already open on the target file before replacement
///    continue to read the old file's data.
/// 3. Subsequent opens of the target path observe the new replaced data.
/// 4. The source name is unlinked (`openat(2)` fails with `ENOENT`).
#[test]
fn test_unicode_rename_and_replacement() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        // 1. Create target file "/target_é" with initial content
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/target_é",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ),
        Step::Sys(sys::write(slot(0), b"target_initial_bytes").ret(20)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        // 2. Pre-open "/target_é" for reading before replacement; keep slot(1) open
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/target_é", LINUX_O_RDONLY as i32, 0)
                .ret(3)
                .save(1),
        ),
        // 3. Create source file "/src_é" with replacement content
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/src_é",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(2),
        ),
        Step::Sys(sys::write(slot(2), b"src_replacement_data").ret(20)),
        Step::Sys(sys::close(slot(2)).ret(0)),
        // 4. Atomically rename "/src_é" -> "/target_é", replacing "/target_é"
        Step::Sys(sys::renameat2(LINUX_AT_FDCWD, "/src_é", LINUX_AT_FDCWD, "/target_é", 0).ret(0)),
        // 5. Source name is unlinked -> ENOENT
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/src_é", LINUX_O_RDONLY as i32, 0).errno(LINUX_ENOENT),
        ),
        // 6. Pre-opened descriptor (slot 1) retains access to old content
        Step::Sys(sys::read_tagged(slot(1), 20, "read_preopened_old").ret(20)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        // 7. Newly opened descriptor sees replaced content
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/target_é", LINUX_O_RDONLY as i32, 0)
                .ret(3)
                .save(3),
        ),
        Step::Sys(sys::read_tagged(slot(3), 20, "read_replaced_new").ret(20)),
        Step::Sys(sys::close(slot(3)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        run.output_tagged("read_preopened_old"),
        b"target_initial_bytes"
    );
    assert_eq!(
        run.output_tagged("read_replaced_new"),
        b"src_replacement_data"
    );
}

/// Linux `mkdirat(2)`, `symlinkat(2)`, `readlinkat(2)`, `openat(2)`.
///
/// Non-ASCII directory paths and symlink targets are preserved byte-for-byte;
/// `readlinkat(2)` returns the exact target string bytes, and decomposed
/// path components fail with `ENOENT`.
#[test]
fn test_unicode_symlink_and_directory_names() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        // Make non-ASCII directory (mkdirat(2))
        Step::Sys(sys::mkdirat(LINUX_AT_FDCWD, "/dir_é", 0o755).ret(0)),
        // Create target file inside directory (openat(2))
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/dir_é/target",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .ret(3),
        ),
        Step::Sys(sys::close(3).ret(0)),
        // Create symlink "/dir_é/symlink_é" -> "target" (symlinkat(2))
        Step::Sys(sys::symlinkat("target", LINUX_AT_FDCWD, "/dir_é/symlink_é").ret(0)),
        // readlinkat on symlink returns "target" (readlinkat(2))
        Step::Sys(sys::readlinkat(LINUX_AT_FDCWD, "/dir_é/symlink_é", 32).ret(6)),
        // Decomposed symlink path -> ENOENT
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/dir_é/symlink_e\u{0301}",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_ENOENT),
        ),
        // Decomposed directory path -> ENOENT
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/dir_e\u{0301}/symlink_é",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_ENOENT),
        ),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(&run.output("readlinkat")[0..6], b"target");
}

/// macOS-only single-leaf query zero-enumeration verification.
///
/// On macOS APFS hosts, `getattrlistat(2)` (`ATTR_CMN_NAME`, `FSOPT_NOFOLLOW`)
/// queries stored leaf name bytes directly in O(1) without enumerating sibling entries.
/// Linux intentionally uses directory enumeration fallback.
#[cfg(target_os = "macos")]
#[test]
fn test_unicode_lookup_bounds_directory_entry_visits_with_siblings() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    // Create a directory with 100 sibling files plus one non-ASCII file
    host_backend.make_dir("/wide").unwrap();
    for i in 0..100 {
        host_backend
            .create_file(&format!("/wide/sibling_{i:04}.txt"))
            .unwrap();
    }
    host_backend.create_file("/wide/café.txt").unwrap();

    // Clone test-only instance counter handle before moving backend into Box
    let counter = host_backend.name_validation_dir_entries_handle();

    let script = vec![
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/wide/café.txt", LINUX_O_RDONLY as i32, 0).ret(3)),
        Step::Sys(sys::close(3).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);

    // On macOS using getattrlistat, zero directory entries are visited during lookup.
    // In unfixed baseline, this fails because read_dir_entries enumerates all 100+ siblings.
    let visits = counter.load(Ordering::Relaxed);
    assert_eq!(
        visits, 0,
        "macOS single-leaf lookup must visit 0 directory entries (got {visits})"
    );
}
