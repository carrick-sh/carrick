//! VM-free public kernel backend coverage for file descriptor table admission ordering.
//!
//! # Linux Specification and Oracle References
//! - Linux `open(2)` / `openat(2)`:
//!   - `EMFILE`: "The per-process limit on the number of open file descriptors has been reached
//!     (see the discussion of RLIMIT_NOFILE in getrlimit(2))."
//!   - Under Linux, descriptor table admission precedes file truncation (`O_TRUNC`) and file
//!     creation (`O_CREAT`), as well as pathname resolution for missing targets.
//!   - When the process's descriptor limit (`RLIMIT_NOFILE`) is reached, `openat(2)` fails with
//!     `EMFILE` without modifying existing file contents, without materializing new files in the
//!     directory, and without returning `ENOENT` on missing targets.
//! - Linux `getrlimit(2)` / `prlimit64(2)`:
//!   - `RLIMIT_NOFILE`: "Specifies a value one greater than the maximum file descriptor number
//!     that can be opened by this process."
//!   - Changes to soft limits via `prlimit64(2)` take effect immediately and are per-process.
//! - Native ARM64 Docker Oracle:
//!   - Reference run recorded in `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_EBUSY, LINUX_EMFILE, LINUX_ENOENT, LINUX_O_CREAT, LINUX_O_RDONLY,
    LINUX_O_RDWR, LINUX_O_TRUNC, LINUX_O_WRONLY, LINUX_RLIMIT_NOFILE,
};
use carrick_kernel_example::{ScriptedBackend, Step, await_parked, last_child, slot, sys};
use carrick_vfs::fs_backend::HostFsBackend;

fn rlimit_payload(cur: u64, max: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&cur.to_le_bytes());
    b[8..16].copy_from_slice(&max.to_le_bytes());
    b
}

// ============================================================================
// (1) No truncation on rejected open
// ============================================================================

/// Linux `openat(2)` with `O_TRUNC` on a full descriptor table (memory filesystem).
///
/// Authority: `man 2 openat`, `man 2 getrlimit` (RLIMIT_NOFILE),
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.
///
/// When all descriptor slots are exhausted under `RLIMIT_NOFILE`, `openat(2)`
/// with `O_TRUNC` must fail with `EMFILE` without truncating the existing file's
/// contents.
#[test]
fn test_memfs_open_rejected_by_rlimit_does_not_truncate_existing_file() {
    let limit_3 = rlimit_payload(3, 1024);
    let limit_1024 = rlimit_payload(1024, 1024);

    let script = vec![
        // 1. Create existing file with initial content "preserve" (8 bytes)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/preserve_mem.txt",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ),
        Step::Sys(sys::write(slot(0), b"preserve").ret(8)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        // 2. Set RLIMIT_NOFILE soft limit to 3 (stdio fds 0..2 occupy all 3 slots)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 3. Attempt open with O_TRUNC -> must fail with EMFILE
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/preserve_mem.txt",
                (LINUX_O_TRUNC | LINUX_O_WRONLY) as i32,
                0,
            )
            .errno(LINUX_EMFILE),
        ),
        // 4. Restore soft limit to inspect file content
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_1024[..], 0).ret(0)),
        // 5. Open for read and verify content was preserved
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/preserve_mem.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .save(1),
        ),
        Step::Sys(sys::read_tagged(slot(1), 8, "read_preserved").ret(8)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        run.output_tagged("read_preserved"),
        b"preserve",
        "file content must not be truncated when openat is rejected by RLIMIT_NOFILE"
    );
}

/// Linux `openat(2)` with `O_TRUNC` on a full descriptor table (host filesystem).
///
/// Authority: `man 2 openat`, `man 2 getrlimit` (RLIMIT_NOFILE),
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.
///
/// When all descriptor slots are exhausted under `RLIMIT_NOFILE`, `openat(2)`
/// with `O_TRUNC` on `HostFsBackend` must fail with `EMFILE` without truncating
/// the existing host file's contents.
#[test]
fn test_hostfs_open_rejected_by_rlimit_does_not_truncate_existing_file() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let limit_3 = rlimit_payload(3, 1024);
    let limit_1024 = rlimit_payload(1024, 1024);

    let script = vec![
        // 1. Create existing file with initial content "preserve" (8 bytes)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/preserve_host.txt",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .save(0),
        ),
        Step::Sys(sys::write(slot(0), b"preserve").ret(8)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        // 2. Set RLIMIT_NOFILE soft limit to 3 (stdio fds 0..2 occupy all 3 slots)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 3. Attempt open with O_TRUNC -> must fail with EMFILE
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/preserve_host.txt",
                (LINUX_O_TRUNC | LINUX_O_WRONLY) as i32,
                0,
            )
            .errno(LINUX_EMFILE),
        ),
        // 4. Restore soft limit to inspect file content
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_1024[..], 0).ret(0)),
        // 5. Open for read and verify content was preserved
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/preserve_host.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .save(1),
        ),
        Step::Sys(sys::read_tagged(slot(1), 8, "read_preserved").ret(8)),
        Step::Sys(sys::close(slot(1)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(
        run.output_tagged("read_preserved"),
        b"preserve",
        "host file content must not be truncated when openat is rejected by RLIMIT_NOFILE"
    );
}

// ============================================================================
// (2) No create on rejected open
// ============================================================================

/// Linux `openat(2)` with `O_CREAT` on a full descriptor table (memory filesystem).
///
/// Authority: `man 2 openat`, `man 2 getrlimit` (RLIMIT_NOFILE),
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.
///
/// When all descriptor slots are exhausted under `RLIMIT_NOFILE`, `openat(2)`
/// with `O_CREAT` for a non-existent path must fail with `EMFILE` without creating
/// the target file in the filesystem.
#[test]
fn test_memfs_open_rejected_by_rlimit_does_not_create_nonexistent_file() {
    let limit_3 = rlimit_payload(3, 1024);
    let limit_1024 = rlimit_payload(1024, 1024);

    let script = vec![
        // 1. Set RLIMIT_NOFILE soft limit to 3 (table full with stdio 0..2)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 2. Attempt open with O_CREAT for nonexistent path -> must fail with EMFILE
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/nonexistent_mem.txt",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .errno(LINUX_EMFILE),
        ),
        // 3. Restore soft limit to inspect filesystem state
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_1024[..], 0).ret(0)),
        // 4. Opening without O_CREAT must fail with ENOENT (file was never created)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/nonexistent_mem.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_ENOENT),
        ),
        // 5. Stat on the path must also fail with ENOENT
        Step::Sys(sys::newfstatat(LINUX_AT_FDCWD, "/nonexistent_mem.txt", 0).errno(LINUX_ENOENT)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `openat(2)` with `O_CREAT` on a full descriptor table (host filesystem).
///
/// Authority: `man 2 openat`, `man 2 getrlimit` (RLIMIT_NOFILE),
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.
///
/// When all descriptor slots are exhausted under `RLIMIT_NOFILE`, `openat(2)`
/// with `O_CREAT` on `HostFsBackend` must fail with `EMFILE` without creating
/// the host file on disk.
#[test]
fn test_hostfs_open_rejected_by_rlimit_does_not_create_nonexistent_file() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let limit_3 = rlimit_payload(3, 1024);
    let limit_1024 = rlimit_payload(1024, 1024);

    let script = vec![
        // 1. Set RLIMIT_NOFILE soft limit to 3 (table full with stdio 0..2)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 2. Attempt open with O_CREAT for nonexistent path -> must fail with EMFILE
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/nonexistent_host.txt",
                (LINUX_O_CREAT | LINUX_O_WRONLY) as i32,
                0o644,
            )
            .errno(LINUX_EMFILE),
        ),
        // 3. Restore soft limit to inspect filesystem state
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_1024[..], 0).ret(0)),
        // 4. Opening without O_CREAT must fail with ENOENT (file was never created)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/nonexistent_host.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_ENOENT),
        ),
        // 5. Stat on the path must also fail with ENOENT
        Step::Sys(sys::newfstatat(LINUX_AT_FDCWD, "/nonexistent_host.txt", 0).errno(LINUX_ENOENT)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

// ============================================================================
// (3) Full-table EMFILE before missing-path resolution
// ============================================================================

/// Linux `openat(2)` missing-path resolution ordering on full table (memory filesystem).
///
/// Authority: `man 2 openat`, `man 2 getrlimit` (RLIMIT_NOFILE),
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.
///
/// Under Linux, descriptor admission is verified before pathname resolution.
/// Opening a nonexistent file without `O_CREAT` on a full descriptor table
/// must return `EMFILE`, not `ENOENT`.
#[test]
fn test_memfs_open_full_table_returns_emfile_before_missing_path_resolution() {
    let limit_3 = rlimit_payload(3, 1024);

    let script = vec![
        // 1. Set RLIMIT_NOFILE soft limit to 3 (table full with stdio 0..2)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 2. Open nonexistent path without O_CREAT on full table -> must return EMFILE, not ENOENT
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/missing_mem_path.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_EMFILE),
        ),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `openat(2)` missing-path resolution ordering on full table (host filesystem).
///
/// Authority: `man 2 openat`, `man 2 getrlimit` (RLIMIT_NOFILE),
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/nofile-red.jsonl`.
///
/// Under Linux, descriptor admission is verified before pathname resolution.
/// Opening a nonexistent host path without `O_CREAT` on a full descriptor table
/// must return `EMFILE`, not `ENOENT`.
#[test]
fn test_hostfs_open_full_table_returns_emfile_before_missing_path_resolution() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let limit_3 = rlimit_payload(3, 1024);

    let script = vec![
        // 1. Set RLIMIT_NOFILE soft limit to 3 (table full with stdio 0..2)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 2. Open nonexistent host path without O_CREAT on full table -> must return EMFILE, not ENOENT
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/missing_host_path.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_EMFILE),
        ),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

// ============================================================================
// Passing guards / controls
// ============================================================================

/// Linux `close(2)`, `openat(2)`.
///
/// Authority: `man 2 close`, `man 2 openat` (lowest-numbered unused descriptor).
///
/// Closing a descriptor frees that slot in the descriptor table, allowing a
/// subsequent `openat(2)` to succeed and reuse the freed lowest slot.
#[test]
fn test_close_frees_descriptor_slot_for_subsequent_open() {
    let limit_3 = rlimit_payload(3, 1024);

    let script = vec![
        // 1. Set RLIMIT_NOFILE soft limit to 3 (stdio fds 0..2 occupy all 3 slots)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_3[..], 0).ret(0)),
        // 2. Close fd 0 -> free slot 0 (open fds: {1, 2}, count: 2 < 3)
        Step::Sys(sys::close(0).ret(0)),
        // 3. openat succeeds and reuses lowest available slot (fd 0)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/reuse_zero.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .ret(0),
        ),
        Step::Sys(sys::write(0, b"reused").ret(6)),
        Step::Sys(sys::close(0).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `openat(2)`.
///
/// Authority: `man 2 openat`.
///
/// A failed `openat(2)` (e.g. `ENOENT`) must not leak slot admission or increment
/// the allocator cursor; the next valid `openat(2)` must allocate the lowest
/// unused slot.
#[test]
fn test_failed_open_releases_admission_and_next_valid_open_uses_lowest_slot() {
    let limit_4 = rlimit_payload(4, 1024);

    let script = vec![
        // 1. Set soft limit to 4 (stdio 0..2 open; 1 slot free: fd 3)
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_4[..], 0).ret(0)),
        // 2. Failed open for nonexistent file (ENOENT)
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/definitely_does_not_exist.txt",
                LINUX_O_RDONLY as i32,
                0,
            )
            .errno(LINUX_ENOENT),
        ),
        // 3. Next valid open must successfully acquire fd 3
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/valid_file.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .ret(3),
        ),
        Step::Sys(sys::close(3).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `fork(2)`, `prlimit64(2)`, `openat(2)`.
///
/// Authority: `man 2 fork`, `man 2 prlimit64`.
///
/// Limits and descriptor tables on fork parent and child remain independent.
/// A child raising its soft limit and opening descriptors does not affect the parent's
/// descriptor limit or table.
#[test]
fn test_fork_preserves_independent_rlimits_and_descriptor_tables() {
    let limit_4 = rlimit_payload(4, 1024);
    let limit_1024 = rlimit_payload(1024, 1024);

    let script = vec![
        // 1. Parent sets limit to 4
        Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_4[..], 0).ret(0)),
        // 2. Parent opens fd 3 -> table full ({0, 1, 2, 3})
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/parent_held.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .ret(3),
        ),
        // 3. Parent forks child
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child raises its soft limit to 1024
            Step::Sys(sys::prlimit64(0, LINUX_RLIMIT_NOFILE, &limit_1024[..], 0).ret(0)),
            // Child opens additional descriptor at fd 4
            Step::Sys(
                sys::openat(
                    LINUX_AT_FDCWD,
                    "/child_opened.txt",
                    (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                    0o644,
                )
                .ret(4),
            ),
            Step::Sys(sys::close(4).ret(0)),
            Step::Sys(sys::close(3).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // 4. Parent waits for child
        Step::Sys(sys::wait4(last_child(), 0)),
        // 5. Parent still has limit 4 and fds 0..3 open -> next open yields EMFILE
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/parent_overflow.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .errno(LINUX_EMFILE),
        ),
        // 6. Parent closes fd 3 and opens new file -> gets fd 3
        Step::Sys(sys::close(3).ret(0)),
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/parent_next.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .ret(3),
        ),
        Step::Sys(sys::close(3).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

// ============================================================================
// (4) FIFO open descriptor reservation and dup2/dup3 EBUSY exclusion
// ============================================================================

/// Linux FIFO `openat(2)` slot reservation and `dup3(2)` / `dup2(2)` `EBUSY` exclusion.
///
/// Authority: Linux FIFO semantics, `man 2 dup2`, `man 2 openat`,
/// and Docker oracle `target/conformance/eco-fd-exec-20260917/fifo-reservation-oracle.log`.
///
/// When a thread blocks in `openat(2)` on a FIFO awaiting peer arrival:
/// 1. Its descriptor slot (e.g. fd 3) is reserved at admission time.
/// 2. Sibling threads attempting `dup2(oldfd, 3)` or `dup3(oldfd, 3, 0)` receive `EBUSY` (16).
/// 3. Other `openat(2)` calls allocate the next free slot (fd 4), skipping the reserved slot.
/// 4. When peer arrives (`openat` for write), the blocked thread wakes and completes with fd 3.
#[test]
fn test_fifo_open_parks_with_reserved_slot_and_rejects_dup2_ebusy() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        // 1. Create a FIFO
        Step::Sys(sys::mkfifo("/test_fifo", 0o666).ret(0)),
        // 2. Spawn sibling thread (tid 2)
        Step::Sys(sys::clone_thread(0).save(2)),
        Step::ChildMarker(vec![
            // Sibling thread opens FIFO for read (blocks awaiting peer writer) -> expects fd 3
            Step::Sys(sys::openat(LINUX_AT_FDCWD, "/test_fifo", LINUX_O_RDONLY as i32, 0).ret(3)),
            Step::Sys(sys::close(3).ret(0)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        // 3. Leader awaits sibling thread parking on openat
        await_parked(2, "openat"),
        // 4. Leader attempts dup3 to slot 3 -> must fail with EBUSY (16)
        Step::Sys(sys::dup3(0, 3, 0).errno(LINUX_EBUSY)),
        // 5. Leader opens regular file -> must skip reserved slot 3 and allocate slot 4
        Step::Sys(
            sys::openat(
                LINUX_AT_FDCWD,
                "/regular_file.txt",
                (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                0o644,
            )
            .ret(4),
        ),
        // 6. Leader opens FIFO for writing -> wakes sibling, leader gets slot 5
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/test_fifo", LINUX_O_WRONLY as i32, 0).ret(5)),
        // 7. Cleanup
        Step::Sys(sys::close(4).ret(0)),
        Step::Sys(sys::close(5).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux FIFO `openat(2)` cancellation releases reserved slot exactly once.
///
/// Authority: Linux FIFO semantics, `man 2 exit_group`.
///
/// When a thread blocking on FIFO open is cancelled or the process terminates,
/// the uncommitted slot reservation is rolled back cleanly without double-free
/// or leaked slot state.
#[test]
fn test_fifo_open_cancellation_releases_reservation_exactly_once() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        // 1. Fork a child process
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child creates FIFO
            Step::Sys(sys::mkfifo("/fifo_cancel", 0o666).ret(0)),
            // Child spawns sibling thread (tid 3)
            Step::Sys(sys::clone_thread(0).save(3)),
            Step::ChildMarker(vec![
                // Sibling thread parks on FIFO read open
                Step::Sys(sys::openat(
                    LINUX_AT_FDCWD,
                    "/fifo_cancel",
                    LINUX_O_RDONLY as i32,
                    0,
                )),
            ]),
            // Child leader awaits sibling parked on openat
            await_parked(3, "openat"),
            // Child leader confirms slot 3 is reserved via dup3 returning EBUSY
            Step::Sys(sys::dup3(0, 3, 0).errno(LINUX_EBUSY)),
            // Child leader issues exit_group(42), cancelling parked sibling open
            Step::Sys(sys::exit_group(42)),
        ]),
        // 2. Parent waits for child process
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}

/// Linux `fork(2)` during pending FIFO open does not propagate uncommitted reservations to child.
///
/// Authority: `man 2 fork`, Linux descriptor table semantics.
///
/// Uncommitted descriptor reservations belong only to the calling thread/process transaction;
/// fork copies only committed open file descriptions. A child created while a sibling thread
/// is parked in `openat` has an unreserved slot 3 and can allocate fd 3 immediately.
#[test]
fn test_fork_during_pending_fifo_open_allows_child_to_allocate_uncommitted_slot() {
    let scratch = tempfile::TempDir::new().unwrap();
    let host_backend = HostFsBackend::new_in(scratch.path()).unwrap();

    let script = vec![
        // 1. Create FIFO
        Step::Sys(sys::mkfifo("/fifo_fork", 0o666).ret(0)),
        // 2. Spawn sibling thread (tid 2)
        Step::Sys(sys::clone_thread(0).save(2)),
        Step::ChildMarker(vec![
            // Sibling parks in FIFO open
            Step::Sys(sys::openat(LINUX_AT_FDCWD, "/fifo_fork", LINUX_O_RDONLY as i32, 0).ret(3)),
            Step::Sys(sys::close(3).ret(0)),
            Step::Sys(sys::exit_thread(0)),
        ]),
        // 3. Leader awaits sibling parked on openat
        await_parked(2, "openat"),
        // 4. Leader confirms slot 3 is reserved in parent
        Step::Sys(sys::dup3(0, 3, 0).errno(LINUX_EBUSY)),
        // 5. Leader forks child process
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Child process must NOT have slot 3 reserved; child open allocates lowest slot (fd 3)
            Step::Sys(
                sys::openat(
                    LINUX_AT_FDCWD,
                    "/child_file.txt",
                    (LINUX_O_CREAT | LINUX_O_RDWR) as i32,
                    0o644,
                )
                .ret(3),
            ),
            Step::Sys(sys::close(3).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        // 6. Leader waits for child process
        Step::Sys(sys::wait4(last_child(), 0)),
        // 7. Leader opens FIFO for write -> wakes sibling, leader gets slot 4
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/fifo_fork", LINUX_O_WRONLY as i32, 0).ret(4)),
        Step::Sys(sys::close(4).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(host_backend))
        .run_root(script)
        .expect("backend ran");
    assert_eq!(run.exit_code(), 0);
}
