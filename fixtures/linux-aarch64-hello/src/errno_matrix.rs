#![no_main]
#![no_std]

#[path = "abi.rs"]
mod abi;

use abi::*;

static EXISTING: [u8; 10] = *b"/etc/motd\0";
static MISSING: [u8; 13] = *b"/etc/missing\0";
static FRESH_DIR: [u8; 13] = *b"/etc/new-dir\0";
static FRESH_LINK: [u8; 14] = *b"/etc/new-link\0";
static TARGET: [u8; 7] = *b"target\0";
static EMPTY: [u8; 1] = *b"\0";
static MESSAGE: [u8; 13] = *b"errno_matrix\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // mknodat: 33
        if syscall4(
            SYS_MKNODAT,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
            0o100644,
            0,
        ) != EEXIST
        {
            exit(5);
        }
        if syscall4(
            SYS_MKNODAT,
            AT_FDCWD,
            FRESH_LINK.as_ptr() as u64,
            0o100644,
            0,
        ) != EROFS
        {
            exit(6);
        }

        // mkdirat: 34
        if syscall3(SYS_MKDIRAT, AT_FDCWD, EXISTING.as_ptr() as u64, 0o755) != EEXIST {
            exit(10);
        }
        if syscall3(SYS_MKDIRAT, AT_FDCWD, FRESH_DIR.as_ptr() as u64, 0o755) != EROFS {
            exit(11);
        }
        if syscall3(SYS_MKDIRAT, AT_FDCWD, EMPTY.as_ptr() as u64, 0o755) != ENOENT {
            exit(12);
        }

        // unlinkat: 35
        if syscall3(SYS_UNLINKAT, AT_FDCWD, EXISTING.as_ptr() as u64, 0) != EROFS {
            exit(20);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, MISSING.as_ptr() as u64, 0) != ENOENT {
            exit(21);
        }
        if syscall3(SYS_UNLINKAT, AT_FDCWD, EXISTING.as_ptr() as u64, AT_REMOVEDIR) != ENOTDIR {
            exit(22);
        }

        // symlinkat: 36
        if syscall3(
            SYS_SYMLINKAT,
            TARGET.as_ptr() as u64,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
        ) != EEXIST
        {
            exit(30);
        }
        if syscall3(
            SYS_SYMLINKAT,
            TARGET.as_ptr() as u64,
            AT_FDCWD,
            FRESH_LINK.as_ptr() as u64,
        ) != EROFS
        {
            exit(31);
        }

        // linkat: 37
        if syscall5(
            SYS_LINKAT,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
            AT_FDCWD,
            FRESH_LINK.as_ptr() as u64,
            0,
        ) != EROFS
        {
            exit(40);
        }
        if syscall5(
            SYS_LINKAT,
            AT_FDCWD,
            MISSING.as_ptr() as u64,
            AT_FDCWD,
            FRESH_LINK.as_ptr() as u64,
            0,
        ) != ENOENT
        {
            exit(41);
        }
        if syscall5(
            SYS_LINKAT,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
            0,
        ) != EEXIST
        {
            exit(42);
        }

        // renameat: 38
        if syscall4(
            SYS_RENAMEAT,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
            AT_FDCWD,
            FRESH_LINK.as_ptr() as u64,
        ) != EROFS
        {
            exit(50);
        }
        if syscall4(
            SYS_RENAMEAT,
            AT_FDCWD,
            MISSING.as_ptr() as u64,
            AT_FDCWD,
            FRESH_LINK.as_ptr() as u64,
        ) != ENOENT
        {
            exit(51);
        }

        // truncate: 45
        if syscall2(SYS_TRUNCATE, EXISTING.as_ptr() as u64, 0) != EROFS {
            exit(60);
        }
        if syscall2(SYS_TRUNCATE, MISSING.as_ptr() as u64, 0) != ENOENT {
            exit(61);
        }
        if syscall2(SYS_TRUNCATE, EXISTING.as_ptr() as u64, (-1_i64) as u64) != EINVAL {
            exit(62);
        }

        // ftruncate: 46 (stdio is non-truncatable)
        if syscall2(SYS_FTRUNCATE, 1, 0) != EINVAL {
            exit(70);
        }
        if syscall2(SYS_FTRUNCATE, 999, 0) != EBADF {
            exit(71);
        }

        // fallocate: 47 (stdio is non-seekable)
        if syscall4(SYS_FALLOCATE, 1, 0, 0, 4096) != ESPIPE {
            exit(75);
        }
        if syscall4(SYS_FALLOCATE, 999, 0, 0, 4096) != EBADF {
            exit(76);
        }
        if syscall4(SYS_FALLOCATE, 1, 0, 0, 0) != EINVAL {
            exit(77);
        }

        // fchmod: 52
        if syscall2(SYS_FCHMOD, 1, 0o644) != EROFS {
            exit(80);
        }
        if syscall2(SYS_FCHMOD, 999, 0o644) != EBADF {
            exit(81);
        }

        // fchmodat: 53
        if syscall4(SYS_FCHMODAT, AT_FDCWD, EXISTING.as_ptr() as u64, 0o644, 0) != EROFS {
            exit(90);
        }
        if syscall4(SYS_FCHMODAT, AT_FDCWD, MISSING.as_ptr() as u64, 0o644, 0) != ENOENT {
            exit(91);
        }

        // fchown: 55
        if syscall3(SYS_FCHOWN, 1, 0, 0) != EROFS {
            exit(100);
        }
        if syscall3(SYS_FCHOWN, 999, 0, 0) != EBADF {
            exit(101);
        }

        // fchownat: 54
        if syscall5(
            SYS_FCHOWNAT,
            AT_FDCWD,
            EXISTING.as_ptr() as u64,
            0,
            0,
            0,
        ) != EROFS
        {
            exit(110);
        }
        if syscall5(
            SYS_FCHOWNAT,
            AT_FDCWD,
            MISSING.as_ptr() as u64,
            0,
            0,
            0,
        ) != ENOENT
        {
            exit(111);
        }

        // utimensat: 88 (NULL times = no-op for valid path)
        if syscall4(SYS_UTIMENSAT, AT_FDCWD, EXISTING.as_ptr() as u64, 0, 0) != EROFS {
            exit(120);
        }
        if syscall4(SYS_UTIMENSAT, AT_FDCWD, MISSING.as_ptr() as u64, 0, 0) != ENOENT {
            exit(121);
        }

        // sync / fsync / fdatasync: 81 / 82 / 83
        if syscall0(SYS_SYNC) != 0 {
            exit(130);
        }
        if syscall1(SYS_FSYNC, 1) != 0 {
            exit(131);
        }
        if syscall1(SYS_FSYNC, 999) != EBADF {
            exit(132);
        }
        if syscall1(SYS_FDATASYNC, 2) != 0 {
            exit(133);
        }

        // pwrite64 / pwritev: 68 / 70 (stdio is non-seekable)
        let payload: [u8; 4] = *b"data";
        if syscall4(
            SYS_PWRITE64,
            1,
            payload.as_ptr() as u64,
            payload.len() as u64,
            0,
        ) != ESPIPE
        {
            exit(140);
        }

        let wrote = syscall3(SYS_WRITE, 1, MESSAGE.as_ptr() as u64, MESSAGE.len() as u64);
        if wrote != MESSAGE.len() as i64 {
            exit(150);
        }
        exit(0);
    }
}
