//! fd-stat vs path-stat consistency probe. Pins the invariant that
//! `fstat(fd)`, `fstatat(path)`, and `statx(fd, AT_EMPTY_PATH)` report the
//! SAME stat for the same file — size, mtime, mode, and inode all agree.
//!
//! Motivation: a carrick bug returned `st_mtime = 0` from `fstat(fd)` while
//! `statx(path)` returned the real mtime. apt's cache cross-check compares the
//! two and aborted install with "Cache is out of sync, can't x-ref a package
//! file". Fixed in cf6de43; this probe guards against regression.
//!
//! Deterministic only: prints BOOLEAN agreement of the three stat views (the
//! absolute mtimes differ between carrick and real Linux, so we never print a
//! raw mtime — except the ONE value we explicitly set via futimens, which is
//! deterministic by construction). On real Linux every boolean is `true`.

use std::ffi::CString;

/// The mtime we deliberately stamp on the file (a fixed epoch second). Both
/// carrick and real Linux must read this back identically.
const SET_MTIME: i64 = 1_700_000_000;

// musl's libc crate binding doesn't expose `statx`; issue the raw syscall
// (aarch64 nr 291) against a locally-declared struct mirroring the kernel's.
const SYS_STATX: libc::c_long = 291;
const STATX_ALL: u32 = 0x0fff; // request all basic fields
const AT_EMPTY_PATH: i32 = 0x1000;

#[repr(C)]
#[derive(Clone, Copy)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    _pad: i32,
}

#[repr(C)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    _spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    // Remaining device/spare fields are unused; pad to the full 256-byte
    // kernel statx struct so the kernel never writes past the buffer.
    _rest: [u8; 256 - 144],
}

fn main() {
    let path = "/tmp/fdstat_probe_file";
    let pc = CString::new(path).unwrap();

    // Fresh file: unlink any leftover, create, write known bytes.
    unsafe { libc::unlink(pc.as_ptr()) };
    let fd = unsafe {
        libc::open(
            pc.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        println!("open=ERR:{}", errno());
        return;
    }
    let payload = b"twelve-bytes";
    let w = unsafe { libc::write(fd, payload.as_ptr() as *const _, payload.len()) };
    if w != payload.len() as isize {
        println!("write=ERR:{}", errno());
    }
    // Flush metadata so path-stat and fd-stat observe the same size.
    unsafe { libc::fsync(fd) };

    // -- Observation 1: fstat(fd) == fstatat(path) ------------------------
    //
    // Stamp a known mtime FIRST (via futimens on the fd) so all three views
    // have a fixed, comparable timestamp regardless of wall-clock.
    let times = [
        libc::timespec { tv_sec: SET_MTIME, tv_nsec: 0 }, // atime
        libc::timespec { tv_sec: SET_MTIME, tv_nsec: 0 }, // mtime
    ];
    let ut = unsafe { libc::futimens(fd, times.as_ptr()) };
    if ut != 0 {
        println!("futimens=ERR:{}", errno());
    }

    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let frc = unsafe { libc::fstat(fd, &mut fst) };
    let mut pst: libc::stat = unsafe { std::mem::zeroed() };
    let prc = unsafe { libc::fstatat(libc::AT_FDCWD, pc.as_ptr(), &mut pst, 0) };

    if frc != 0 || prc != 0 {
        println!("fdstat_size_match=ERR:{}/{}", frc, prc);
        println!("fdstat_mtime_match=ERR");
        println!("fdstat_mode_match=ERR");
        println!("fdstat_ino_match=ERR");
    } else {
        println!("fdstat_size_match={}", fst.st_size == pst.st_size);
        println!("fdstat_mtime_match={}", fst.st_mtime == pst.st_mtime);
        println!("fdstat_mode_match={}", fst.st_mode == pst.st_mode);
        println!("fdstat_ino_match={}", fst.st_ino == pst.st_ino);
    }

    // -- Observation 2: fstat mtime reflects the set mtime ----------------
    //
    // Deterministic absolute value is fine here: WE chose SET_MTIME.
    println!("fdstat_mtime_is_set={}", fst.st_mtime as i64 == SET_MTIME);

    // -- Observation 3: statx(fd, AT_EMPTY_PATH) == fstat -----------------
    //
    // statx on the fd with an empty path + AT_EMPTY_PATH stats the open fd
    // itself; its mtime/size/ino must equal fstat's.
    let empty = CString::new("").unwrap();
    let mut stx: Statx = unsafe { std::mem::zeroed() };
    let xrc = unsafe {
        libc::syscall(
            SYS_STATX,
            fd,
            empty.as_ptr(),
            AT_EMPTY_PATH,
            STATX_ALL,
            &mut stx as *mut Statx,
        )
    };
    if xrc != 0 || frc != 0 {
        println!("statx_emptypath_mtime_match=ERR:{}", errno());
        println!("statx_emptypath_size_match=ERR");
        println!("statx_emptypath_ino_match=ERR");
    } else {
        println!(
            "statx_emptypath_mtime_match={}",
            stx.stx_mtime.tv_sec == fst.st_mtime as i64
        );
        println!(
            "statx_emptypath_size_match={}",
            stx.stx_size == fst.st_size as u64
        );
        println!(
            "statx_emptypath_ino_match={}",
            stx.stx_ino == fst.st_ino as u64
        );
    }

    unsafe { libc::close(fd) };
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
