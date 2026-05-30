//! fd-stat vs path-stat INODE-IDENTITY probe (the `os.path.samestat` invariant).
//!
//! Python's `os.path.samestat(a, b)` is `a.st_ino == b.st_ino && a.st_dev ==
//! b.st_dev`. `shutil.rmtree` uses it as a security check: it `lstat`s the
//! directory and `fstat`s the fd it `open`ed, and refuses to recurse ("Cannot
//! call rmtree on a symbolic link") unless they're the same object. Under
//! `--fs host`, carrick derived a DIRECTORY fd's `st_ino` from a synthetic hash
//! of its path while a path-stat of the same directory reported the REAL host
//! inode, so `samestat(lstat(dir), fstat(open(dir)))` was False. rmtree then
//! never cleaned the tempdir and every later test setUp hit FileExistsError —
//! test_glob cascaded to 15 ERRORs. REGULAR FILES already agreed (they open as
//! a real host fd whose `fstat` reports the same inode).
//!
//! This probe pins the invariant for BOTH a directory and a regular file, plus
//! a symlink lstat/stat type check. On real Linux every boolean is `true`.
//!
//! Deterministic only: prints BOOLEAN `st_ino == st_ino && st_dev == st_dev`
//! agreement (never a raw inode/dev/size — those differ across machines).

use std::ffi::CString;

/// `os.path.samestat`: same inode AND same device.
fn samestat(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_ino == b.st_ino && a.st_dev == b.st_dev
}

fn main() {
    // -- Directory: fstat(open(dir)) must samestat lstat(dir) ----------------
    let dir = "/tmp/statfdino_probe_dir";
    let dc = CString::new(dir).unwrap();
    // Clean any leftover from a prior run, then create a fresh directory.
    unsafe { libc::rmdir(dc.as_ptr()) };
    let mk = unsafe { libc::mkdir(dc.as_ptr(), 0o755 as libc::c_uint) };
    if mk != 0 {
        println!("dir_setup=ERR:{}", errno());
        println!("dir_samestat=ERR");
    } else {
        let mut lst: libc::stat = unsafe { std::mem::zeroed() };
        let lrc = unsafe { libc::lstat(dc.as_ptr(), &mut lst) };
        let dfd = unsafe { libc::open(dc.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        let mut fst: libc::stat = unsafe { std::mem::zeroed() };
        let frc = if dfd >= 0 {
            unsafe { libc::fstat(dfd, &mut fst) }
        } else {
            -1
        };
        if lrc != 0 || dfd < 0 || frc != 0 {
            println!("dir_samestat=ERR:{}/{}/{}", lrc, dfd, frc);
        } else {
            println!("dir_samestat={}", samestat(&lst, &fst));
            // The directory's type bits must read S_IFDIR through both views.
            println!(
                "dir_isdir_both={}",
                (lst.st_mode & libc::S_IFMT) == libc::S_IFDIR
                    && (fst.st_mode & libc::S_IFMT) == libc::S_IFDIR
            );
        }
        if dfd >= 0 {
            unsafe { libc::close(dfd) };
        }
    }

    // -- Regular file: fstat(open(file)) must samestat lstat(file) -----------
    let file = "/tmp/statfdino_probe_file";
    let fc = CString::new(file).unwrap();
    unsafe { libc::unlink(fc.as_ptr()) };
    let wfd = unsafe {
        libc::open(
            fc.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644 as libc::c_uint,
        )
    };
    if wfd < 0 {
        println!("file_setup=ERR:{}", errno());
        println!("file_samestat=ERR");
    } else {
        let payload = b"hello";
        unsafe { libc::write(wfd, payload.as_ptr() as *const _, payload.len()) };
        unsafe { libc::fsync(wfd) };
        let mut lst: libc::stat = unsafe { std::mem::zeroed() };
        let lrc = unsafe { libc::lstat(fc.as_ptr(), &mut lst) };
        let mut fst: libc::stat = unsafe { std::mem::zeroed() };
        let frc = unsafe { libc::fstat(wfd, &mut fst) };
        if lrc != 0 || frc != 0 {
            println!("file_samestat=ERR:{}/{}", lrc, frc);
        } else {
            println!("file_samestat={}", samestat(&lst, &fst));
        }
        unsafe { libc::close(wfd) };
    }

    // -- Symlink: lstat reports the link, stat reports the target ------------
    //
    // Type-bit check only (no raw inode). lstat(link) must read S_IFLNK while
    // stat(link) follows to the regular-file target (S_IFREG). These two views
    // must NOT samestat each other (the link and its target are distinct
    // objects), pinning that the follow vs no-follow distinction is honoured.
    let link = "/tmp/statfdino_probe_link";
    let lc = CString::new(link).unwrap();
    unsafe { libc::unlink(lc.as_ptr()) };
    let sl = unsafe { libc::symlink(fc.as_ptr(), lc.as_ptr()) };
    if sl != 0 {
        println!("symlink_setup=ERR:{}", errno());
        println!("symlink_lstat_islnk=ERR");
        println!("symlink_stat_isreg=ERR");
        println!("symlink_distinct_from_target=ERR");
    } else {
        let mut llst: libc::stat = unsafe { std::mem::zeroed() };
        let llrc = unsafe { libc::lstat(lc.as_ptr(), &mut llst) };
        let mut lstt: libc::stat = unsafe { std::mem::zeroed() };
        let lstrc = unsafe { libc::stat(lc.as_ptr(), &mut lstt) };
        if llrc != 0 || lstrc != 0 {
            println!("symlink_lstat_islnk=ERR:{}/{}", llrc, lstrc);
            println!("symlink_stat_isreg=ERR");
            println!("symlink_distinct_from_target=ERR");
        } else {
            println!(
                "symlink_lstat_islnk={}",
                (llst.st_mode & libc::S_IFMT) == libc::S_IFLNK
            );
            println!(
                "symlink_stat_isreg={}",
                (lstt.st_mode & libc::S_IFMT) == libc::S_IFREG
            );
            // The link node and its followed target are different objects.
            println!("symlink_distinct_from_target={}", !samestat(&llst, &lstt));
        }
    }

    // Cleanup so a re-run starts fresh (best-effort; ignore errors).
    unsafe {
        libc::unlink(lc.as_ptr());
        libc::unlink(fc.as_ptr());
        libc::rmdir(dc.as_ptr());
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
