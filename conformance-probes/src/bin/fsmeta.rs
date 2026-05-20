//! Filesystem metadata probe. Exercises stat/access/readlink/getcwd-family
//! syscalls and prints one labelled line per observation. The conformance
//! harness runs this identical static binary under carrick and real Linux
//! and diffs line by line — a divergent line names the exact failing syscall.
//!
//! Deterministic only: no timestamps, pids, addresses, or inode numbers.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn main() {
    // getcwd via std (exercises getcwd(2)).
    std::env::set_current_dir("/tmp").ok();
    fs::create_dir_all("/tmp/probe/a/b").ok();
    std::env::set_current_dir("/tmp/probe/a/b").ok();
    match std::env::current_dir() {
        Ok(p) => println!("getcwd={}", p.display()),
        Err(e) => println!("getcwd=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // stat /etc/passwd (size + mode + is_file).
    match fs::metadata("/etc/passwd") {
        Ok(m) => println!(
            "stat_passwd size={} mode={:o} file={}",
            m.len(),
            m.permissions().mode() & 0o7777,
            m.is_file()
        ),
        Err(e) => println!("stat_passwd=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // symlink_metadata of a known symlink (if any) — use /bin (often a symlink).
    match fs::symlink_metadata("/bin") {
        Ok(m) => println!("lstat_bin symlink={} dir={}", m.file_type().is_symlink(), m.is_dir()),
        Err(e) => println!("lstat_bin=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // access() family via faccessat: readable/writable/executable as root.
    println!("access_passwd_r={}", access("/etc/passwd", libc::R_OK));
    println!("access_passwd_w={}", access("/etc/passwd", libc::W_OK));
    println!("access_sh_x={}", access("/bin/sh", libc::X_OK));
    println!("access_missing={}", access("/no/such/path", libc::F_OK));

    // create + stat a fresh file (mode after umask), then chmod, re-stat.
    fs::write("/tmp/probe/f", b"hello").ok();
    if let Ok(m) = fs::metadata("/tmp/probe/f") {
        println!("newfile size={} mode={:o}", m.len(), m.permissions().mode() & 0o7777);
    }
    fs::set_permissions("/tmp/probe/f", fs::Permissions::from_mode(0o640)).ok();
    if let Ok(m) = fs::metadata("/tmp/probe/f") {
        println!("chmod640 mode={:o}", m.permissions().mode() & 0o7777);
    }

    // symlink create + readlink.
    std::os::unix::fs::symlink("/etc/passwd", "/tmp/probe/lnk").ok();
    match fs::read_link("/tmp/probe/lnk") {
        Ok(t) => println!("readlink={}", t.display()),
        Err(e) => println!("readlink=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // rename then confirm source gone / dest present.
    fs::write("/tmp/probe/r1", b"x").ok();
    fs::rename("/tmp/probe/r1", "/tmp/probe/r2").ok();
    println!(
        "rename src_exists={} dst_exists={}",
        fs::metadata("/tmp/probe/r1").is_ok(),
        fs::metadata("/tmp/probe/r2").is_ok()
    );
}

fn access(path: &str, mode: i32) -> i32 {
    let c = std::ffi::CString::new(path).unwrap();
    unsafe { libc::access(c.as_ptr(), mode) }
}
