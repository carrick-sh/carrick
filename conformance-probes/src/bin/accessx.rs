//! Access-family probe. Exercises access/faccessat/faccessat2 edge cases and
//! prints one labelled line per observation. The conformance harness runs this
//! identical static binary under carrick (--fs host, uid 0) and real arm64
//! Linux (ubuntu:24.04, root) and diffs line by line — a divergent line names
//! the exact failing check.
//!
//! The guest runs as ROOT (uid 0), so the expected values below encode root
//! semantics: root bypasses rwx permission bits on directories and for R_OK/
//! W_OK on regular files, but X_OK on a regular file still requires at least
//! one execute bit to be set (root is NOT exempt from that one rule).
//!
//! Deterministic only: booleans (rc==0) and errnos. No timestamps, pids,
//! addresses, inodes, or sizes.

use std::ffi::CString;

fn main() {
    // ---- Root-owned dirs/files: as root, R_OK/W_OK/X_OK all succeed. ----

    // access("/", R_OK|W_OK|X_OK) each separately. As root on a 0755 dir all
    // three succeed (root bypasses rwx on dirs that carry any perm bits, and
    // W_OK on a root-owned dir succeeds for root).
    println!("access_root_r={}", access("/", libc::R_OK));
    println!("access_root_w={}", access("/", libc::W_OK));
    println!("access_root_x={}", access("/", libc::X_OK));

    // access("/var/cache/apt", W_OK) — the exact check apt performs and the bug
    // under investigation. Root-owned dir → rc=0 for root.
    println!("access_varcacheapt_w={}", access("/var/cache/apt", libc::W_OK));

    // access("/etc", W_OK) and access("/usr", W_OK) — root-owned dirs → rc=0.
    println!("access_etc_w={}", access("/etc", libc::W_OK));
    println!("access_usr_w={}", access("/usr", libc::W_OK));

    // access("/etc/hostname", W_OK) — root-owned regular file → rc=0 for root.
    println!("access_hostname_w={}", access("/etc/hostname", libc::W_OK));

    // access("/etc/passwd", R_OK) — rc=0.
    println!("access_passwd_r={}", access("/etc/passwd", libc::R_OK));

    // faccessat(AT_FDCWD, "/var/cache/apt", W_OK, 0) and with AT_EACCESS —
    // both rc=0 for root.
    println!("faccessat_varcacheapt_w={}", faccessat("/var/cache/apt", libc::W_OK, 0));
    println!(
        "faccessat_varcacheapt_w_eaccess={}",
        faccessat("/var/cache/apt", libc::W_OK, libc::AT_EACCESS)
    );

    // faccessat2 (raw syscall) on "/var/cache/apt", W_OK, AT_EACCESS — rc=0.
    println!(
        "faccessat2_varcacheapt_w_eaccess={}",
        faccessat2("/var/cache/apt", libc::W_OK, libc::AT_EACCESS)
    );

    // ---- X_OK semantics: root still needs at least one execute bit. ----

    // access("/bin/sh", X_OK) — executable → rc=0.
    println!("access_sh_x={}", access("/bin/sh", libc::X_OK));

    // access("/etc/hostname", X_OK) — non-executable 0644 regular file. On
    // Linux, X_OK for root on a file with NO execute bits → EACCES(13).
    println!("access_hostname_x={}", access("/etc/hostname", libc::X_OK));

    // ---- Nonexistent / error paths. ----

    // access("/no/such/path", F_OK) — ENOENT(2).
    println!("access_missing_f={}", access("/no/such/path", libc::F_OK));

    // access("/no/such/path", R_OK) — ENOENT(2).
    println!("access_missing_r={}", access("/no/such/path", libc::R_OK));

    // access("/etc/hostname", F_OK) — rc=0.
    println!("access_hostname_f={}", access("/etc/hostname", libc::F_OK));

    // faccessat(AT_FDCWD, "/nonexistent", F_OK, 0) — ENOENT(2).
    println!("faccessat_missing_f={}", faccessat("/nonexistent", libc::F_OK, 0));

    // access with an invalid mode (mode=0xff) — EINVAL(22) on Linux.
    println!("access_invalid_mode={}", access("/etc/hostname", 0xff));
}

/// Render a result: "rc=N" on success (rc==0) else "ERR:<errno>".
fn rc_or_err(rc: i32) -> String {
    if rc == 0 {
        format!("rc={}", rc)
    } else {
        format!("ERR:{}", errno())
    }
}

/// access(2) returning a rendered result line value.
fn access(path: &str, mode: i32) -> String {
    let c = CString::new(path).unwrap();
    let rc = unsafe { libc::access(c.as_ptr(), mode) };
    rc_or_err(rc)
}

/// faccessat(2) returning a rendered result line value.
fn faccessat(path: &str, mode: i32, flags: i32) -> String {
    let c = CString::new(path).unwrap();
    let rc = unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), mode, flags) };
    rc_or_err(rc)
}

/// faccessat2(2) via raw syscall (no portable libc wrapper) — rendered result.
fn faccessat2(path: &str, mode: i32, flags: i32) -> String {
    let c = CString::new(path).unwrap();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD as libc::c_long,
            c.as_ptr() as libc::c_long,
            mode as libc::c_long,
            flags as libc::c_long,
        )
    };
    rc_or_err(rc as i32)
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
