//! SECURITY INVARIANT (regression guard for the --fs host cap-std bypass):
//! a guest must NOT be able to read the CONTENT of a host file outside its rootfs
//! via a symlink. The dangerous vector for an openat(root_fd, rel)+F_GETPATH fast
//! path is an INTERMEDIATE symlink to an absolute host dir: O_NOFOLLOW only guards
//! the FINAL component, so the kernel traverses the intermediate symlink and a
//! naive bypass would read the host file. cap-std prevents it via per-component
//! resolution; the fast path must preserve it (F_GETPATH containment → reject).
//!
//! We assert on CONTENT, not open-success: carrick may open a leaf abs-symlink and
//! return the target path string (a benign quirk) — that is NOT an escape. Escape
//! == the read bytes contain the macOS SystemVersion.plist marker. On Linux the
//! host paths don't exist, so nothing is read → contained. Both sides: contained.
//!
//!  * intermediate_symlink_no_host_read: reading "/tmp/d/SystemVersion.plist" via
//!    an intermediate symlink d -> /System/Library/CoreServices yields no host data
//!  * leaf_symlink_no_host_read: same via a leaf symlink straight to the plist

use conformance_probes::report;

/// Returns true iff NO host-file content leaked (contained).
fn no_host_read(linkname: &[u8], target: &[u8], openpath: &[u8]) -> bool {
    unsafe {
        libc::unlink(linkname.as_ptr() as *const libc::c_char);
        let _ = libc::symlink(
            target.as_ptr() as *const libc::c_char,
            linkname.as_ptr() as *const libc::c_char,
        );
        let fd = libc::open(openpath.as_ptr() as *const libc::c_char, libc::O_RDONLY);
        let mut leaked = false;
        if fd >= 0 {
            let mut buf = [0u8; 256];
            let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if n > 0 {
                let s = &buf[..n as usize];
                // macOS SystemVersion.plist markers.
                leaked = s.windows(18).any(|w| w == b"ProductBuildVersion")
                    || s.windows(5).any(|w| w == b"<?xml")
                    || s.windows(14).any(|w| w == b"ProductVersion");
            }
            libc::close(fd);
        }
        libc::unlink(linkname.as_ptr() as *const libc::c_char);
        !leaked
    }
}

fn main() {
    let inter = no_host_read(
        b"/tmp/escguard_d\0",
        b"/System/Library/CoreServices\0",
        b"/tmp/escguard_d/SystemVersion.plist\0",
    );
    let leaf = no_host_read(
        b"/tmp/escguard_f\0",
        b"/System/Library/CoreServices/SystemVersion.plist\0",
        b"/tmp/escguard_f\0",
    );
    report!(
        intermediate_symlink_no_host_read = inter,
        leaf_symlink_no_host_read = leaf
    );
}
