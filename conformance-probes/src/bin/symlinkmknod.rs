//! mknod through a symlink path component must follow the link WITHIN the
//! guest rootfs, exactly like real Linux: `ln -s /tmp/sm_real /tmp/sm_link;
//! mkfifo /tmp/sm_link/f` lands a FIFO at /tmp/sm_real/f.
//!
//! carrick's host backend creates a FIFO via a raw mkfifoat/fchmodat on the
//! cap-std scratch dir fd. BEFORE that raw call, the mknodat dispatch path runs
//! a parent-directory check: `path_is_directory(parent)` (dispatch/fs/pathres.rs)
//! consults `overlay.lookup(parent)`, and HostBackend::lookup uses a NO-FOLLOW
//! `symlink_metadata`, so a symlink parent comes back as OverlayEntry::File
//! (fs_backend.rs:966-971) -> path_is_directory returns false -> mknodat returns
//! ENOENT (dispatch/fs.rs:4543) before the raw call ever runs. So a contained
//! mknod-through-symlink that Linux accepts is over-rejected. The booleans
//! diverge exactly on that gap; `contained_consistent` stays true on both sides
//! (carrick over-rejects rather than escaping — the containment invariant holds).
//!
//! Deterministic: umask(0) fixes the mode; everything lives under /tmp; no
//! blocking calls (no FIFO is opened, only mknod/stat/lstat). Re-runnable
//! (cleanup unlinks/rmdirs first).

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::umask(0);
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        libc::unlink(b"/tmp/sm_real/f\0".as_ptr() as *const libc::c_char);
        libc::rmdir(b"/tmp/sm_real\0".as_ptr() as *const libc::c_char);
        libc::unlink(b"/tmp/sm_link\0".as_ptr() as *const libc::c_char);

        let made_real = libc::mkdir(b"/tmp/sm_real\0".as_ptr() as *const libc::c_char, 0o777) == 0;
        let made_link = libc::symlink(
            b"/tmp/sm_real\0".as_ptr() as *const libc::c_char,
            b"/tmp/sm_link\0".as_ptr() as *const libc::c_char,
        ) == 0;
        println!("setup_real_dir={}", made_real);
        println!("setup_abs_symlink={}", made_link);

        let via = b"/tmp/sm_link/f\0".as_ptr() as *const libc::c_char;
        let rc = libc::mknod(via, libc::S_IFIFO | 0o644, 0);
        println!("mknod_via_symlink_ok={}", rc == 0);
        println!("mknod_via_symlink_enoent={}", rc == -1 && errno() == libc::ENOENT);

        let mut st: libc::stat = std::mem::zeroed();
        let at_target = libc::lstat(b"/tmp/sm_real/f\0".as_ptr() as *const libc::c_char, &mut st);
        println!(
            "fifo_at_target_in_rootfs={}",
            at_target == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO
        );

        let mut st2: libc::stat = std::mem::zeroed();
        let via_link = libc::stat(via, &mut st2);
        println!(
            "fifo_via_symlink_path={}",
            via_link == 0 && (st2.st_mode & libc::S_IFMT) == libc::S_IFIFO
        );

        // Containment invariant: a successful mknod must materialise the node at
        // the (followed) in-rootfs target. Stays true on BOTH sides — carrick
        // over-rejects (rc!=0, no node) rather than escaping; Linux succeeds with
        // a node at the target. It is the containment guarantee, not the
        // divergence (the divergence is the four lines above).
        println!(
            "contained_consistent={}",
            (rc == 0) == (at_target == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFIFO)
        );
    }
}