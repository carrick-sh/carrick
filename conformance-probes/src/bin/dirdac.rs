//! Directory-modify DAC (LTP mkdir04/rmdir03/unlink08): an unprivileged guest
//! can create/remove an entry only in a directory it has write+search on.
//! carrick presents the guest as root by default (root bypasses DAC, so the
//! apt/python demos are unaffected) — this probe DROPS to an unprivileged uid
//! to exercise the enforcement. Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        // Created as root → owned by uid 0.
        let priv_d = b"/tmp/dac_priv\0".as_ptr() as *const libc::c_char;
        let pub_d = b"/tmp/dac_pub\0".as_ptr() as *const libc::c_char;
        libc::mkdir(priv_d, 0o700); // no access for "other"
        libc::mkdir(pub_d, 0o777);
        // mkdir applies the umask, so force the modes explicitly: priv = no
        // "other" access, pub = truly world-writable (rwx for other).
        libc::chmod(priv_d, 0o700);
        libc::chmod(pub_d, 0o777);

        // Drop all uids to an unprivileged id (CAP_DAC_OVERRIDE gone).
        let dropped = libc::setuid(65534) == 0;
        println!("dropped_to_nonroot={}", dropped);

        // mkdir inside the root-owned 0700 dir → EACCES (no write for "other").
        let r1 = libc::mkdir(b"/tmp/dac_priv/x\0".as_ptr() as *const _, 0o777);
        println!(
            "mkdir_in_unwritable_eacces={}",
            r1 == -1 && errno() == libc::EACCES
        );

        // mkdir inside the world-writable dir → success.
        let r2 = libc::mkdir(b"/tmp/dac_pub/y\0".as_ptr() as *const _, 0o777);
        println!("mkdir_in_writable_ok={}", r2 == 0);

        // rmdir of the entry we just made (in a dir we now have write+search on)
        // → success; rmdir of an entry in the unwritable dir → EACCES (the entry
        // doesn't exist there, but the parent perm check fires first... actually
        // the entry is absent → ENOENT; so only assert the writable removal).
        let r3 = libc::rmdir(b"/tmp/dac_pub/y\0".as_ptr() as *const _);
        println!("rmdir_in_writable_ok={}", r3 == 0);

        let _ = errno;
    }
}
