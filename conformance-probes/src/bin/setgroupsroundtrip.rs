//! `setgroups(2)` must replace the supplementary group set so a subsequent
//! `getgroups(2)` returns exactly what was set (and an empty set clears it).
//! CPython test_subprocess.test_extra_groups / test_extra_groups_empty_list
//! rely on this: the subprocess `extra_groups=` param calls setgroups() in the
//! pre-exec child, and the child's os.getgroups() must report those gids.
//!
//! Carrick's setgroups was a no-op (getgroups always derived groups from
//! /etc/group), so the set never round-tripped.
//!
//!  * groups_roundtrip: setgroups([100,200,300]) then getgroups == {100,200,300}
//!  * empty_clears:      setgroups([]) then getgroups returns 0 entries

use conformance_probes::report;

fn main() {
    unsafe {
        // Non-empty: set three gids, read them back as a set.
        let want: [libc::gid_t; 3] = [100, 200, 300];
        let set_rc = libc::setgroups(want.len(), want.as_ptr());
        let mut buf = [0 as libc::gid_t; 64];
        let n = libc::getgroups(buf.len() as i32, buf.as_mut_ptr());
        let mut got: Vec<libc::gid_t> = if n >= 0 {
            buf[..n as usize].to_vec()
        } else {
            Vec::new()
        };
        got.sort_unstable();
        let groups_roundtrip = set_rc == 0 && got == want;

        // Empty: clears the supplementary set.
        let empty: [libc::gid_t; 0] = [];
        let set_empty_rc = libc::setgroups(0, empty.as_ptr());
        let n2 = libc::getgroups(0, std::ptr::null_mut());
        let empty_clears = set_empty_rc == 0 && n2 == 0;

        report!(
            groups_roundtrip = groups_roundtrip,
            empty_clears = empty_clears
        );
    }
}
