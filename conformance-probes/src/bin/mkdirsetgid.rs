//! setgid-directory inheritance (LTP mkdir02): a directory created inside a
//! parent with the S_ISGID bit set inherits the parent's GID and itself gets
//! S_ISGID. carrick previously gave the new dir the creator's egid and dropped
//! S_ISGID. Deterministic booleans, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let parent = b"/tmp/sgp\0".as_ptr() as *const libc::c_char;
        libc::rmdir(b"/tmp/sgp/c\0".as_ptr() as *const _);
        libc::rmdir(parent);
        libc::mkdir(parent, 0o755);
        // Set the parent's group to a fixed GID and turn on S_ISGID.
        libc::chown(parent, u32::MAX, 100);
        libc::chmod(parent, 0o2755);

        let child = b"/tmp/sgp/c\0".as_ptr() as *const libc::c_char;
        let rc = libc::mkdir(child, 0o755);
        println!("mkdir_child_ok={}", rc == 0);

        let mut st: libc::stat = std::mem::zeroed();
        let strc = libc::stat(child, &mut st);
        println!("stat_ok={}", strc == 0);
        println!("child_gid_inherited_100={}", st.st_gid == 100);
        println!("child_has_setgid={}", st.st_mode & 0o2000 != 0);

        let _ = errno;
        libc::rmdir(child);
        libc::rmdir(parent);
    }
}
