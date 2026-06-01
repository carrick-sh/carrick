//! `open(O_CREAT|O_EXCL)` on an existing DIRECTORY must fail with EEXIST (Linux:
//! O_EXCL "fail if the path already exists" takes priority over EISDIR). carrick
//! returned EISDIR for the writable-open-of-a-dir case before checking O_EXCL,
//! so CPython's tempfile.mkstemp retry-on-collision
//! (test_tempfile.test_collision_with_existing_directory) saw the wrong errno
//! and didn't retry.
//!
//!  * excl_existing_dir_eexist: open(<existing dir>, O_CREAT|O_EXCL|O_RDWR) → EEXIST

use conformance_probes::report;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    unsafe {
        let dir = b"/tmp/cr_excldir\0".as_ptr() as *const libc::c_char;
        libc::mkdir(dir, 0o755);
        let fd = libc::open(dir, libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o644);
        let excl_existing_dir_eexist = fd < 0 && errno() == libc::EEXIST;
        if fd >= 0 {
            libc::close(fd);
        }
        report!(excl_existing_dir_eexist = excl_existing_dir_eexist);
        libc::rmdir(dir);
    }
}
