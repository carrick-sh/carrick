//! Conformance probe for VFS mount read/write/readdir and cross-mount boundary semantics.
//!
//! Verifies from inside the guest:
//! 1. Creating and writing to a file on a mounted filesystem (/dev/shm).
//! 2. Reading back the written contents.
//! 3. Listing parent directory (/dev) and discovering the mount entry (shm).
//! 4. Attempting cross-mount rename (/dev/shm -> /tmp) returns EXDEV(18).
//! 5. Attempting cross-mount hard link (/dev/shm -> /tmp) returns EXDEV(18).
//! 6. Same-mount rename (/dev/shm -> /dev/shm) succeeds (rc=0).
//!
//! Deterministic output lines diffed against Linux oracle.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};

fn main() {
    let test_file = "/dev/shm/carrick_vfs_test.txt";
    let renamed_file = "/dev/shm/carrick_vfs_test_renamed.txt";
    let cross_target = "/tmp/carrick_cross_mount_target.txt";

    // 1. Create and write to mount-backed file
    let write_res = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(test_file)
        .and_then(|mut f| f.write_all(b"injected_mount_data_payload\n"));
    println!("write_mount_file={}", if write_res.is_ok() { "rc=0" } else { "ERR" });

    // 2. Read back written contents
    let mut buf = String::new();
    let read_res = File::open(test_file).and_then(|mut f| f.read_to_string(&mut buf));
    let read_matches = read_res.is_ok() && buf == "injected_mount_data_payload\n";
    println!("reread_mount_file={}", if read_matches { "rc=0" } else { "ERR" });

    // 3. List parent directory (/dev) and find the mount point entry (shm)
    let parent_readdir_has_mount = fs::read_dir("/dev")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|e| e.file_name() == "shm")
        })
        .unwrap_or(false);
    println!("parent_readdir_has_mount={parent_readdir_has_mount}");

    // 4. Attempt cross-mount rename: /dev/shm (tmpfs/mount) -> /tmp (rootfs)
    let c_src = CString::new(test_file).unwrap();
    let c_cross = CString::new(cross_target).unwrap();
    let c_renamed = CString::new(renamed_file).unwrap();

    let rename_cross_rc = unsafe { libc::rename(c_src.as_ptr(), c_cross.as_ptr()) };
    let rename_cross_errno = if rename_cross_rc != 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    } else {
        0
    };
    println!("cross_mount_rename_errno={rename_cross_errno}");

    // 5. Attempt cross-mount link: /dev/shm -> /tmp
    let link_cross_rc = unsafe { libc::link(c_src.as_ptr(), c_cross.as_ptr()) };
    let link_cross_errno = if link_cross_rc != 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
    } else {
        0
    };
    println!("cross_mount_link_errno={link_cross_errno}");

    // 6. Same-mount rename: /dev/shm -> /dev/shm
    let rename_same_rc = unsafe { libc::rename(c_src.as_ptr(), c_renamed.as_ptr()) };
    println!("same_mount_rename_rc={rename_same_rc}");

    // Cleanup
    let _ = fs::remove_file(renamed_file);
    let _ = fs::remove_file(test_file);
    let _ = fs::remove_file(cross_target);
}
