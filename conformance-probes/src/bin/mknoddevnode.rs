//! mknod(2) device-node probe. Creates a character device and a block device
//! node in a tmpdir, then stat()s each and asserts the reported file TYPE,
//! permission bits, and major/minor device numbers; finally re-creates the
//! existing node and asserts EEXIST. The conformance harness runs this identical
//! static binary under carrick and real Linux and diffs line by line — a
//! divergent line names the exact failing behavior.
//!
//! Deterministic only: type/perms/major/minor constants and booleans, never raw
//! addresses, pids, inodes, or timestamps.

use std::ffi::CString;

fn main() {
    // The run-elf rootfs is empty, so make the tmpdir first (Docker's tmp
    // already exists; mkdir then reports EEXIST, which we ignore).
    mkdir("/tmp", 0o777);

    char_device();
    block_device();
    eexist();
}

/// mknod a character device with makedev(1, 3) (the Linux /dev/null pairing) and
/// stat it back: type must be S_IFCHR, perms the umask-free 0o644, major 1,
/// minor 3.
fn char_device() {
    let path = "/tmp/cdev";
    let rc = mknod(path, libc::S_IFCHR | 0o644, makedev(1, 3));
    if rc != 0 {
        println!("cdev_mknod=ERR:{}", errno());
        return;
    }
    let Some(st) = stat(path) else {
        println!("cdev_stat=ERR:{}", errno());
        return;
    };
    println!(
        "cdev_is_chr={}",
        (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
    );
    println!("cdev_perms={:o}", st.st_mode & 0o777);
    println!("cdev_major={}", libc::major(st.st_rdev));
    println!("cdev_minor={}", libc::minor(st.st_rdev));
}

/// mknod a block device with makedev(7, 0) (the Linux /dev/loop0 pairing) and
/// stat it back: type must be S_IFBLK, major 7, minor 0.
fn block_device() {
    let path = "/tmp/bdev";
    let rc = mknod(path, libc::S_IFBLK | 0o600, makedev(7, 0));
    if rc != 0 {
        println!("bdev_mknod=ERR:{}", errno());
        return;
    }
    let Some(st) = stat(path) else {
        println!("bdev_stat=ERR:{}", errno());
        return;
    };
    println!(
        "bdev_is_blk={}",
        (st.st_mode & libc::S_IFMT) == libc::S_IFBLK
    );
    println!("bdev_major={}", libc::major(st.st_rdev));
    println!("bdev_minor={}", libc::minor(st.st_rdev));
}

/// A second mknod of an existing node must fail with EEXIST.
fn eexist() {
    let rc = mknod("/tmp/cdev", libc::S_IFCHR | 0o644, makedev(1, 3));
    println!("cdev_eexist={}", rc < 0 && errno() == libc::EEXIST);
}

/// mknod(2) wrapper. Returns 0 on success, -1 on error (errno set).
fn mknod(path: &str, mode: libc::mode_t, dev: libc::dev_t) -> i32 {
    let Ok(c) = CString::new(path) else {
        return -1;
    };
    unsafe { libc::mknod(c.as_ptr(), mode, dev) }
}

/// mkdir(2) wrapper; failures (e.g. EEXIST) are ignored by the caller.
fn mkdir(path: &str, mode: libc::mode_t) {
    if let Ok(c) = CString::new(path) {
        unsafe {
            libc::mkdir(c.as_ptr(), mode);
        }
    }
}

/// stat(2) wrapper returning the filled `libc::stat`, or `None` on error.
fn stat(path: &str) -> Option<libc::stat> {
    let c = CString::new(path).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } == 0 {
        Some(st)
    } else {
        None
    }
}

/// Compose a Linux dev_t from major/minor via the libc makedev encoding.
fn makedev(major: u32, minor: u32) -> libc::dev_t {
    libc::makedev(major, minor)
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
