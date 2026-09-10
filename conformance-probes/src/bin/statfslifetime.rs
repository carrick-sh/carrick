//! statfslifetime probe.
//!
//! Verifies Linux statfs(2) and fstatfs(2) semantics:
//! 1. Consistency between path query (statfs) and open descriptor (fstatfs).
//! 2. Open file descriptor retains filesystem statistics and geometry after unlink(2).
//! 3. Descriptor retention across dup(2) and numeric fd reuse with a different mount.
//! 4. Synthetic descriptor geometry (pipe, socket).
//! 5. Error numbers for empty path, missing path, and bad fd.

use conformance_probes::errno;
use std::ffi::CString;

fn main() {
    let tmp_path = CString::new("/tmp/statfs_lifetime_test.txt").unwrap();

    // 1. Create a regular file in /tmp and compare statfs(path) with fstatfs(fd)
    let fd = unsafe {
        libc::open(
            tmp_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o644,
        )
    };
    println!("create_ok={}", fd >= 0);

    let mut st_path: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_path = unsafe { libc::statfs(tmp_path.as_ptr(), &mut st_path) };
    println!("statfs_path_ok={}", rc_path == 0);

    let mut st_fd: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_fd = unsafe { libc::fstatfs(fd, &mut st_fd) };
    println!("fstatfs_fd_ok={}", rc_fd == 0);

    println!("path_fd_type_match={}", st_path.f_type == st_fd.f_type);
    println!("path_fd_bsize_match={}", st_path.f_bsize == st_fd.f_bsize);
    println!("path_fd_blocks_match={}", st_path.f_blocks == st_fd.f_blocks);

    // 2. Unlink the file: statfs(path) becomes ENOENT, but fstatfs(fd) retains filesystem authority
    let rc_unlink = unsafe { libc::unlink(tmp_path.as_ptr()) };
    println!("unlink_ok={}", rc_unlink == 0);

    let mut st_unlinked_path: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_unlinked_path = unsafe { libc::statfs(tmp_path.as_ptr(), &mut st_unlinked_path) };
    let unlinked_statfs_errno = if rc_unlinked_path == -1 { errno() } else { 0 };
    println!("unlinked_statfs_errno={unlinked_statfs_errno}");

    let mut st_unlinked_fd: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_unlinked_fd = unsafe { libc::fstatfs(fd, &mut st_unlinked_fd) };
    println!("unlinked_fstatfs_ok={}", rc_unlinked_fd == 0);
    println!(
        "unlinked_fstatfs_type_match={}",
        st_unlinked_fd.f_type == st_fd.f_type
    );
    println!(
        "unlinked_fstatfs_blocks_match={}",
        st_unlinked_fd.f_blocks == st_fd.f_blocks
    );

    // 3. Dup and numeric fd reuse
    let dup_fd = unsafe { libc::dup(fd) };
    println!("dup_ok={}", dup_fd >= 0 && dup_fd != fd);

    unsafe { libc::close(fd) };

    // Open /proc/version which should reuse the lowest free numeric descriptor
    let proc_path = CString::new("/proc/version").unwrap();
    let proc_fd = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY) };
    println!("proc_open_ok={}", proc_fd >= 0);
    println!("proc_fd_reused={}", proc_fd == fd);

    let mut st_proc: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_proc = unsafe { libc::fstatfs(proc_fd, &mut st_proc) };
    let proc_fstatfs_errno = if rc_proc == -1 { errno() } else { 0 };
    println!("proc_fstatfs_errno={proc_fstatfs_errno}");

    let mut st_dup: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_dup = unsafe { libc::fstatfs(dup_fd, &mut st_dup) };
    let dup_fstatfs_errno = if rc_dup == -1 { errno() } else { 0 };
    println!("dup_fstatfs_errno={dup_fstatfs_errno}");

    println!("orig_f_type={:#x}", st_fd.f_type);
    println!("dup_f_type={:#x}", st_dup.f_type);
    println!("proc_f_type={:#x}", st_proc.f_type);
    println!("dup_retains_orig_type={}", st_dup.f_type == st_fd.f_type);
    println!("reused_fd_distinct_type={}", st_proc.f_type != st_dup.f_type);

    unsafe {
        libc::close(dup_fd);
        if proc_fd >= 0 {
            libc::close(proc_fd);
        }
    }

    // 4. Special descriptor filesystem types
    let mut pipe_fds = [0i32; 2];
    let pipe_rc = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
    let pipe_create_errno = if pipe_rc == -1 { errno() } else { 0 };
    println!("pipe_create_errno={pipe_create_errno}");
    if pipe_rc == 0 {
        let mut st_pipe: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstatfs(pipe_fds[0], &mut st_pipe) };
        let pipe_fstatfs_errno = if rc == -1 { errno() } else { 0 };
        println!("pipe_fstatfs_errno={pipe_fstatfs_errno}");
        println!("pipe_magic={:#x}", st_pipe.f_type);
        println!("pipe_blocks={}", st_pipe.f_blocks);
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
    }

    let sock_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    let sock_create_errno = if sock_fd < 0 { errno() } else { 0 };
    println!("sock_create_errno={sock_create_errno}");
    if sock_fd >= 0 {
        let mut st_sock: libc::statfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstatfs(sock_fd, &mut st_sock) };
        let sock_fstatfs_errno = if rc == -1 { errno() } else { 0 };
        println!("sock_fstatfs_errno={sock_fstatfs_errno}");
        println!("sock_magic={:#x}", st_sock.f_type);
        println!("sock_blocks={}", st_sock.f_blocks);
        unsafe { libc::close(sock_fd) };
    }

    // 5. Named FIFO descriptor filesystem types, unlinking, dup retention, and numeric reuse
    let fifo_path = CString::new("/tmp/statfs_lifetime_fifo").unwrap();
    let _ = unsafe { libc::unlink(fifo_path.as_ptr()) };
    let fifo_mk_rc = unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) };
    let fifo_mk_errno = if fifo_mk_rc == -1 { errno() } else { 0 };
    println!("fifo_mk_errno={fifo_mk_errno}");

    let fifo_fd = unsafe { libc::open(fifo_path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    let fifo_open_errno = if fifo_fd < 0 { errno() } else { 0 };
    println!("fifo_open_errno={fifo_open_errno}");
    if fifo_fd >= 0 {
        let mut st_fifo: libc::statfs = unsafe { std::mem::zeroed() };
        let rc_fifo = unsafe { libc::fstatfs(fifo_fd, &mut st_fifo) };
        let fifo_fstatfs_errno = if rc_fifo == -1 { errno() } else { 0 };
        println!("fifo_fstatfs_errno={fifo_fstatfs_errno}");
        println!("fifo_magic={:#x}", st_fifo.f_type);

        let fifo_dup_fd = unsafe { libc::dup(fifo_fd) };
        let fifo_dup_errno = if fifo_dup_fd < 0 { errno() } else { 0 };
        println!("fifo_dup_errno={fifo_dup_errno}");

        let rc_fifo_unlink = unsafe { libc::unlink(fifo_path.as_ptr()) };
        let fifo_unlink_errno = if rc_fifo_unlink == -1 { errno() } else { 0 };
        println!("fifo_unlink_errno={fifo_unlink_errno}");

        let mut st_fifo_unlinked: libc::statfs = unsafe { std::mem::zeroed() };
        let rc_fifo_unlinked = unsafe { libc::fstatfs(fifo_fd, &mut st_fifo_unlinked) };
        let fifo_unlinked_fstatfs_errno = if rc_fifo_unlinked == -1 { errno() } else { 0 };
        println!("fifo_unlinked_fstatfs_errno={fifo_unlinked_fstatfs_errno}");
        println!("fifo_unlinked_magic={:#x}", st_fifo_unlinked.f_type);

        unsafe { libc::close(fifo_fd) };

        let fifo_reuse_fd = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY) };
        println!("fifo_reuse_reused={}", fifo_reuse_fd == fifo_fd);

        if fifo_dup_fd >= 0 {
            let mut st_fifo_dup: libc::statfs = unsafe { std::mem::zeroed() };
            let rc_fifo_dup = unsafe { libc::fstatfs(fifo_dup_fd, &mut st_fifo_dup) };
            let fifo_dup_fstatfs_errno = if rc_fifo_dup == -1 { errno() } else { 0 };
            println!("fifo_dup_fstatfs_errno={fifo_dup_fstatfs_errno}");
            println!("fifo_dup_magic={:#x}", st_fifo_dup.f_type);
            println!(
                "fifo_dup_retains_magic={}",
                st_fifo_dup.f_type == st_fifo.f_type
            );
            unsafe { libc::close(fifo_dup_fd) };
        }

        if fifo_reuse_fd >= 0 {
            unsafe { libc::close(fifo_reuse_fd) };
        }
    }

    // 6. Error numbers
    let empty_path = CString::new("").unwrap();
    let mut st_err: libc::statfs = unsafe { std::mem::zeroed() };
    let rc_empty = unsafe { libc::statfs(empty_path.as_ptr(), &mut st_err) };
    let empty_path_errno = if rc_empty == -1 { errno() } else { 0 };
    println!("empty_path_errno={empty_path_errno}");

    let missing_path = CString::new("/nonexistent_path_statfs_probe").unwrap();
    let rc_missing = unsafe { libc::statfs(missing_path.as_ptr(), &mut st_err) };
    let missing_path_errno = if rc_missing == -1 { errno() } else { 0 };
    println!("missing_path_errno={missing_path_errno}");

    let rc_bad_fd = unsafe { libc::fstatfs(-1, &mut st_err) };
    let bad_fd_errno = if rc_bad_fd == -1 { errno() } else { 0 };
    println!("bad_fd_errno={bad_fd_errno}");

    let rc_bad_fd_high = unsafe { libc::fstatfs(999999, &mut st_err) };
    let bad_fd_high_errno = if rc_bad_fd_high == -1 { errno() } else { 0 };
    println!("bad_fd_high_errno={bad_fd_high_errno}");
}
