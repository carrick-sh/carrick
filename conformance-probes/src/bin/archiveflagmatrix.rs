//! Filesystem archive, metadata, extended attributes, and directory stream matrix probe.
//!
//! Exercises Linux archive preparation, extraction, and inspection invariants across:
//! 1. `statfs(2)` and `fstatfs(2)` filesystem geometry and error handling (f_type, f_bsize,
//!    f_blocks, f_bfree, f_bavail, f_files, f_namelen, f_frsize, ENOENT on empty/missing, EBADF).
//! 2. `getdents64(2)` directory stream enumeration (DT_REG, DT_DIR, DT_LNK, DT_FIFO, d_reclen
//!    alignment, d_off progress, EOF, lseek rewind to entry 0, ENOTDIR on file, EINVAL on small buffer).
//! 3. Extended attributes (fsetxattr, fgetxattr, flistxattr, fremovexattr, lsetxattr, lgetxattr
//!    with XATTR_CREATE -> EEXIST, XATTR_REPLACE -> ENODATA, NULL size queries, ERANGE on small buffer,
//!    ENODATA on missing, EOPNOTSUPP on invalid namespace, EPERM on symlink user xattr).
//! 4. Archive hardlink, symlink, mode, and timestamp metadata (linkat with AT_SYMLINK_FOLLOW vs 0,
//!    linkat directory rejection -> EPERM, fchmodat symlink rejection -> EOPNOTSUPP, utimensat with
//!    UTIME_NOW/UTIME_OMIT combinations and AT_SYMLINK_NOFOLLOW, EINVAL on out-of-range nsec).
//! 5. FIFO and special node lifecycle (mkfifo, mknodat S_IFIFO/S_IFREG, non-blocking open read vs write,
//!    ENXIO on write without reader, EEXIST on duplicate creation).
//!
//! Compact table-driven structure reporting deterministic boolean and error observations.

use conformance_probes::{errno, report};
use std::ffi::CString;

const XATTR_CREATE: libc::c_int = 1;
const XATTR_REPLACE: libc::c_int = 2;

const AT_FDCWD: libc::c_int = -100;
const AT_SYMLINK_NOFOLLOW: libc::c_int = 0x100;
const AT_SYMLINK_FOLLOW: libc::c_int = 0x400;

const UTIME_NOW: libc::c_long = (1 << 30) - 1;
const UTIME_OMIT: libc::c_long = (1 << 30) - 2;

const DT_FIFO: u8 = 1;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
}

struct DirGuard(String);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// -----------------------------------------------------------------------------
// 1. statfs / fstatfs Filesystem Geometry & Flags Matrix
// -----------------------------------------------------------------------------

unsafe fn test_statfs_matrix(base: &str) {
    let tmp_path = CString::new("/tmp").unwrap();
    let mut st: libc::statfs = std::mem::zeroed();
    let r_statfs = libc::statfs(tmp_path.as_ptr(), &mut st);
    let err_statfs = if r_statfs == -1 { errno() } else { 0 };

    report!(
        statfs_tmp_rc = r_statfs,
        statfs_tmp_errno = err_statfs,
        statfs_tmp_ftype_nonzero = st.f_type != 0,
        statfs_tmp_bsize_positive = st.f_bsize > 0,
        statfs_tmp_blocks_positive = st.f_blocks > 0,
        statfs_tmp_namelen_ge_255 = st.f_namelen >= 255,
        statfs_tmp_frsize_positive = st.f_frsize > 0,
    );

    // 1.2 fstatfs on open file matches statfs
    let reg_path = CString::new(format!("{base}/statfs_file")).unwrap();
    let fd = libc::open(
        reg_path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    let open_ok = fd >= 0;
    let mut fst: libc::statfs = std::mem::zeroed();
    let r_fstatfs = if fd >= 0 {
        libc::fstatfs(fd, &mut fst)
    } else {
        -1
    };
    let err_fstatfs = if r_fstatfs == -1 { errno() } else { 0 };
    report!(
        fstatfs_regfile_open_ok = open_ok,
        fstatfs_regfile_rc = r_fstatfs,
        fstatfs_regfile_errno = err_fstatfs,
        fstatfs_regfile_match_type = fst.f_type == st.f_type,
        fstatfs_regfile_match_bsize = fst.f_bsize == st.f_bsize,
        fstatfs_regfile_match_namelen = fst.f_namelen == st.f_namelen,
        fstatfs_regfile_match_frsize = fst.f_frsize == st.f_frsize,
    );
    if fd >= 0 {
        libc::close(fd);
    }

    // 1.3 statfs on empty path -> ENOENT
    let empty_path = CString::new("").unwrap();
    let mut st_empty: libc::statfs = std::mem::zeroed();
    let r_empty = libc::statfs(empty_path.as_ptr(), &mut st_empty);
    let err_empty = if r_empty == -1 { errno() } else { 0 };
    report!(
        statfs_empty_path_rc = r_empty,
        statfs_empty_path_errno = err_empty,
    );

    // 1.4 statfs on non-existent path -> ENOENT
    let missing_path = CString::new(format!("{base}/nonexistent_statfs_path")).unwrap();
    let mut st_missing: libc::statfs = std::mem::zeroed();
    let r_missing = libc::statfs(missing_path.as_ptr(), &mut st_missing);
    let err_missing = if r_missing == -1 { errno() } else { 0 };
    report!(
        statfs_nonexistent_rc = r_missing,
        statfs_nonexistent_errno = err_missing,
    );

    // 1.5 fstatfs on bad fd -> EBADF
    let mut st_bad: libc::statfs = std::mem::zeroed();
    let r_bad_fd = libc::fstatfs(-1, &mut st_bad);
    let err_bad_fd = if r_bad_fd == -1 { errno() } else { 0 };
    report!(
        fstatfs_bad_fd_rc = r_bad_fd,
        fstatfs_bad_fd_errno = err_bad_fd,
    );
}

// -----------------------------------------------------------------------------
// 2. getdents64 Directory Stream Enumeration Matrix
// -----------------------------------------------------------------------------

unsafe fn test_getdents64_matrix(base: &str) {
    let dir_path = format!("{base}/dents_dir");
    let _ = std::fs::create_dir_all(&dir_path);

    let reg_path = format!("{dir_path}/file.txt");
    let sub_path = format!("{dir_path}/subdir");
    let lnk_path = format!("{dir_path}/symlink");
    let fifo_path = format!("{dir_path}/fifo_node");

    std::fs::write(&reg_path, b"content").ok();
    std::fs::create_dir(&sub_path).ok();
    std::os::unix::fs::symlink("file.txt", &lnk_path).ok();
    let c_fifo = CString::new(fifo_path.as_str()).unwrap();
    libc::mkfifo(c_fifo.as_ptr(), 0o644);

    let c_dir = CString::new(dir_path.as_str()).unwrap();
    let dir_fd = libc::open(c_dir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
    let dir_open_ok = dir_fd >= 0;
    report!(getdents64_open_dir_ok = dir_open_ok);
    if dir_fd < 0 {
        return;
    }

    let mut buf = [0u8; 2048];
    let n_read = libc::syscall(
        libc::SYS_getdents64,
        dir_fd as libc::c_long,
        buf.as_mut_ptr(),
        buf.len(),
    );
    let err_read = if n_read == -1 { errno() } else { 0 };

    let mut saw_reg = false;
    let mut saw_sub = false;
    let mut saw_lnk = false;
    let mut saw_fifo = false;
    let mut saw_dot = false;
    let mut saw_dotdot = false;
    let mut all_reclen_aligned = true;
    let mut off_progressive = true;
    let mut last_off = 0i64;

    if n_read > 0 {
        let mut pos = 0usize;
        let total = n_read as usize;
        while pos < total {
            let d = &*(buf.as_ptr().add(pos) as *const LinuxDirent64);
            let reclen = d.d_reclen as usize;
            if reclen == 0 || pos + reclen > total {
                break;
            }
            if reclen % 8 != 0 {
                all_reclen_aligned = false;
            }
            if d.d_off <= last_off && d.d_off != 0 {
                off_progressive = false;
            }
            last_off = d.d_off;

            let name_ptr = buf.as_ptr().add(pos + 19);
            let name_cstr = std::ffi::CStr::from_ptr(name_ptr as *const libc::c_char);
            let name = name_cstr.to_string_lossy();

            match name.as_ref() {
                "file.txt" => {
                    if d.d_type == DT_REG {
                        saw_reg = true;
                    }
                }
                "subdir" => {
                    if d.d_type == DT_DIR {
                        saw_sub = true;
                    }
                }
                "symlink" => {
                    if d.d_type == DT_LNK {
                        saw_lnk = true;
                    }
                }
                "fifo_node" => {
                    if d.d_type == DT_FIFO {
                        saw_fifo = true;
                    }
                }
                "." => {
                    if d.d_type == DT_DIR {
                        saw_dot = true;
                    }
                }
                ".." => {
                    if d.d_type == DT_DIR {
                        saw_dotdot = true;
                    }
                }
                _ => {}
            }

            pos += reclen;
        }
    }

    report!(
        getdents64_initial_nread_positive = n_read > 0,
        getdents64_initial_errno = err_read,
        getdents64_saw_dot_dir = saw_dot,
        getdents64_saw_dotdot_dir = saw_dotdot,
        getdents64_saw_file_reg = saw_reg,
        getdents64_saw_subdir_dir = saw_sub,
        getdents64_saw_symlink_lnk = saw_lnk,
        getdents64_saw_fifo_node = saw_fifo,
        getdents64_all_reclen_aligned = all_reclen_aligned,
        getdents64_off_progressive = off_progressive,
    );

    // 2.2 Reaching EOF returns 0
    let n_eof = libc::syscall(
        libc::SYS_getdents64,
        dir_fd as libc::c_long,
        buf.as_mut_ptr(),
        buf.len(),
    );
    let err_eof = if n_eof == -1 { errno() } else { 0 };
    report!(getdents64_eof_rc = n_eof, getdents64_eof_errno = err_eof,);

    // 2.3 Rewind via lseek(0, SEEK_SET) and re-read
    let r_seek = libc::lseek(dir_fd, 0, libc::SEEK_SET);
    let err_seek = if r_seek == -1 { errno() } else { 0 };
    let n_rewound = libc::syscall(
        libc::SYS_getdents64,
        dir_fd as libc::c_long,
        buf.as_mut_ptr(),
        buf.len(),
    );
    let err_rewound = if n_rewound == -1 { errno() } else { 0 };
    report!(
        getdents64_lseek_rewind_rc = r_seek,
        getdents64_lseek_rewind_errno = err_seek,
        getdents64_rewound_nread_positive = n_rewound > 0,
        getdents64_rewound_errno = err_rewound,
    );

    // 2.4 getdents64 on regular file -> ENOTDIR
    let reg_c = CString::new(reg_path.as_str()).unwrap();
    let reg_fd = libc::open(reg_c.as_ptr(), libc::O_RDONLY);
    let (r_notdir, err_notdir) = if reg_fd >= 0 {
        let r = libc::syscall(
            libc::SYS_getdents64,
            reg_fd as libc::c_long,
            buf.as_mut_ptr(),
            buf.len(),
        );
        let err = if r == -1 { errno() } else { 0 };
        libc::close(reg_fd);
        (r, err)
    } else {
        (-1, errno())
    };
    report!(
        getdents64_on_file_rc = r_notdir,
        getdents64_on_file_errno = err_notdir,
    );

    // 2.5 getdents64 on bad fd -> EBADF
    let r_bad_fd = libc::syscall(
        libc::SYS_getdents64,
        -1 as libc::c_long,
        buf.as_mut_ptr(),
        buf.len(),
    );
    let err_bad_fd = if r_bad_fd == -1 { errno() } else { 0 };
    report!(
        getdents64_bad_fd_rc = r_bad_fd,
        getdents64_bad_fd_errno = err_bad_fd,
    );

    // 2.6 Buffer too small for even one dirent -> EINVAL
    let mut small_buf = [0u8; 1];
    let r_small = libc::syscall(
        libc::SYS_getdents64,
        dir_fd as libc::c_long,
        small_buf.as_mut_ptr(),
        1,
    );
    let err_small = if r_small == -1 { errno() } else { 0 };
    report!(
        getdents64_short_buf_rc = r_small,
        getdents64_short_buf_errno = err_small,
    );

    libc::close(dir_fd);
}

// -----------------------------------------------------------------------------
// 3. Extended Attributes Matrix (fsetxattr, fgetxattr, flistxattr, fremovexattr, lsetxattr)
// -----------------------------------------------------------------------------

unsafe fn test_xattr_matrix(base: &str) {
    let file_path = CString::new(format!("{base}/xattr_target")).unwrap();
    let fd = libc::open(
        file_path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    let target_open_ok = fd >= 0;
    report!(xattr_target_open_ok = target_open_ok);
    if fd < 0 {
        return;
    }

    let attr_name = CString::new("user.arch_meta").unwrap();
    let attr_val1 = b"archive_payload_v1";

    // 3.1 Initial set with flags = 0
    let r_set0 = libc::fsetxattr(
        fd,
        attr_name.as_ptr(),
        attr_val1.as_ptr().cast(),
        attr_val1.len(),
        0,
    );
    let err_set0 = if r_set0 == -1 { errno() } else { 0 };
    report!(
        fsetxattr_initial_rc = r_set0,
        fsetxattr_initial_errno = err_set0,
    );

    // 3.2 XATTR_CREATE on already existing attr -> EEXIST
    let attr_val2 = b"archive_payload_v2";
    let r_create_dup = libc::fsetxattr(
        fd,
        attr_name.as_ptr(),
        attr_val2.as_ptr().cast(),
        attr_val2.len(),
        XATTR_CREATE,
    );
    let err_create_dup = if r_create_dup == -1 { errno() } else { 0 };
    report!(
        fsetxattr_create_existing_rc = r_create_dup,
        fsetxattr_create_existing_errno = err_create_dup,
    );

    // 3.3 XATTR_REPLACE on missing attr -> ENODATA
    let missing_name = CString::new("user.arch_nonexistent").unwrap();
    let r_repl_miss = libc::fsetxattr(
        fd,
        missing_name.as_ptr(),
        attr_val2.as_ptr().cast(),
        attr_val2.len(),
        XATTR_REPLACE,
    );
    let err_repl_miss = if r_repl_miss == -1 { errno() } else { 0 };
    report!(
        fsetxattr_replace_missing_rc = r_repl_miss,
        fsetxattr_replace_missing_errno = err_repl_miss,
    );

    // 3.4 XATTR_REPLACE on existing attr -> success
    let r_repl_ok = libc::fsetxattr(
        fd,
        attr_name.as_ptr(),
        attr_val2.as_ptr().cast(),
        attr_val2.len(),
        XATTR_REPLACE,
    );
    let err_repl_ok = if r_repl_ok == -1 { errno() } else { 0 };
    report!(
        fsetxattr_replace_existing_rc = r_repl_ok,
        fsetxattr_replace_existing_errno = err_repl_ok,
    );

    // 3.5 Query value size with NULL buffer and size = 0
    let size_query = libc::fgetxattr(fd, attr_name.as_ptr(), core::ptr::null_mut(), 0);
    let err_size_query = if size_query == -1 { errno() } else { 0 };
    report!(
        fgetxattr_size_query_val = size_query,
        fgetxattr_size_query_errno = err_size_query,
    );

    // 3.6 Buffer too small -> ERANGE
    let mut small_buf = [0u8; 4];
    let r_erange = libc::fgetxattr(
        fd,
        attr_name.as_ptr(),
        small_buf.as_mut_ptr().cast(),
        small_buf.len(),
    );
    let err_erange = if r_erange == -1 { errno() } else { 0 };
    report!(
        fgetxattr_buffer_too_small_rc = r_erange,
        fgetxattr_buffer_too_small_errno = err_erange,
    );

    // 3.7 Exact readback
    let mut get_buf = [0u8; 64];
    let r_get = libc::fgetxattr(
        fd,
        attr_name.as_ptr(),
        get_buf.as_mut_ptr().cast(),
        get_buf.len(),
    );
    let err_get = if r_get == -1 { errno() } else { 0 };
    report!(
        fgetxattr_readback_rc = r_get,
        fgetxattr_readback_errno = err_get,
        fgetxattr_readback_payload_matches =
            r_get == attr_val2.len() as isize && &get_buf[..attr_val2.len()] == attr_val2,
    );

    // 3.8 flistxattr size query and list content
    let list_size = libc::flistxattr(fd, core::ptr::null_mut(), 0);
    let err_list_size = if list_size == -1 { errno() } else { 0 };
    let mut list_buf = vec![
        0u8;
        if list_size > 0 {
            list_size as usize
        } else {
            64
        }
    ];
    let r_list = libc::flistxattr(fd, list_buf.as_mut_ptr().cast(), list_buf.len());
    let err_list = if r_list == -1 { errno() } else { 0 };
    let has_name = r_list > 0
        && list_buf[..r_list as usize]
            .split(|&b| b == 0)
            .any(|s| s == b"user.arch_meta");
    report!(
        flistxattr_size_query_val = list_size,
        flistxattr_size_query_errno = err_list_size,
        flistxattr_fetch_rc = r_list,
        flistxattr_fetch_errno = err_list,
        flistxattr_contains_name = has_name,
    );

    // 3.9 flistxattr with short buffer -> ERANGE
    let r_list_small = libc::flistxattr(fd, small_buf.as_mut_ptr().cast(), 1);
    let err_list_small = if r_list_small == -1 { errno() } else { 0 };
    report!(
        flistxattr_short_buf_rc = r_list_small,
        flistxattr_short_buf_errno = err_list_small,
    );

    // 3.10 fremovexattr missing attr -> ENODATA
    let r_rm_miss = libc::fremovexattr(fd, missing_name.as_ptr());
    let err_rm_miss = if r_rm_miss == -1 { errno() } else { 0 };
    report!(
        fremovexattr_missing_rc = r_rm_miss,
        fremovexattr_missing_errno = err_rm_miss,
    );

    // 3.11 fremovexattr existing attr -> success
    let r_rm_ok = libc::fremovexattr(fd, attr_name.as_ptr());
    let err_rm_ok = if r_rm_ok == -1 { errno() } else { 0 };
    let r_get_after = libc::fgetxattr(
        fd,
        attr_name.as_ptr(),
        get_buf.as_mut_ptr().cast(),
        get_buf.len(),
    );
    let err_get_after = if r_get_after == -1 { errno() } else { 0 };
    report!(
        fremovexattr_existing_rc = r_rm_ok,
        fremovexattr_existing_errno = err_rm_ok,
        fgetxattr_after_remove_rc = r_get_after,
        fgetxattr_after_remove_errno = err_get_after,
    );

    // 3.12 Invalid namespace -> EOPNOTSUPP
    let bad_ns = CString::new("invalid_ns.attr").unwrap();
    let r_bad_ns = libc::fsetxattr(
        fd,
        bad_ns.as_ptr(),
        attr_val1.as_ptr().cast(),
        attr_val1.len(),
        0,
    );
    let err_bad_ns = if r_bad_ns == -1 { errno() } else { 0 };
    report!(
        fsetxattr_invalid_ns_rc = r_bad_ns,
        fsetxattr_invalid_ns_errno = err_bad_ns,
    );

    // 3.13 Bad fd -> EBADF
    let r_bad_fd = libc::fsetxattr(
        -1,
        attr_name.as_ptr(),
        attr_val1.as_ptr().cast(),
        attr_val1.len(),
        0,
    );
    let err_bad_fd = if r_bad_fd == -1 { errno() } else { 0 };
    report!(
        fsetxattr_bad_fd_rc = r_bad_fd,
        fsetxattr_bad_fd_errno = err_bad_fd,
    );

    // 3.14 Symlink user xattr rejection -> EPERM on Linux
    let symlink_path = format!("{base}/xattr_symlink");
    let c_symlink = CString::new(symlink_path.as_str()).unwrap();
    std::os::unix::fs::symlink(file_path.to_str().unwrap(), &symlink_path).ok();
    let r_sym_xattr = libc::lsetxattr(
        c_symlink.as_ptr(),
        attr_name.as_ptr(),
        attr_val1.as_ptr().cast(),
        attr_val1.len(),
        0,
    );
    let err_sym_xattr = if r_sym_xattr == -1 { errno() } else { 0 };
    report!(
        lsetxattr_symlink_user_rc = r_sym_xattr,
        lsetxattr_symlink_user_errno = err_sym_xattr,
    );

    libc::close(fd);
}

// -----------------------------------------------------------------------------
// 4. Archive Hardlink, Symlink, Mode & Timestamp Matrix
// -----------------------------------------------------------------------------

unsafe fn test_archive_meta_matrix(base: &str) {
    let target_path = format!("{base}/link_target");
    let symlink_path = format!("{base}/link_symlink");
    let hardlink_follow = format!("{base}/link_hard_follow");
    let hardlink_nofollow = format!("{base}/link_hard_nofollow");
    let dir_path = format!("{base}/link_dir");

    std::fs::write(&target_path, b"link_content").ok();
    std::os::unix::fs::symlink("link_target", &symlink_path).ok();
    std::fs::create_dir(&dir_path).ok();

    let c_target = CString::new(target_path.as_str()).unwrap();
    let c_symlink = CString::new(symlink_path.as_str()).unwrap();
    let c_follow = CString::new(hardlink_follow.as_str()).unwrap();
    let c_nofollow = CString::new(hardlink_nofollow.as_str()).unwrap();
    let c_dir = CString::new(dir_path.as_str()).unwrap();

    // 4.1 linkat with AT_SYMLINK_FOLLOW links to target regular file
    let r_follow = libc::linkat(
        AT_FDCWD,
        c_symlink.as_ptr(),
        AT_FDCWD,
        c_follow.as_ptr(),
        AT_SYMLINK_FOLLOW,
    );
    let err_follow = if r_follow == -1 { errno() } else { 0 };
    let mut st_follow: libc::stat = std::mem::zeroed();
    libc::lstat(c_follow.as_ptr(), &mut st_follow);
    let follow_is_reg = (st_follow.st_mode & libc::S_IFMT) == libc::S_IFREG;
    report!(
        linkat_symlink_follow_rc = r_follow,
        linkat_symlink_follow_errno = err_follow,
        linkat_symlink_follow_target_is_reg = follow_is_reg,
    );

    // 4.2 linkat with flags = 0 links to symlink itself
    let r_nofollow = libc::linkat(
        AT_FDCWD,
        c_symlink.as_ptr(),
        AT_FDCWD,
        c_nofollow.as_ptr(),
        0,
    );
    let err_nofollow = if r_nofollow == -1 { errno() } else { 0 };
    let mut st_nofollow: libc::stat = std::mem::zeroed();
    libc::lstat(c_nofollow.as_ptr(), &mut st_nofollow);
    let nofollow_is_lnk = (st_nofollow.st_mode & libc::S_IFMT) == libc::S_IFLNK;
    report!(
        linkat_symlink_nofollow_rc = r_nofollow,
        linkat_symlink_nofollow_errno = err_nofollow,
        linkat_symlink_nofollow_target_is_lnk = nofollow_is_lnk,
    );

    // 4.3 linkat on directory -> EPERM
    let dummy_link = CString::new(format!("{base}/dummy_dir_link")).unwrap();
    let r_dir_link = libc::linkat(AT_FDCWD, c_dir.as_ptr(), AT_FDCWD, dummy_link.as_ptr(), 0);
    let err_dir_link = if r_dir_link == -1 { errno() } else { 0 };
    report!(
        linkat_directory_rc = r_dir_link,
        linkat_directory_errno = err_dir_link,
    );

    // 4.4 fchmodat with AT_SYMLINK_NOFOLLOW -> EOPNOTSUPP on Linux
    let r_chmod_sym = libc::fchmodat(AT_FDCWD, c_symlink.as_ptr(), 0o644, AT_SYMLINK_NOFOLLOW);
    let err_chmod_sym = if r_chmod_sym == -1 { errno() } else { 0 };
    report!(
        fchmodat_symlink_nofollow_rc = r_chmod_sym,
        fchmodat_symlink_nofollow_errno = err_chmod_sym,
    );

    // 4.5 utimensat with UTIME_NOW and UTIME_OMIT combinations
    let ts_now_omit = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
    ];
    let r_utime1 = libc::utimensat(AT_FDCWD, c_target.as_ptr(), ts_now_omit.as_ptr(), 0);
    let err_utime1 = if r_utime1 == -1 { errno() } else { 0 };

    let ts_omit_now = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        },
    ];
    let r_utime2 = libc::utimensat(AT_FDCWD, c_target.as_ptr(), ts_omit_now.as_ptr(), 0);
    let err_utime2 = if r_utime2 == -1 { errno() } else { 0 };
    report!(
        utimensat_atime_now_mtime_omit_rc = r_utime1,
        utimensat_atime_now_mtime_omit_errno = err_utime1,
        utimensat_atime_omit_mtime_now_rc = r_utime2,
        utimensat_atime_omit_mtime_now_errno = err_utime2,
    );

    // 4.6 utimensat on symlink with AT_SYMLINK_NOFOLLOW
    let r_utime_sym = libc::utimensat(
        AT_FDCWD,
        c_symlink.as_ptr(),
        ts_now_omit.as_ptr(),
        AT_SYMLINK_NOFOLLOW,
    );
    let err_utime_sym = if r_utime_sym == -1 { errno() } else { 0 };
    report!(
        utimensat_symlink_nofollow_rc = r_utime_sym,
        utimensat_symlink_nofollow_errno = err_utime_sym,
    );

    // 4.7 utimensat invalid tv_nsec (1_000_000_000) -> EINVAL
    let ts_invalid = [
        libc::timespec {
            tv_sec: 1000,
            tv_nsec: 1_000_000_000,
        },
        libc::timespec {
            tv_sec: 1000,
            tv_nsec: 0,
        },
    ];
    let r_utime_bad = libc::utimensat(AT_FDCWD, c_target.as_ptr(), ts_invalid.as_ptr(), 0);
    let err_utime_bad = if r_utime_bad == -1 { errno() } else { 0 };
    report!(
        utimensat_invalid_nsec_rc = r_utime_bad,
        utimensat_invalid_nsec_errno = err_utime_bad,
    );
}

// -----------------------------------------------------------------------------
// 5. FIFO and Special Node Lifecycle
// -----------------------------------------------------------------------------

unsafe fn test_fifo_node_matrix(base: &str) {
    let fifo1_path = format!("{base}/fifo_test1");
    let fifo2_path = format!("{base}/fifo_test2");
    let c_fifo1 = CString::new(fifo1_path.as_str()).unwrap();
    let c_fifo2 = CString::new(fifo2_path.as_str()).unwrap();

    // 5.1 mkfifo creates FIFO with exact mode & S_ISFIFO
    let r_mkfifo = libc::mkfifo(c_fifo1.as_ptr(), 0o640);
    let err_mkfifo = if r_mkfifo == -1 { errno() } else { 0 };
    let mut st_fifo: libc::stat = std::mem::zeroed();
    libc::lstat(c_fifo1.as_ptr(), &mut st_fifo);
    let is_fifo = (st_fifo.st_mode & libc::S_IFMT) == libc::S_IFIFO;
    let mode_ok = (st_fifo.st_mode & 0o777) == 0o640;
    report!(
        mkfifo_rc = r_mkfifo,
        mkfifo_errno = err_mkfifo,
        mkfifo_is_fifo = is_fifo,
        mkfifo_mode_0640 = mode_ok,
        mkfifo_size_zero = st_fifo.st_size == 0,
    );

    // 5.2 open(FIFO, O_RDONLY | O_NONBLOCK) succeeds even without writer
    let r_fd = libc::open(c_fifo1.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
    let err_r_fd = if r_fd == -1 { errno() } else { 0 };
    report!(
        open_fifo_rdonly_nonblock_ok = r_fd >= 0,
        open_fifo_rdonly_nonblock_errno = err_r_fd,
    );
    if r_fd >= 0 {
        libc::close(r_fd);
    }

    // 5.3 open(FIFO, O_WRONLY | O_NONBLOCK) fails with ENXIO when no reader exists
    let r_mk2 = libc::mkfifo(c_fifo2.as_ptr(), 0o644);
    let err_mk2 = if r_mk2 == -1 { errno() } else { 0 };
    let w_fd = libc::open(c_fifo2.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
    let err_w = if w_fd == -1 { errno() } else { 0 };
    report!(
        mkfifo_for_writer_rc = r_mk2,
        mkfifo_for_writer_errno = err_mk2,
        open_fifo_wronly_nonblock_no_reader_rc = if w_fd >= 0 { 0 } else { -1 },
        open_fifo_wronly_nonblock_no_reader_errno = err_w,
    );
    if w_fd >= 0 {
        libc::close(w_fd);
    }

    // 5.4 mknodat with S_IFIFO creates FIFO
    let fifo3_path = CString::new(format!("{base}/fifo_mknod")).unwrap();
    let r_mknod_fifo = libc::mknodat(AT_FDCWD, fifo3_path.as_ptr(), libc::S_IFIFO | 0o644, 0);
    let err_mknod_fifo = if r_mknod_fifo == -1 { errno() } else { 0 };
    let mut st_mknod: libc::stat = std::mem::zeroed();
    libc::lstat(fifo3_path.as_ptr(), &mut st_mknod);
    report!(
        mknodat_fifo_rc = r_mknod_fifo,
        mknodat_fifo_errno = err_mknod_fifo,
        mknodat_fifo_is_fifo = (st_mknod.st_mode & libc::S_IFMT) == libc::S_IFIFO,
        mknodat_fifo_mode_0644 = (st_mknod.st_mode & 0o777) == 0o644,
    );

    // 5.5 mknodat with S_IFREG creates regular file
    let reg_mknod_path = CString::new(format!("{base}/reg_mknod")).unwrap();
    let r_mknod_reg = libc::mknodat(AT_FDCWD, reg_mknod_path.as_ptr(), libc::S_IFREG | 0o644, 0);
    let err_mknod_reg = if r_mknod_reg == -1 { errno() } else { 0 };
    let mut st_reg_mknod: libc::stat = std::mem::zeroed();
    libc::lstat(reg_mknod_path.as_ptr(), &mut st_reg_mknod);
    report!(
        mknodat_reg_rc = r_mknod_reg,
        mknodat_reg_errno = err_mknod_reg,
        mknodat_reg_is_reg = (st_reg_mknod.st_mode & libc::S_IFMT) == libc::S_IFREG,
        mknodat_reg_mode_0644 = (st_reg_mknod.st_mode & 0o777) == 0o644,
    );

    // 5.6 mknodat on existing path -> EEXIST
    let r_mknod_dup = libc::mknodat(AT_FDCWD, reg_mknod_path.as_ptr(), libc::S_IFREG | 0o644, 0);
    let err_mknod_dup = if r_mknod_dup == -1 { errno() } else { 0 };
    report!(
        mknodat_existing_rc = r_mknod_dup,
        mknodat_existing_errno = err_mknod_dup,
    );
}

// -----------------------------------------------------------------------------
// Main Entrypoint
// -----------------------------------------------------------------------------

fn main() {
    let pid = unsafe { libc::getpid() };
    let base = format!("/tmp/archiveflagmatrix_{pid}");
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::create_dir_all(&base);
    let _guard = DirGuard(base.clone());

    unsafe {
        test_statfs_matrix(&base);
        test_getdents64_matrix(&base);
        test_xattr_matrix(&base);
        test_archive_meta_matrix(&base);
        test_fifo_node_matrix(&base);
    }
}
