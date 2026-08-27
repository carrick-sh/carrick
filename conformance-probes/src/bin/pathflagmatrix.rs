//! Path flag and error semantics matrix probe.
//!
//! Exercises Linux flag validation, invalid/conflicting flag interactions, and
//! path-resolution error invariants across `openat2`, `statx`, `fstatat`,
//! `renameat2`, `unlinkat`, `faccessat2`, `fchownat`, and `utimensat`.
//!
//! Compact table-driven structure reporting deterministic boolean observations.

use conformance_probes::errno;
use std::ffi::CString;

const SYS_OPENAT2: libc::c_long = 437;
const SYS_STATX: libc::c_long = libc::SYS_statx;
const SYS_RENAMEAT2: libc::c_long = libc::SYS_renameat2;
const SYS_FACCESSAT2: libc::c_long = libc::SYS_faccessat2;

const AT_FDCWD: libc::c_int = -100;
const AT_SYMLINK_NOFOLLOW: libc::c_int = 0x100;
const AT_REMOVEDIR: libc::c_int = 0x200;
const AT_SYMLINK_FOLLOW: libc::c_int = 0x400;
const AT_NO_AUTOMOUNT: libc::c_int = 0x800;
const AT_EMPTY_PATH: libc::c_int = 0x1000;
const AT_STATX_FORCE_SYNC: libc::c_int = 0x2000;
const AT_STATX_DONT_SYNC: libc::c_int = 0x4000;

const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;

const RENAME_NOREPLACE: libc::c_uint = 1;
const RENAME_EXCHANGE: libc::c_uint = 2;
const RENAME_WHITEOUT: libc::c_uint = 4;

const STATX_BASIC_STATS: u32 = 0x07ff;
const STATX_RESERVED: u32 = 0x8000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    _pad: i32,
}

#[repr(C)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    _spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    _rest: [u8; 256 - 144],
}

fn openat2(
    dfd: libc::c_int,
    path: *const libc::c_char,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> libc::c_long {
    let how = [flags, mode, resolve];
    unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dfd as libc::c_long,
            path,
            how.as_ptr(),
            24usize,
        )
    }
}

fn statx(
    dfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mask: u32,
    stx: &mut Statx,
) -> libc::c_long {
    unsafe {
        libc::syscall(
            SYS_STATX,
            dfd as libc::c_long,
            path,
            flags as libc::c_long,
            mask as libc::c_long,
            stx as *mut Statx,
        )
    }
}

fn renameat2(
    olddfd: libc::c_int,
    oldpath: *const libc::c_char,
    newdfd: libc::c_int,
    newpath: *const libc::c_char,
    flags: libc::c_uint,
) -> libc::c_long {
    unsafe {
        libc::syscall(
            SYS_RENAMEAT2,
            olddfd as libc::c_long,
            oldpath,
            newdfd as libc::c_long,
            newpath,
            flags as libc::c_long,
        )
    }
}

fn faccessat2(
    dfd: libc::c_int,
    path: *const libc::c_char,
    mode: libc::c_int,
    flags: libc::c_int,
) -> libc::c_long {
    unsafe {
        libc::syscall(
            SYS_FACCESSAT2,
            dfd as libc::c_long,
            path,
            mode as libc::c_long,
            flags as libc::c_long,
        )
    }
}

fn make_regfile(path: &str, content: &[u8]) {
    let c = CString::new(path).unwrap();
    unsafe {
        libc::unlink(c.as_ptr());
        let fd = libc::open(
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            if !content.is_empty() {
                libc::write(fd, content.as_ptr() as *const libc::c_void, content.len());
            }
            libc::close(fd);
        }
    }
}

fn make_dir(path: &str) {
    let c = CString::new(path).unwrap();
    unsafe {
        libc::mkdir(c.as_ptr(), 0o755);
    }
}

fn make_symlink(target: &str, link: &str) {
    let t = CString::new(target).unwrap();
    let l = CString::new(link).unwrap();
    unsafe {
        libc::unlink(l.as_ptr());
        libc::symlink(t.as_ptr(), l.as_ptr());
    }
}

struct CleanGuard<'a>(&'a str);
impl<'a> Drop for CleanGuard<'a> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0);
    }
}

fn main() {
    let pid = unsafe { libc::getpid() };
    let base = format!("/tmp/pathflagmatrix_{pid}");

    // Wipe any existing residue for this PID before starting setup.
    let _ = std::fs::remove_dir_all(&base);
    let _guard = CleanGuard(&base);

    make_dir("/tmp");
    make_dir(&base);

    let regfile_path = format!("{base}/regfile");
    let missing_path = format!("{base}/missing");
    let dangling_link = format!("{base}/dangling_link");
    let valid_link = format!("{base}/valid_link");
    let dir_link = format!("{base}/dir_link");
    let empty_dir = format!("{base}/empty_dir");
    let nonempty_dir = format!("{base}/nonempty_dir");
    let nonempty_sub = format!("{base}/nonempty_dir/subfile");

    make_regfile(&regfile_path, b"testdata");
    make_symlink(&missing_path, &dangling_link);
    make_symlink(&regfile_path, &valid_link);
    make_dir(&empty_dir);
    make_dir(&nonempty_dir);
    make_regfile(&nonempty_sub, b"inner");
    make_symlink(&empty_dir, &dir_link);

    let reg_c = CString::new(regfile_path.as_str()).unwrap();
    let empty_c = CString::new("").unwrap();
    let dangling_c = CString::new(dangling_link.as_str()).unwrap();
    let empty_dir_c = CString::new(empty_dir.as_str()).unwrap();
    let nonempty_dir_c = CString::new(nonempty_dir.as_str()).unwrap();
    let dir_link_c = CString::new(dir_link.as_str()).unwrap();

    let reg_fd = unsafe { libc::open(reg_c.as_ptr(), libc::O_RDONLY) };
    let base_dir_fd = unsafe {
        libc::open(
            CString::new(base.as_str()).unwrap().as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
    };

    // ------------------------------------------------------------------------
    // 1. openat2 Flag Combinations & Resolve Invariants
    // ------------------------------------------------------------------------
    let o_path = libc::O_PATH as u64;
    let o_rdwr = libc::O_RDWR as u64;
    let o_wronly = libc::O_WRONLY as u64;
    let o_rdonly = libc::O_RDONLY as u64;
    let o_creat = libc::O_CREAT as u64;
    let o_trunc = libc::O_TRUNC as u64;
    let o_tmpfile = libc::O_TMPFILE as u64;

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_path | o_rdwr, 0, 0);
    println!(
        "openat2_opath_rdwr_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_path | o_wronly, 0, 0);
    println!(
        "openat2_opath_wronly_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_path | o_creat, 0o644, 0);
    println!(
        "openat2_opath_creat_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_path | o_trunc, 0, 0);
    println!(
        "openat2_opath_trunc_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(
        AT_FDCWD,
        empty_dir_c.as_ptr(),
        o_path | o_tmpfile | o_wronly,
        0o644,
        0,
    );
    println!(
        "openat2_opath_tmpfile_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_rdonly | (1u64 << 62), 0, 0);
    println!(
        "openat2_unknown_flag_bits_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(
        AT_FDCWD,
        empty_dir_c.as_ptr(),
        o_rdonly | o_tmpfile,
        0o644,
        0,
    );
    println!(
        "openat2_tmpfile_rdonly_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_rdonly, 0, RESOLVE_BENEATH);
    println!(
        "openat2_resolve_beneath_absolute_exdev={}",
        r == -1 && errno() == libc::EXDEV
    );

    let rel_reg = CString::new("regfile").unwrap();
    let r = openat2(base_dir_fd, rel_reg.as_ptr(), o_rdonly, 0, RESOLVE_BENEATH);
    println!("openat2_resolve_beneath_rel_ok={}", r >= 0);
    if r >= 0 {
        unsafe { libc::close(r as i32) };
    }

    let rel_escape = CString::new("../../regfile").unwrap();
    let r = openat2(
        base_dir_fd,
        rel_escape.as_ptr(),
        o_rdonly,
        0,
        RESOLVE_IN_ROOT,
    );
    println!("openat2_resolve_in_root_escape_stay_in_root={}", r >= 0);
    if r >= 0 {
        unsafe { libc::close(r as i32) };
    }

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_rdonly, 0, RESOLVE_NO_SYMLINKS);
    println!("openat2_resolve_no_symlinks_regfile_ok={}", r >= 0);
    if r >= 0 {
        unsafe { libc::close(r as i32) };
    }

    let r = openat2(AT_FDCWD, reg_c.as_ptr(), o_rdonly, 0, 0x8000);
    println!(
        "openat2_resolve_unknown_bits_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    // ------------------------------------------------------------------------
    // 2. fstatat & statx Flag Matrix
    // ------------------------------------------------------------------------
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::fstatat(AT_FDCWD, reg_c.as_ptr(), &mut st, AT_SYMLINK_FOLLOW) };
    println!(
        "fstatat_symlink_follow_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::fstatat(AT_FDCWD, reg_c.as_ptr(), &mut st, AT_REMOVEDIR) };
    println!(
        "fstatat_removedir_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::fstatat(AT_FDCWD, reg_c.as_ptr(), &mut st, 0x4000_0000) };
    println!(
        "fstatat_bogus_flag_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::fstatat(reg_fd, empty_c.as_ptr(), &mut st, AT_EMPTY_PATH) };
    let is_reg = (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
    println!("fstatat_empty_path_valid_fd_ok={}", r == 0 && is_reg);

    let r = unsafe { libc::fstatat(reg_fd, empty_c.as_ptr(), &mut st, 0) };
    println!(
        "fstatat_empty_path_without_flag_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    let r = unsafe { libc::fstatat(AT_FDCWD, empty_c.as_ptr(), &mut st, 0) };
    println!(
        "fstatat_empty_path_at_fdcwd_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    let r = unsafe { libc::fstatat(AT_FDCWD, reg_c.as_ptr(), &mut st, AT_NO_AUTOMOUNT) };
    println!("fstatat_no_automount_ok={}", r == 0);

    let r = unsafe { libc::fstatat(AT_FDCWD, dir_link_c.as_ptr(), &mut st, AT_SYMLINK_NOFOLLOW) };
    let is_lnk = (st.st_mode & libc::S_IFMT) == libc::S_IFLNK;
    println!("fstatat_symlink_dir_nofollow_is_lnk={}", r == 0 && is_lnk);

    let r = unsafe { libc::fstatat(AT_FDCWD, dir_link_c.as_ptr(), &mut st, 0) };
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    println!("fstatat_symlink_dir_follow_is_dir={}", r == 0 && is_dir);

    let mut stx: Statx = unsafe { std::mem::zeroed() };
    let r = statx(
        AT_FDCWD,
        reg_c.as_ptr(),
        0x4000_0000,
        STATX_BASIC_STATS,
        &mut stx,
    );
    println!(
        "statx_unknown_flag_bits_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = statx(
        AT_FDCWD,
        reg_c.as_ptr(),
        AT_SYMLINK_FOLLOW,
        STATX_BASIC_STATS,
        &mut stx,
    );
    println!(
        "statx_symlink_follow_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = statx(
        AT_FDCWD,
        reg_c.as_ptr(),
        AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC,
        STATX_BASIC_STATS,
        &mut stx,
    );
    println!(
        "statx_sync_conflict_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = statx(
        reg_fd,
        empty_c.as_ptr(),
        AT_EMPTY_PATH,
        STATX_BASIC_STATS,
        &mut stx,
    );
    println!("statx_empty_path_valid_fd_ok={}", r == 0);

    let r = statx(reg_fd, empty_c.as_ptr(), 0, STATX_BASIC_STATS, &mut stx);
    println!(
        "statx_empty_path_without_flag_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    let r = statx(AT_FDCWD, reg_c.as_ptr(), 0, STATX_RESERVED, &mut stx);
    println!(
        "statx_reserved_mask_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = statx(
        AT_FDCWD,
        reg_c.as_ptr(),
        0,
        0x4000_0000 | STATX_BASIC_STATS,
        &mut stx,
    );
    println!("statx_unsupported_mask_ignored_ok={}", r == 0);

    // ------------------------------------------------------------------------
    // 3. renameat2 Flag & Error Matrix
    // ------------------------------------------------------------------------
    let ren_src1 = format!("{base}/ren_src1");
    let ren_src2 = format!("{base}/ren_src2");
    let ren_dst_existing = format!("{base}/ren_dst_existing");
    let ren_dst_missing = format!("{base}/ren_dst_missing");
    make_regfile(&ren_src1, b"src1");
    make_regfile(&ren_src2, b"src2");
    make_regfile(&ren_dst_existing, b"dst_old");

    let ren_src1_c = CString::new(ren_src1.as_str()).unwrap();
    let ren_src2_c = CString::new(ren_src2.as_str()).unwrap();
    let ren_dst_existing_c = CString::new(ren_dst_existing.as_str()).unwrap();
    let ren_dst_missing_c = CString::new(ren_dst_missing.as_str()).unwrap();

    let r = renameat2(
        AT_FDCWD,
        ren_src1_c.as_ptr(),
        AT_FDCWD,
        ren_dst_existing_c.as_ptr(),
        0x80,
    );
    println!(
        "renameat2_unknown_flag_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = renameat2(
        AT_FDCWD,
        ren_src1_c.as_ptr(),
        AT_FDCWD,
        ren_dst_existing_c.as_ptr(),
        RENAME_EXCHANGE | RENAME_WHITEOUT,
    );
    println!(
        "renameat2_exchange_whiteout_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = renameat2(
        AT_FDCWD,
        ren_src1_c.as_ptr(),
        AT_FDCWD,
        ren_dst_existing_c.as_ptr(),
        RENAME_NOREPLACE,
    );
    println!(
        "renameat2_noreplace_existing_dest_eexist={}",
        r == -1 && errno() == libc::EEXIST
    );

    let r = renameat2(
        AT_FDCWD,
        ren_src1_c.as_ptr(),
        AT_FDCWD,
        ren_dst_missing_c.as_ptr(),
        RENAME_NOREPLACE,
    );
    println!("renameat2_noreplace_new_dest_ok={}", r == 0);

    let r = renameat2(
        AT_FDCWD,
        empty_dir_c.as_ptr(),
        AT_FDCWD,
        ren_src2_c.as_ptr(),
        0,
    );
    println!(
        "renameat2_dir_to_file_enotdir={}",
        r == -1 && errno() == libc::ENOTDIR
    );

    let r = renameat2(
        AT_FDCWD,
        ren_src2_c.as_ptr(),
        AT_FDCWD,
        empty_dir_c.as_ptr(),
        0,
    );
    println!(
        "renameat2_file_to_dir_eisdir={}",
        r == -1 && errno() == libc::EISDIR
    );

    let r = renameat2(
        AT_FDCWD,
        empty_dir_c.as_ptr(),
        AT_FDCWD,
        nonempty_dir_c.as_ptr(),
        0,
    );
    println!(
        "renameat2_dir_to_nonempty_dir_enotempty={}",
        r == -1 && errno() == libc::ENOTEMPTY
    );

    let dir_a = format!("{base}/dir_a");
    let dir_b = format!("{base}/dir_b");
    make_dir(&dir_a);
    make_dir(&dir_b);
    make_regfile(&format!("{dir_a}/item_a"), b"alpha");
    make_regfile(&format!("{dir_b}/item_b"), b"beta");
    let dir_a_fd = unsafe {
        libc::open(
            CString::new(dir_a.as_str()).unwrap().as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
    };
    let dir_b_fd = unsafe {
        libc::open(
            CString::new(dir_b.as_str()).unwrap().as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
    };
    let item_a_c = CString::new("item_a").unwrap();
    let item_b_c = CString::new("item_b").unwrap();
    let r = renameat2(
        dir_a_fd,
        item_a_c.as_ptr(),
        dir_b_fd,
        item_b_c.as_ptr(),
        RENAME_EXCHANGE,
    );
    println!("renameat2_cross_dir_exchange_ok={}", r == 0);
    if dir_a_fd >= 0 {
        unsafe { libc::close(dir_a_fd) };
    }
    if dir_b_fd >= 0 {
        unsafe { libc::close(dir_b_fd) };
    }

    // ------------------------------------------------------------------------
    // 4. unlinkat Flag & Target Type Matrix
    // ------------------------------------------------------------------------
    let unl_file = format!("{base}/unl_file");
    make_regfile(&unl_file, b"unl");
    let unl_file_c = CString::new(unl_file.as_str()).unwrap();

    let r = unsafe { libc::unlinkat(AT_FDCWD, unl_file_c.as_ptr(), AT_SYMLINK_NOFOLLOW) };
    println!(
        "unlinkat_invalid_flag_nofollow_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::unlinkat(AT_FDCWD, unl_file_c.as_ptr(), AT_EMPTY_PATH) };
    println!(
        "unlinkat_invalid_flag_emptypath_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::unlinkat(AT_FDCWD, unl_file_c.as_ptr(), 0x8000) };
    println!(
        "unlinkat_invalid_flag_bogus_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::unlinkat(AT_FDCWD, unl_file_c.as_ptr(), AT_REMOVEDIR) };
    println!(
        "unlinkat_file_with_removedir_enotdir={}",
        r == -1 && errno() == libc::ENOTDIR
    );

    let r = unsafe { libc::unlinkat(AT_FDCWD, empty_dir_c.as_ptr(), 0) };
    println!(
        "unlinkat_dir_without_removedir_eisdir={}",
        r == -1 && errno() == libc::EISDIR
    );

    let unl_symlink_dir = format!("{base}/unl_symlink_dir");
    make_symlink(&empty_dir, &unl_symlink_dir);
    let unl_symlink_dir_c = CString::new(unl_symlink_dir.as_str()).unwrap();

    let r = unsafe { libc::unlinkat(AT_FDCWD, unl_symlink_dir_c.as_ptr(), AT_REMOVEDIR) };
    println!(
        "unlinkat_symlink_to_dir_with_removedir_enotdir={}",
        r == -1 && errno() == libc::ENOTDIR
    );

    let r = unsafe { libc::unlinkat(AT_FDCWD, unl_symlink_dir_c.as_ptr(), 0) };
    println!("unlinkat_symlink_to_dir_without_removedir_ok={}", r == 0);

    let r = unsafe { libc::unlinkat(AT_FDCWD, nonempty_dir_c.as_ptr(), AT_REMOVEDIR) };
    println!(
        "unlinkat_nonempty_dir_enotempty={}",
        r == -1 && errno() == libc::ENOTEMPTY
    );

    let r = unsafe { libc::unlinkat(AT_FDCWD, empty_c.as_ptr(), 0) };
    println!(
        "unlinkat_empty_path_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    // ------------------------------------------------------------------------
    // 5. faccessat2 Flag & Mode Matrix
    // ------------------------------------------------------------------------
    let r = faccessat2(AT_FDCWD, reg_c.as_ptr(), libc::R_OK, AT_SYMLINK_FOLLOW);
    println!(
        "faccessat2_invalid_flag_follow_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = faccessat2(AT_FDCWD, reg_c.as_ptr(), libc::R_OK, AT_NO_AUTOMOUNT);
    println!(
        "faccessat2_invalid_flag_automount_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = faccessat2(AT_FDCWD, reg_c.as_ptr(), libc::R_OK, 0x8000);
    println!(
        "faccessat2_invalid_flag_bogus_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = faccessat2(AT_FDCWD, reg_c.as_ptr(), 0xff, 0);
    println!(
        "faccessat2_invalid_mode_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = faccessat2(AT_FDCWD, reg_c.as_ptr(), 0x10, 0);
    println!(
        "faccessat2_invalid_mode_high_bit_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = faccessat2(AT_FDCWD, dangling_c.as_ptr(), libc::F_OK, 0);
    println!(
        "faccessat2_dangling_symlink_follow_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    let r = faccessat2(
        AT_FDCWD,
        dangling_c.as_ptr(),
        libc::F_OK,
        AT_SYMLINK_NOFOLLOW,
    );
    println!("faccessat2_dangling_symlink_nofollow_ok={}", r == 0);

    let r = faccessat2(reg_fd, empty_c.as_ptr(), libc::R_OK, AT_EMPTY_PATH);
    println!("faccessat2_empty_path_valid_fd_ok={}", r == 0);

    let r = faccessat2(reg_fd, empty_c.as_ptr(), libc::R_OK, 0);
    println!(
        "faccessat2_empty_path_without_flag_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    // ------------------------------------------------------------------------
    // 6. fchownat & utimensat Flag Validation Matrix
    // ------------------------------------------------------------------------
    let r = unsafe { libc::fchownat(AT_FDCWD, reg_c.as_ptr(), u32::MAX, u32::MAX, AT_REMOVEDIR) };
    println!(
        "fchownat_invalid_flag_removedir_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe {
        libc::fchownat(
            AT_FDCWD,
            reg_c.as_ptr(),
            u32::MAX,
            u32::MAX,
            AT_SYMLINK_FOLLOW,
        )
    };
    println!(
        "fchownat_invalid_flag_follow_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::fchownat(AT_FDCWD, reg_c.as_ptr(), u32::MAX, u32::MAX, 0x8000) };
    println!(
        "fchownat_invalid_flag_bogus_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::fchownat(reg_fd, empty_c.as_ptr(), u32::MAX, u32::MAX, AT_EMPTY_PATH) };
    println!("fchownat_empty_path_valid_fd_ok={}", r == 0);

    let r = unsafe { libc::fchownat(reg_fd, empty_c.as_ptr(), u32::MAX, u32::MAX, 0) };
    println!(
        "fchownat_empty_path_without_flag_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    let r = unsafe { libc::utimensat(AT_FDCWD, reg_c.as_ptr(), std::ptr::null(), AT_REMOVEDIR) };
    println!(
        "utimensat_invalid_flag_removedir_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe {
        libc::utimensat(
            AT_FDCWD,
            reg_c.as_ptr(),
            std::ptr::null(),
            AT_SYMLINK_FOLLOW,
        )
    };
    println!(
        "utimensat_invalid_flag_follow_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe { libc::utimensat(AT_FDCWD, reg_c.as_ptr(), std::ptr::null(), 0x8000) };
    println!(
        "utimensat_invalid_flag_bogus_einval={}",
        r == -1 && errno() == libc::EINVAL
    );

    let r = unsafe {
        libc::utimensat(
            AT_FDCWD,
            dangling_c.as_ptr(),
            std::ptr::null(),
            AT_SYMLINK_NOFOLLOW,
        )
    };
    println!("utimensat_dangling_symlink_nofollow_ok={}", r == 0);

    let r = unsafe { libc::utimensat(AT_FDCWD, dangling_c.as_ptr(), std::ptr::null(), 0) };
    println!(
        "utimensat_dangling_symlink_follow_enoent={}",
        r == -1 && errno() == libc::ENOENT
    );

    if reg_fd >= 0 {
        unsafe { libc::close(reg_fd) };
    }
    if base_dir_fd >= 0 {
        unsafe { libc::close(base_dir_fd) };
    }
}
