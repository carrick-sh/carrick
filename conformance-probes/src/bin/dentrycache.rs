//! Conformance probe for dentry cache behaviour on host-backed rootfs.
//!
//! Exercises:
//! - Positive stat through symlinks (1 hop, multi-hop).
//! - Negative stat (ENOENT) and consistency.
//! - Unlink invalidating cached dentry.
//! - Create after negative stat (verifying negative cache invalidation).
//! - Mkdir/rmdir directory generation bump and cache invalidation.
//! - Rename moving dentry and negative-caching old path.
//! - Chmod updating/invalidating metadata.
//! - Trailing slashes on regular files and symlinks to regular files (ENOTDIR).
//! - Symlink loop detection (ELOOP).
//! - Readlink on symlink vs regular file.

use std::ffi::CString;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::symlink;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn stat_mode_and_size(path: &str) -> Result<(u32, u64), i32> {
    let c = CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::stat(c.as_ptr(), &mut st) };
    if rc == 0 {
        Ok((st.st_mode as u32, st.st_size as u64))
    } else {
        Err(errno())
    }
}

fn lstat_mode(path: &str) -> Result<u32, i32> {
    let c = CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::lstat(c.as_ptr(), &mut st) };
    if rc == 0 {
        Ok(st.st_mode as u32)
    } else {
        Err(errno())
    }
}

fn main() {
    let dir = "/tmp/carrick_dentrycache_probe";
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).expect("failed to create probe test dir");

    let target1 = format!("{dir}/target1");
    let link1 = format!("{dir}/link1");
    let link2 = format!("{dir}/link2");
    let link3 = format!("{dir}/link3");

    // 1. Setup target1 and symlink chain
    {
        let mut f = File::create(&target1).expect("create target1");
        f.write_all(b"hello").expect("write target1");
    }
    symlink("target1", &link1).expect("symlink link1 -> target1");
    symlink("link1", &link2).expect("symlink link2 -> link1");
    symlink("link2", &link3).expect("symlink link3 -> link2");

    // 2. Positive stat through 1-hop symlink
    match stat_mode_and_size(&link1) {
        Ok((mode, size)) => {
            println!("link1_stat_ok=true");
            println!("link1_stat_size={size}");
            println!("link1_stat_is_reg={}", (mode & libc::S_IFMT as u32) == libc::S_IFREG as u32);
        }
        Err(e) => println!("link1_stat_ok=ERR:{e}"),
    }

    match lstat_mode(&link1) {
        Ok(mode) => {
            println!("link1_lstat_is_lnk={}", (mode & libc::S_IFMT as u32) == libc::S_IFLNK as u32);
        }
        Err(e) => println!("link1_lstat_is_lnk=ERR:{e}"),
    }

    // 3. Multi-hop symlink stat (3 hops)
    match stat_mode_and_size(&link3) {
        Ok((mode, size)) => {
            println!("link3_stat_ok=true");
            println!("link3_stat_size={size}");
            println!("link3_stat_is_reg={}", (mode & libc::S_IFMT as u32) == libc::S_IFREG as u32);
        }
        Err(e) => println!("link3_stat_ok=ERR:{e}"),
    }

    // 4. Negative stat (ENOENT)
    let nonexistent = format!("{dir}/nonexistent");
    match stat_mode_and_size(&nonexistent) {
        Ok(_) => println!("nonexistent_first_errno=0"),
        Err(e) => println!("nonexistent_first_errno={e}"),
    }
    match stat_mode_and_size(&nonexistent) {
        Ok(_) => println!("nonexistent_second_errno=0"),
        Err(e) => println!("nonexistent_second_errno={e}"),
    }

    // 5. Unlink invalidation
    let to_unlink = format!("{dir}/to_unlink");
    {
        let mut f = File::create(&to_unlink).expect("create to_unlink");
        f.write_all(b"temp").expect("write temp");
    }
    println!("to_unlink_stat_before={}", stat_mode_and_size(&to_unlink).is_ok());
    let c_to_unlink = CString::new(to_unlink.clone()).unwrap();
    let unlinked = unsafe { libc::unlink(c_to_unlink.as_ptr()) };
    println!("unlink_rc_ok={}", unlinked == 0);
    match stat_mode_and_size(&to_unlink) {
        Ok(_) => println!("unlink_stat_after_errno=0"),
        Err(e) => println!("unlink_stat_after_errno={e}"),
    }

    // 6. Create after negative hit
    let created_later = format!("{dir}/created_later");
    println!("created_later_stat_before_enoent={}", stat_mode_and_size(&created_later) == Err(libc::ENOENT));
    {
        let mut f = File::create(&created_later).expect("create created_later");
        f.write_all(b"data").expect("write data");
    }
    println!("created_later_stat_after_ok={}", stat_mode_and_size(&created_later).is_ok());

    // 7. Mkdir / Rmdir directory generation bump and cache invalidation
    let subdir = format!("{dir}/subdir");
    let c_subdir = CString::new(subdir.clone()).unwrap();
    let mk_rc = unsafe { libc::mkdir(c_subdir.as_ptr(), 0o755) };
    println!("mkdir_ok={}", mk_rc == 0);
    match stat_mode_and_size(&subdir) {
        Ok((mode, _)) => println!("subdir_is_dir={}", (mode & libc::S_IFMT as u32) == libc::S_IFDIR as u32),
        Err(e) => println!("subdir_is_dir=ERR:{e}"),
    }

    let child = format!("{subdir}/child");
    println!("child_stat_before_enoent={}", stat_mode_and_size(&child) == Err(libc::ENOENT));
    {
        let mut f = File::create(&child).expect("create child");
        f.write_all(b"c").expect("write child");
    }
    println!("child_stat_after_ok={}", stat_mode_and_size(&child).is_ok());
    let c_child = CString::new(child.clone()).unwrap();
    let _ = unsafe { libc::unlink(c_child.as_ptr()) };
    let rm_rc = unsafe { libc::rmdir(c_subdir.as_ptr()) };
    println!("rmdir_ok={}", rm_rc == 0);
    match stat_mode_and_size(&subdir) {
        Ok(_) => println!("rmdir_stat_after_errno=0"),
        Err(e) => println!("rmdir_stat_after_errno={e}"),
    }

    // 8. Rename moving dentry and negative caching old path
    let rename_src = format!("{dir}/rename_src");
    let rename_dst = format!("{dir}/rename_dst");
    {
        let mut f = File::create(&rename_src).expect("create rename_src");
        f.write_all(b"move").expect("write move");
    }
    println!("rename_src_stat_before={}", stat_mode_and_size(&rename_src).is_ok());
    let c_src = CString::new(rename_src.clone()).unwrap();
    let c_dst = CString::new(rename_dst.clone()).unwrap();
    let rn_rc = unsafe { libc::rename(c_src.as_ptr(), c_dst.as_ptr()) };
    println!("rename_rc_ok={}", rn_rc == 0);
    match stat_mode_and_size(&rename_src) {
        Ok(_) => println!("rename_old_stat_errno=0"),
        Err(e) => println!("rename_old_stat_errno={e}"),
    }
    println!("rename_new_stat_ok={}", stat_mode_and_size(&rename_dst).is_ok());

    // 9. Chmod metadata update
    let c_target1 = CString::new(target1.clone()).unwrap();
    let ch_rc1 = unsafe { libc::chmod(c_target1.as_ptr(), 0o600) };
    println!("chmod_600_rc_ok={}", ch_rc1 == 0);
    match stat_mode_and_size(&target1) {
        Ok((mode, _)) => println!("chmod_stat_mode_0600={}", (mode & 0o777) == 0o600),
        Err(e) => println!("chmod_stat_mode_0600=ERR:{e}"),
    }
    let ch_rc2 = unsafe { libc::chmod(c_target1.as_ptr(), 0o644) };
    println!("chmod_644_rc_ok={}", ch_rc2 == 0);
    match stat_mode_and_size(&target1) {
        Ok((mode, _)) => println!("chmod_stat_mode_0644={}", (mode & 0o777) == 0o644),
        Err(e) => println!("chmod_stat_mode_0644=ERR:{e}"),
    }

    // 10. Trailing slash checks (ENOTDIR = 20)
    let target1_slash = format!("{target1}/");
    match stat_mode_and_size(&target1_slash) {
        Ok(_) => println!("reg_trailing_slash_errno=0"),
        Err(e) => println!("reg_trailing_slash_errno={e}"),
    }
    let link1_slash = format!("{link1}/");
    match stat_mode_and_size(&link1_slash) {
        Ok(_) => println!("symlink_to_reg_trailing_slash_errno=0"),
        Err(e) => println!("symlink_to_reg_trailing_slash_errno={e}"),
    }

    // 11. Symlink loop (ELOOP = 40)
    let loop_a = format!("{dir}/loop_a");
    let loop_b = format!("{dir}/loop_b");
    symlink("loop_b", &loop_a).expect("symlink loop_a -> loop_b");
    symlink("loop_a", &loop_b).expect("symlink loop_b -> loop_a");
    match stat_mode_and_size(&loop_a) {
        Ok(_) => println!("symlink_loop_errno=0"),
        Err(e) => println!("symlink_loop_errno={e}"),
    }

    // 12. Readlink
    let mut buf = [0u8; 128];
    let c_link1 = CString::new(link1.clone()).unwrap();
    let rl_n = unsafe {
        libc::readlink(c_link1.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    if rl_n > 0 {
        let s = String::from_utf8_lossy(&buf[..rl_n as usize]);
        println!("readlink_target_match={}", s == "target1");
    } else {
        println!("readlink_target_match=ERR:{}", errno());
    }

    let rl_reg = unsafe {
        libc::readlink(c_target1.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    if rl_reg < 0 {
        println!("readlink_reg_errno={}", errno());
    } else {
        println!("readlink_reg_errno=0");
    }

    // Cleanup
    let _ = fs::remove_dir_all(dir);
}
