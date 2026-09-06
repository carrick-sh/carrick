//! Conformance probe for namei path resolution and escape prevention.
//!
//! Exercises:
//! 1. `..` chains (parent traversal, deep traversal, root clamping, non-existent parent)
//! 2. Absolute symlinks (resolution, O_NOFOLLOW behavior)
//! 3. Swapped / multi-hop symlinks and loops (ELOOP propagation)
//! 4. Relative symlinks escaping via `..`
//! 5. Directory symlink traversal
//! 6. O_CREAT | O_EXCL on existing symlink
//!
//! Prints deterministic output: boolean samestat (st_dev/st_ino agreement) and
//! raw errno numbers so the test diffs cleanly against Linux oracle.

use conformance_probes::{errno, report};
use std::ffi::CString;

fn samestat(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn cleanup(base: &str) {
    let files = [
        format!("{base}/sub/deep/nested.txt"),
        format!("{base}/sub/link_dotdot"),
        format!("{base}/sub/link_abs"),
        format!("{base}/sub/link_loop_a"),
        format!("{base}/sub/link_loop_b"),
        format!("{base}/sub/link_swap_a"),
        format!("{base}/sub/link_swap_b"),
        format!("{base}/link_to_sub"),
        format!("{base}/target.txt"),
    ];
    for f in &files {
        let c = cstr(f);
        unsafe { libc::unlink(c.as_ptr()) };
    }
    let dirs = [
        format!("{base}/sub/deep"),
        format!("{base}/sub"),
        base.to_string(),
    ];
    for d in &dirs {
        let c = cstr(d);
        unsafe { libc::rmdir(c.as_ptr()) };
    }
}

fn main() {
    let base = "/tmp/namei_escape_probe";
    cleanup(base);

    // Setup hierarchy
    let base_c = cstr(base);
    let sub_c = cstr(&format!("{base}/sub"));
    let deep_c = cstr(&format!("{base}/sub/deep"));
    let target_c = cstr(&format!("{base}/target.txt"));
    let nested_c = cstr(&format!("{base}/sub/deep/nested.txt"));

    unsafe {
        libc::mkdir(base_c.as_ptr(), 0o755);
        libc::mkdir(sub_c.as_ptr(), 0o755);
        libc::mkdir(deep_c.as_ptr(), 0o755);

        let tfd = libc::open(
            target_c.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        if tfd >= 0 {
            libc::write(tfd, b"target\n".as_ptr() as *const _, 7);
            libc::close(tfd);
        }

        let nfd = libc::open(
            nested_c.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644,
        );
        if nfd >= 0 {
            libc::write(nfd, b"nested\n".as_ptr() as *const _, 7);
            libc::close(nfd);
        }

        // Symlinks
        libc::symlink(
            cstr("../target.txt").as_ptr(),
            cstr(&format!("{base}/sub/link_dotdot")).as_ptr(),
        );
        libc::symlink(
            target_c.as_ptr(),
            cstr(&format!("{base}/sub/link_abs")).as_ptr(),
        );
        libc::symlink(
            cstr("link_loop_b").as_ptr(),
            cstr(&format!("{base}/sub/link_loop_a")).as_ptr(),
        );
        libc::symlink(
            cstr("link_loop_a").as_ptr(),
            cstr(&format!("{base}/sub/link_loop_b")).as_ptr(),
        );
        libc::symlink(
            cstr("link_swap_b").as_ptr(),
            cstr(&format!("{base}/sub/link_swap_a")).as_ptr(),
        );
        libc::symlink(
            cstr("../target.txt").as_ptr(),
            cstr(&format!("{base}/sub/link_swap_b")).as_ptr(),
        );
        libc::symlink(
            cstr("sub").as_ptr(),
            cstr(&format!("{base}/link_to_sub")).as_ptr(),
        );
    }

    // Baseline stat for target and nested
    let mut target_st: libc::stat = unsafe { std::mem::zeroed() };
    let target_rc = unsafe { libc::stat(target_c.as_ptr(), &mut target_st) };
    let mut nested_st: libc::stat = unsafe { std::mem::zeroed() };
    let nested_rc = unsafe { libc::stat(nested_c.as_ptr(), &mut nested_st) };

    assert_eq!(target_rc, 0, "target setup must succeed");
    assert_eq!(nested_rc, 0, "nested setup must succeed");

    // 1. `..` chains
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let dotdot_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/sub/../target.txt")).as_ptr(),
            &mut st,
        )
    };
    let dotdot_samestat = dotdot_rc == 0 && samestat(&st, &target_st);

    let mut deep_st: libc::stat = unsafe { std::mem::zeroed() };
    let deep_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/sub/deep/../../target.txt")).as_ptr(),
            &mut deep_st,
        )
    };
    let deep_dotdot_samestat = deep_rc == 0 && samestat(&deep_st, &target_st);

    let mut root_st: libc::stat = unsafe { std::mem::zeroed() };
    let root_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/../../../../../../../../tmp/namei_escape_probe/target.txt")).as_ptr(),
            &mut root_st,
        )
    };
    let root_dotdot_samestat = root_rc == 0 && samestat(&root_st, &target_st);

    let nonexistent_parent_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/nonexistent_dir/../target.txt")).as_ptr(),
            &mut st,
        )
    };
    let nonexistent_parent_errno = if nonexistent_parent_rc < 0 { errno() } else { 0 };

    // 2. Absolute symlinks
    let mut abs_st: libc::stat = unsafe { std::mem::zeroed() };
    let abs_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/sub/link_abs")).as_ptr(),
            &mut abs_st,
        )
    };
    let abs_symlink_samestat = abs_rc == 0 && samestat(&abs_st, &target_st);

    let mut abs_lst: libc::stat = unsafe { std::mem::zeroed() };
    let abs_lrc = unsafe {
        libc::lstat(
            cstr(&format!("{base}/sub/link_abs")).as_ptr(),
            &mut abs_lst,
        )
    };
    let abs_symlink_is_link = abs_lrc == 0 && (abs_lst.st_mode & libc::S_IFMT) == libc::S_IFLNK;
    let abs_symlink_distinct = abs_lrc == 0 && !samestat(&abs_lst, &target_st);

    let nofollow_fd = unsafe {
        libc::open(
            cstr(&format!("{base}/sub/link_abs")).as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )
    };
    let abs_nofollow_errno = if nofollow_fd < 0 { errno() } else {
        unsafe { libc::close(nofollow_fd) };
        0
    };

    // 3. Swapped / chained symlinks
    let mut swap_st: libc::stat = unsafe { std::mem::zeroed() };
    let swap_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/sub/link_swap_a")).as_ptr(),
            &mut swap_st,
        )
    };
    let swap_chain_samestat = swap_rc == 0 && samestat(&swap_st, &target_st);

    let mut loop_st: libc::stat = unsafe { std::mem::zeroed() };
    let loop_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/sub/link_loop_a")).as_ptr(),
            &mut loop_st,
        )
    };
    let symlink_loop_errno = if loop_rc < 0 { errno() } else { 0 };

    // 4. Relative symlink with `..`
    let mut rel_dotdot_st: libc::stat = unsafe { std::mem::zeroed() };
    let rel_dotdot_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/sub/link_dotdot")).as_ptr(),
            &mut rel_dotdot_st,
        )
    };
    let rel_symlink_dotdot_samestat = rel_dotdot_rc == 0 && samestat(&rel_dotdot_st, &target_st);

    // 5. Directory symlink traversal
    let mut dir_symlink_st: libc::stat = unsafe { std::mem::zeroed() };
    let dir_symlink_rc = unsafe {
        libc::stat(
            cstr(&format!("{base}/link_to_sub/deep/nested.txt")).as_ptr(),
            &mut dir_symlink_st,
        )
    };
    let dir_symlink_samestat = dir_symlink_rc == 0 && samestat(&dir_symlink_st, &nested_st);

    // 6. O_CREAT | O_EXCL on existing symlink
    let excl_fd = unsafe {
        libc::open(
            cstr(&format!("{base}/sub/link_abs")).as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
            0o644,
        )
    };
    let symlink_creat_excl_errno = if excl_fd < 0 { errno() } else {
        unsafe { libc::close(excl_fd) };
        0
    };

    report!(
        dotdot_samestat = dotdot_samestat,
        deep_dotdot_samestat = deep_dotdot_samestat,
        root_dotdot_samestat = root_dotdot_samestat,
        nonexistent_parent_errno = nonexistent_parent_errno,
        abs_symlink_samestat = abs_symlink_samestat,
        abs_symlink_is_link = abs_symlink_is_link,
        abs_symlink_distinct = abs_symlink_distinct,
        abs_nofollow_errno = abs_nofollow_errno,
        swap_chain_samestat = swap_chain_samestat,
        symlink_loop_errno = symlink_loop_errno,
        rel_symlink_dotdot_samestat = rel_symlink_dotdot_samestat,
        dir_symlink_samestat = dir_symlink_samestat,
        symlink_creat_excl_errno = symlink_creat_excl_errno,
    );

    cleanup(base);
}
