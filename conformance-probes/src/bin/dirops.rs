//! Directory / link operations probe. Exercises mkdir/rmdir, nested dir
//! creation, readdir ordering & content, hard/symlinks, directory rename,
//! unlink, and getdents-on-cwd. Prints one labelled line per observation.
//! The conformance harness runs this identical static binary under carrick
//! and real Linux and diffs line by line — a divergent line names the exact
//! failing operation.
//!
//! Deterministic only: no timestamps, pids, addresses, or inode numbers.
//! Directory listings are sorted and comma-joined so ordering never matters.

use std::fs;
use std::os::unix::fs::MetadataExt;

fn main() {
    // mkdir / rmdir: create, observe existence, remove, observe absence.
    fs::create_dir("/tmp/d1").ok();
    println!("mkdir_d1 exists={}", fs::metadata("/tmp/d1").is_ok());
    fs::remove_dir("/tmp/d1").ok();
    println!("rmdir_d1 exists={}", fs::metadata("/tmp/d1").is_ok());

    // mkdir -p style: create nested /tmp/d2/a/b, confirm leaf + each ancestor.
    fs::create_dir_all("/tmp/d2/a/b").ok();
    println!("mkdirp_d2 exists={}", fs::metadata("/tmp/d2/a/b").is_ok());
    println!("mkdirp_d2 dir={}", is_dir("/tmp/d2"));
    println!("mkdirp_d2_a dir={}", is_dir("/tmp/d2/a"));
    println!("mkdirp_d2_a_b dir={}", is_dir("/tmp/d2/a/b"));

    // readdir ordering/content: create /tmp/dd with files a,b,c; list sorted.
    fs::create_dir_all("/tmp/dd").ok();
    fs::write("/tmp/dd/a", b"a").ok();
    fs::write("/tmp/dd/b", b"b").ok();
    fs::write("/tmp/dd/c", b"c").ok();
    let names = sorted_names("/tmp/dd");
    println!("readdir_dd names={}", names.join(","));
    println!("readdir_dd count={}", names.len());

    // readdir reflects a newly created file.
    fs::write("/tmp/dd/zzz", b"z").ok();
    let names2 = sorted_names("/tmp/dd");
    println!("readdir_dd_zzz listed={}", names2.iter().any(|n| n == "zzz"));

    // hardlink: create /tmp/h1 ("hl"), link to /tmp/h2, read back + nlink.
    fs::write("/tmp/h1", b"hl").ok();
    fs::hard_link("/tmp/h1", "/tmp/h2").ok();
    let h2 = fs::read_to_string("/tmp/h2").unwrap_or_default();
    println!("hardlink_h2_content_ok={}", h2 == "hl");
    // On real Linux a true hardlink makes st_nlink == 2; carrick may differ.
    match fs::metadata("/tmp/h1") {
        Ok(m) => println!("hardlink_h1_nlink={}", m.nlink()),
        Err(e) => println!("hardlink_h1_nlink=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // symlink: /tmp/dlnk -> /tmp/dd; readlink; stat-through vs lstat.
    std::os::unix::fs::symlink("/tmp/dd", "/tmp/dlnk").ok();
    match fs::read_link("/tmp/dlnk") {
        Ok(t) => println!("symlink_dlnk_target={}", t.display()),
        Err(e) => println!("symlink_dlnk_target=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }
    match fs::metadata("/tmp/dlnk") {
        Ok(m) => println!("symlink_dlnk_stat_dir={}", m.is_dir()),
        Err(e) => println!("symlink_dlnk_stat_dir=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }
    match fs::symlink_metadata("/tmp/dlnk") {
        Ok(m) => println!("symlink_dlnk_lstat_symlink={}", m.file_type().is_symlink()),
        Err(e) => println!("symlink_dlnk_lstat_symlink=ERR:{}", e.raw_os_error().unwrap_or(-1)),
    }

    // rename a directory: /tmp/rd (with a file) -> /tmp/rd2.
    fs::create_dir_all("/tmp/rd").ok();
    fs::write("/tmp/rd/inside", b"x").ok();
    fs::rename("/tmp/rd", "/tmp/rd2").ok();
    println!("rename_dir rd_exists={}", fs::metadata("/tmp/rd").is_ok());
    println!(
        "rename_dir rd2_file_exists={}",
        fs::metadata("/tmp/rd2/inside").is_ok()
    );

    // unlink a regular file.
    fs::write("/tmp/u1", b"u").ok();
    fs::remove_file("/tmp/u1").ok();
    println!("unlink_u1 exists={}", fs::metadata("/tmp/u1").is_ok());

    // getdents on "." after chdir into /tmp/dd.
    std::env::set_current_dir("/tmp/dd").ok();
    let dot = sorted_names(".");
    println!("getdents_dot count={}", dot.len());
}

fn is_dir(path: &str) -> bool {
    fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// Read a directory and return its entry names, sorted for determinism.
fn sorted_names(path: &str) -> Vec<String> {
    let mut names: Vec<String> = match fs::read_dir(path) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}
