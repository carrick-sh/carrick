//! Perf probe: metadata/open/access storm against a large sparse file.
//!
//! This workload is intentionally payload-size independent: it creates a large
//! sparse file with ftruncate(2), then times metadata and open/fstat/access
//! operations without reading file contents.
//!
//! Output is `key=value` lines parsed by the perf runner:
//!   large_meta_p50_us=<f>
//!   large_meta_total_us=<f>
//!   file_bytes=<u>
//!   iterations=<u>
//!   nproc=<u>
use std::ffi::CString;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Instant;

const FILE_BYTES: i64 = 256 * 1024 * 1024;
const WARMUP: usize = 16;
const ITERS: usize = 128;

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn metadata_once(path: &PathBuf, cpath: &CString) {
    let _ = fs::metadata(path).expect("metadata");
    let _ = fs::symlink_metadata(path).expect("symlink_metadata");
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        std::process::exit(1);
    }
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        std::process::exit(1);
    }
    unsafe {
        libc::close(fd);
    }
    if unsafe { libc::access(cpath.as_ptr(), libc::F_OK) } != 0 {
        std::process::exit(1);
    }
}

fn main() {
    let dir = std::env::var("BENCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let path = PathBuf::from(format!(
        "{dir}/carrick_large_meta_{}.dat",
        std::process::id()
    ));
    let cpath = CString::new(path.to_string_lossy().as_bytes()).expect("path cstring");

    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        std::process::exit(1);
    }
    if unsafe { libc::ftruncate(fd, FILE_BYTES) } != 0 {
        std::process::exit(1);
    }
    unsafe {
        libc::close(fd);
    }

    for _ in 0..WARMUP {
        metadata_once(&path, &cpath);
    }

    let total_start = Instant::now();
    let mut samples_ns = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        metadata_once(&path, &cpath);
        samples_ns.push(t0.elapsed().as_nanos());
    }
    let total_us = total_start.elapsed().as_secs_f64() * 1_000_000.0;

    samples_ns.sort_unstable();
    let p50 = samples_ns[samples_ns.len() / 2] as f64 / 1000.0;

    let _ = fs::remove_file(&path);

    println!("large_meta_p50_us={p50:.3}");
    println!("large_meta_total_us={total_us:.3}");
    println!("file_bytes={FILE_BYTES}");
    println!("iterations={ITERS}");
    println!("nproc={}", nproc());
}
