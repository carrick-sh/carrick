//! Perf probe: build-tool-like small updates over a larger file set.
//!
//! This creates a fixed set of sparse files, then repeatedly opens one file,
//! writes one byte at a rotating offset, and closes it. Under Carrick `--fs
//! memory`, this exercises overlay dirty-range writeback instead of raw host-fd
//! paths.
//!
//! Output is `key=value` lines parsed by the perf runner:
//!   overlay_small_updates_p50_us=<f>
//!   overlay_small_updates_total_us=<f>
//!   files=<u>
//!   file_bytes=<u>
//!   updates=<u>
//!   write_bytes=<u>
//!   nproc=<u>
use std::ffi::CString;
use std::thread;
use std::time::Instant;

const FILES: usize = 16;
const FILE_BYTES: i64 = 1024 * 1024;
const WARMUP: usize = 64;
const UPDATES: usize = 512;
const WRITE_BYTES: &[u8] = b"x";

fn nproc() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

fn create_file(path: &CString) {
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
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
}

fn update_once(paths: &[CString], iteration: usize) {
    let path = &paths[iteration % paths.len()];
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        std::process::exit(1);
    }
    let offset = ((iteration * 4099) % FILE_BYTES as usize) as libc::off_t;
    let n = unsafe {
        libc::pwrite(
            fd,
            WRITE_BYTES.as_ptr().cast::<libc::c_void>(),
            WRITE_BYTES.len(),
            offset,
        )
    };
    if n != WRITE_BYTES.len() as isize {
        std::process::exit(1);
    }
    unsafe {
        libc::close(fd);
    }
}

fn main() {
    let dir = std::env::var("BENCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let paths: Vec<CString> = (0..FILES)
        .map(|idx| {
            CString::new(format!(
                "{dir}/carrick_overlay_small_updates_{}_{}.dat",
                std::process::id(),
                idx
            ))
            .expect("path cstring")
        })
        .collect();

    for path in &paths {
        create_file(path);
    }

    for iteration in 0..WARMUP {
        update_once(&paths, iteration);
    }

    let total_start = Instant::now();
    let mut samples_ns = Vec::with_capacity(UPDATES);
    for iteration in 0..UPDATES {
        let t0 = Instant::now();
        update_once(&paths, iteration + WARMUP);
        samples_ns.push(t0.elapsed().as_nanos());
    }
    let total_us = total_start.elapsed().as_secs_f64() * 1_000_000.0;

    samples_ns.sort_unstable();
    let p50 = samples_ns[samples_ns.len() / 2] as f64 / 1000.0;

    for path in &paths {
        unsafe {
            libc::unlink(path.as_ptr());
        }
    }

    println!("overlay_small_updates_p50_us={p50:.3}");
    println!("overlay_small_updates_total_us={total_us:.3}");
    println!("files={FILES}");
    println!("file_bytes={FILE_BYTES}");
    println!("updates={UPDATES}");
    println!("write_bytes={}", WRITE_BYTES.len());
    println!("nproc={}", nproc());
}
