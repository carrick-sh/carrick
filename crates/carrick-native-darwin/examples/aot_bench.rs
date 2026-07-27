// A benchmark example, not shipped code: every `expect` here is a setup step
// whose failure invalidates the measurement, so panicking with the reason is the
// correct response and an `Err` return would only obscure it. The workspace
// no-panic gate targets the runtime, which this is not.
#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Benchmark the file-backed AOT publish pipeline against `MAP_JIT`.
//!
//! Two questions, both end-to-end on OUR emitter rather than a compiler-built
//! dylib:
//!
//! 1. What does publishing a unit cost? (emit -> sign -> dlopen)
//! 2. Does a unit we emitted actually avoid the `MAP_JIT` fork penalty?
//!
//! Run: `cargo run -p carrick-native-darwin --example aot_bench --release`
//! Keep the box quiet: fork timings are load-sensitive.

use carrick_native_darwin::aot::{AotExport, AotImage, AotSection, emit_dylib};
use std::time::Instant;

/// `mov w0, #42 ; ret`
const MOV42_RET: [u8; 8] = [0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6];
/// `nop` — pads a unit out to a realistic size without changing behaviour.
const NOP: [u8; 4] = [0x1f, 0x20, 0x03, 0xd5];

fn unit_code(bytes: usize) -> Vec<u8> {
    let mut code = Vec::with_capacity(bytes);
    code.extend_from_slice(&MOV42_RET);
    while code.len() < bytes {
        code.extend_from_slice(&NOP);
    }
    code
}

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

/// fork + child `_exit(0)` + `waitpid`, the same shape as `perf_fork_scale`.
fn fork_p50_us(iters: usize) -> u128 {
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let t0 = Instant::now();
        // SAFETY: the child does nothing but `_exit`, which is async-signal-safe.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        assert!(pid > 0, "fork failed");
        let mut status = 0;
        while unsafe { libc::waitpid(pid, &mut status, 0) } != pid {}
        // Discard warmup: the first forks pay one-time COW setup.
        if i >= 15 {
            samples.push(t0.elapsed().as_nanos());
        }
    }
    median(samples) / 1000
}

fn publish(
    dir: &std::path::Path,
    name: &str,
    code: &[u8],
) -> (u128, u128, u128, std::path::PathBuf) {
    let export = AotExport {
        name: "carrick_aot_entry",
        section: AotSection::Text,
        offset: 0,
    };

    let t = Instant::now();
    let bytes = emit_dylib(&AotImage {
        code,
        data: &[],
        exports: &[export],
        relocations: &[],
    })
    .expect("emit");
    let emit_us = t.elapsed().as_micros();

    let path = dir.join(format!("{name}.dylib"));
    std::fs::write(&path, &bytes).expect("write");

    let t = Instant::now();
    let out = std::process::Command::new("/usr/bin/codesign")
        .args(["-s", "-"])
        .arg(&path)
        .output()
        .expect("codesign");
    let sign_us = t.elapsed().as_micros();
    assert!(
        out.status.success(),
        "sign: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let t = Instant::now();
    // SAFETY: freshly written, signed file.
    let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW) };
    let dlopen_us = t.elapsed().as_micros();
    assert!(!h.is_null(), "dlopen failed for {name}");

    // Prove the loaded unit is real before we time anything against it.
    let sym = std::ffi::CString::new("carrick_aot_entry").unwrap();
    // SAFETY: live handle, symbol exported by `emit_dylib`.
    let addr = unsafe { libc::dlsym(h, sym.as_ptr()) };
    assert!(!addr.is_null(), "dlsym failed for {name}");
    // SAFETY: the symbol addresses `mov w0,#42; ret`.
    let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(addr) };
    assert_eq!(
        f(),
        42,
        "emitted unit executed but returned the wrong value"
    );

    (emit_us, sign_us, dlopen_us, path)
}

fn main() {
    let dir = std::env::temp_dir().join(format!("carrick-aot-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");

    println!("=== publish cost (emit -> sign -> dlopen -> verified by CALL) ===");
    println!(
        "{:>8}  {:>10}  {:>10}  {:>12}",
        "size", "emit_us", "sign_us", "dlopen_us"
    );
    let mut big = None;
    for mib in [1usize, 16, 64] {
        let code = unit_code(mib << 20);
        let (e, s, d, path) = publish(&dir, &format!("u{mib}"), &code);
        println!("{:>7}M  {:>10}  {:>10}  {:>12}", mib, e, s, d);
        if mib == 64 {
            big = Some(path);
        }
    }

    println!("\n=== fork p50 (us), 100 timed iterations after 15 warmup ===");
    // Baseline is this process AFTER the units above are already loaded, so the
    // comparison isolates MAP_JIT rather than re-measuring the loads.
    let with_aot = fork_p50_us(115);
    println!("{:>34}  {:>8}", "with emitted AOT units loaded", with_aot);

    let size = 64usize << 20;
    // SAFETY: a fresh MAP_JIT region of the same size as the largest unit.
    let jit = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
            -1,
            0,
        )
    };
    assert!(jit != libc::MAP_FAILED, "MAP_JIT mmap failed");
    let with_jit = fork_p50_us(115);
    println!("{:>34}  {:>8}", "+ a 64 MiB MAP_JIT region", with_jit);
    println!(
        "\nMAP_JIT delta: {:+} us per fork  (the cost the AOT cache removes)",
        with_jit as i128 - with_aot as i128
    );

    let _ = big;
    let _ = std::fs::remove_dir_all(&dir);
}
