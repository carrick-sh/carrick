//! Uninstrumented aarch64 Linux mmap contract reducer. Build locally with
//! rustc --target aarch64-unknown-linux-musl -C linker=rust-lld
//! -C link-self-contained=yes -O mmap-contract.rs -o mmap-contract.
//! Runs five 1000-iteration trials. Setup, fstat, close, formatting and munmap
//! are outside mmap's counter interval. Report the raw counter overhead;
//! never subtract it silently. No mapped byte is touched by this reducer.
use std::arch::asm;
use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;

unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, length: usize) -> c_int;
}

fn ticks() -> u64 {
    let value;
    unsafe {
        asm!("isb", "mrs {}, cntvct_el0", out(reg) value, options(nostack, preserves_flags));
    }
    value
}

fn main() {
    let file = std::fs::File::open("/usr/local/lib/libpython3.12.so.1.0").unwrap();
    let file_len = file.metadata().unwrap().len() as usize;
    let frequency: u64;
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack, preserves_flags));
    }
    assert!(frequency > 0);
    let scale = 1e6 / frequency as f64;
    println!("{{\"counter_hz\":{frequency},\"file_bytes\":{file_len},\"iterations\":1000}}");
    let mut overhead = 0;
    for _ in 0..1000 {
        let start = ticks();
        overhead += ticks() - start;
    }
    println!(
        "{{\"counter_pair_us\":{}}}",
        overhead as f64 * scale / 1000.0
    );
    for (name, len, prot, flags, fd) in [
        ("immutable_file", file_len, 1, 2, file.as_raw_fd()),
        ("anonymous_1MiB", 1024 * 1024, 3, 2 | 0x20, -1),
    ] {
        for trial in 0..5 {
            let (mut map_ticks, mut unmap_ticks) = (0, 0);
            for _ in 0..1000 {
                let start = ticks();
                let ptr = unsafe { mmap(std::ptr::null_mut(), len, prot, flags, fd, 0) };
                let mapped = ticks();
                assert_ne!(
                    ptr as usize,
                    usize::MAX,
                    "mmap: {}",
                    std::io::Error::last_os_error()
                );
                let unmap_start = ticks();
                let rc = unsafe { munmap(ptr, len) };
                let unmapped = ticks();
                assert_eq!(rc, 0, "munmap: {}", std::io::Error::last_os_error());
                map_ticks += mapped - start;
                unmap_ticks += unmapped - unmap_start;
            }
            println!(
                "{{\"case\":\"{name}\",\"trial\":{trial},\"mmap_us\":{},\"munmap_us\":{}}}",
                map_ticks as f64 * scale / 1000.0,
                unmap_ticks as f64 * scale / 1000.0
            );
        }
    }
}
