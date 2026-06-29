//! Minimal probe: does a SHARED (cross-process) FUTEX_WAIT with a RELATIVE
//! timeout actually time out? A `FUTEX_WAIT` on a matching word that nothing
//! wakes must return ETIMEDOUT after ~the requested interval. Uses the SHARED
//! path (no FUTEX_PRIVATE_FLAG) on a `MAP_SHARED` file word — the path carrick
//! routes through Darwin os_sync. Deterministic booleans only.

use std::time::Instant;

const FUTEX_WAIT: i64 = 0; // SHARED

fn main() {
    unsafe { libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777) };
    let fd = unsafe {
        libc::open(
            b"/tmp/fto.bin\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )
    };
    assert!(fd >= 0);
    assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
    let base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let word = base as *mut u32;
    unsafe { word.write_volatile(0) };

    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 500_000_000,
    }; // 500ms relative
    let start = Instant::now();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_futex,
            word,
            FUTEX_WAIT,
            0u32, // matches *word -> actually waits
            &ts as *const libc::timespec,
            std::ptr::null::<u32>(),
            0u32,
        )
    };
    let elapsed = start.elapsed();
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("timed_out={}", rc == -1 && errno == libc::ETIMEDOUT);
    println!("blocked_ms_ge_250={}", elapsed.as_millis() >= 250);
    println!("returned_not_hung=true");
}
