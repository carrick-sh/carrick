//! `mremap` growth of a `MAP_PRIVATE` file mapping (#3141).
//!
//! mremap(2): a grown mapping keeps its backing, so the pages it gains past
//! the old end are the file's next pages, at offset + old length. A 4-page
//! file has page `i` begin with the word `1 << i`, and a 3-page
//! `MAP_PRIVATE` `PROT_READ | PROT_WRITE` row of it is grown to 4 pages:
//! - in place (no `MREMAP_MAYMOVE`, the next page free), touched before the
//!   growth or not;
//! - moved (`MREMAP_MAYMOVE`, the next page taken by a blocker).
//!
//! The grown page must load 8 (the file's page 3), and the old pages keep
//! their contents (a dirtied page 0 stays dirty). A wrong answer prints the
//! word read; a missing tail kills the probe before its line prints.
//!
//! Deterministic: every placement is `MAP_FIXED` inside a reserved window.

use std::ffi::CString;
use std::ptr;

const PAGE: usize = 4096;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn word(base: *mut libc::c_void, page: usize) -> u64 {
    unsafe { ptr::read_volatile((base as *const u8).add(page * PAGE) as *const u64) }
}

/// A 4-page window: the file row MAP_FIXED over its first 3 pages, the 4th
/// left free (`blocked`: taken by an anonymous blocker instead).
fn row(fd: i32, blocked: bool) -> Option<*mut libc::c_void> {
    let window = unsafe {
        libc::mmap(
            ptr::null_mut(),
            4 * PAGE,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if window == libc::MAP_FAILED {
        return None;
    }
    let tail = unsafe { (window as *mut u8).add(3 * PAGE) as *mut libc::c_void };
    if unsafe { libc::munmap(tail, PAGE) } != 0 {
        return None;
    }
    let mapped = unsafe {
        libc::mmap(
            window,
            3 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            fd,
            0,
        )
    };
    if mapped != window {
        return None;
    }
    if blocked {
        let blocker = unsafe {
            libc::mmap(
                tail,
                PAGE,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if blocker != tail {
            return None;
        }
    }
    Some(window)
}

fn main() {
    let path = CString::new("/tmp/mremapfiletail.data").unwrap();
    let mut file = vec![0u8; 4 * PAGE];
    for page in 0..4 {
        file[page * PAGE..page * PAGE + 8].copy_from_slice(&(1u64 << page).to_le_bytes());
    }
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    let written = fd >= 0
        && unsafe { libc::write(fd, file.as_ptr().cast(), file.len()) } == file.len() as isize;
    println!("file_ok={written}");
    if !written {
        return;
    }

    for (name, touch) in [("in_place_cold", false), ("in_place_touched", true)] {
        let Some(base) = row(fd, false) else {
            println!("{name}_setup=false");
            continue;
        };
        if touch {
            let _ = word(base, 2);
        }
        let grown = unsafe { libc::mremap(base, 3 * PAGE, 4 * PAGE, 0) };
        println!("{name}_in_place={}", grown == base);
        if grown == libc::MAP_FAILED {
            println!("{name}_errno={}", errno());
        }
        if grown == base {
            println!("{name}_page2={}", word(grown, 2));
            println!("{name}_page3={}", word(grown, 3));
        }
        unsafe { libc::munmap(base, 4 * PAGE) };
    }

    match row(fd, true) {
        None => println!("moved_setup=false"),
        Some(base) => {
            unsafe { ptr::write_volatile(base as *mut u64, 0x40) };
            let moved = unsafe { libc::mremap(base, 3 * PAGE, 4 * PAGE, libc::MREMAP_MAYMOVE) };
            let ok = moved != libc::MAP_FAILED;
            println!("moved_ok={ok}");
            if !ok {
                println!("moved_errno={}", errno());
            }
            println!("moved_away={}", ok && moved != base);
            if ok {
                println!("moved_page0={}", word(moved, 0));
                println!("moved_page2={}", word(moved, 2));
                println!("moved_page3={}", word(moved, 3));
            }
        }
    }
    unsafe { libc::unlink(path.as_ptr()) };
}
