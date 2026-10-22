//! Clean-room getdents(2) directory stream into untouched destinations.
use std::ffi::CString;

const CAPACITY: usize = 32768;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

unsafe fn list(path: &CString, buffer: *mut u8, kind: &str) -> Option<Vec<Vec<u8>>> {
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
    };
    println!("{kind}_openat_errno={}", if fd < 0 { errno() } else { 0 });
    if fd < 0 {
        return None;
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstat(fd, stat.as_mut_ptr()) };
    println!("{kind}_fstat_errno={}", if rc < 0 { errno() } else { 0 });
    let mut names = Vec::new();
    let mut failure = 0;
    for iteration in 0..10000 {
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buffer, CAPACITY) };
        if n < 0 {
            failure = errno();
            break;
        }
        if n == 0 {
            break;
        }
        if iteration == 9999 {
            failure = -2;
            break;
        }
        let bytes = unsafe { std::slice::from_raw_parts(buffer, n as usize) };
        let mut at = 0;
        while at < bytes.len() {
            if bytes.len() - at < 20 {
                failure = -3;
                break;
            }
            let length = u16::from_ne_bytes([bytes[at + 16], bytes[at + 17]]) as usize;
            if length < 20 || length > bytes.len() - at {
                failure = -4;
                break;
            }
            let Some(end) = bytes[at + 19..at + length].iter().position(|&b| b == 0) else {
                failure = -5;
                break;
            };
            names.push(bytes[at + 19..at + 19 + end].to_vec());
            at += length;
        }
        if failure != 0 {
            break;
        }
    }
    unsafe {
        libc::close(fd);
    }
    println!("{kind}_getdents64_errno={failure}");
    names.sort();
    let unique = names.windows(2).all(|pair| pair[0] != pair[1]);
    println!("{kind}_entries={}", names.len());
    println!("{kind}_unique={unique}");
    if rc < 0 || failure != 0 || !unique {
        None
    } else {
        Some(names)
    }
}

fn main() {
    println!(
        "source_sha256={}",
        option_env!("CARRICK_DIRECTORY_COPYOUT_SOURCE_SHA256").unwrap_or("unbound")
    );
    let path = CString::new(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "/usr/local/lib/python3.12".into()),
    )
    .unwrap();
    let ok = unsafe {
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            CAPACITY,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        println!(
            "mmap_errno={}",
            if mapped == libc::MAP_FAILED {
                errno()
            } else {
                0
            }
        );
        if mapped == libc::MAP_FAILED {
            std::process::exit(1);
        }
        // Do not touch either output before the first getdents64.
        let first = list(&path, mapped.cast(), "mmap");
        libc::munmap(mapped, CAPACITY);
        let allocated = libc::malloc(CAPACITY);
        println!(
            "malloc_errno={}",
            if allocated.is_null() { errno() } else { 0 }
        );
        if allocated.is_null() {
            std::process::exit(1);
        }
        let second = list(&path, allocated.cast(), "malloc");
        libc::free(allocated);
        let equal = first.is_some() && first == second;
        println!("listings_equal={equal}");
        equal
    };
    if !ok {
        std::process::exit(1);
    }
}
