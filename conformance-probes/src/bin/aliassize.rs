//! Isolation probe for the MAP_SHARED-file alias-mapping HV_ERROR: does a
//! multi-page (32 KiB / 16 KiB-granule × 2) live file mapping succeed where a
//! single-page one does? Maps a 16 KiB then a 32 KiB MAP_SHARED file region and
//! reports success + read-back. Deterministic booleans only.

use std::ffi::CString;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn open_sized(path: &str, len: usize) -> i32 {
    let c = CString::new(path).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    if fd >= 0 {
        unsafe { libc::ftruncate(fd, len as libc::off_t) };
    }
    fd
}

fn test(tag: &str, file_len: usize, prot: i32, readonly_fd: bool) {
    let path = format!("/tmp/as_{tag}");
    let setup_fd = open_sized(&path, file_len);
    if setup_fd < 0 {
        println!("{tag}_open=ERR:{}", errno());
        return;
    }
    let fd = if readonly_fd {
        unsafe { libc::close(setup_fd) };
        let c = CString::new(path.as_str()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            println!("{tag}_reopen_ro=ERR:{}", errno());
            return;
        }
        fd
    } else {
        setup_fd
    };
    let m = unsafe {
        libc::mmap(std::ptr::null_mut(), file_len, prot, libc::MAP_SHARED, fd, 0)
    };
    if m == libc::MAP_FAILED {
        println!("{tag}_mmap=ERR:{}", errno());
        unsafe { libc::close(fd) };
        return;
    }
    println!("{tag}_mmap_ok=true");
    // If writable, write+read a marker through the mapping at the last page.
    if prot & libc::PROT_WRITE != 0 {
        let off = file_len - 16;
        let marker = *b"ALIASSIZE_MARK!!";
        unsafe {
            std::ptr::copy_nonoverlapping(marker.as_ptr(), (m as *mut u8).add(off), 16);
            let _ = libc::msync(m, file_len, libc::MS_SYNC);
        }
        let mut rb = [0u8; 16];
        let n = unsafe { libc::pread(fd, rb.as_mut_ptr() as *mut _, 16, off as libc::off_t) };
        println!("{tag}_writeback_ok={}", n == 16 && rb == marker);
    }
    unsafe {
        libc::munmap(m, file_len);
        libc::close(fd);
    }
}

fn main() {
    // Reproduce the dynamic-binary region layout that breaks the alias map:
    // a MAP_FIXED region at 512 GiB (0x80_0000_0000) and at 4 GiB
    // (0x1_0000_0000) — the loader's interpreter + ELF base. If these make the
    // subsequent MAP_SHARED alias fail, the trigger is a high identity region.
    for (tag, addr) in [("hi512g", 0x80_0000_0000usize), ("hi4g", 0x1_0000_0000usize)] {
        let m = unsafe {
            libc::mmap(
                addr as *mut _,
                64 * 1024,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        println!("{tag}_fixed_ok={}", m != libc::MAP_FAILED);
    }

    // 16 KiB (1 HVF page) RO and RW, then 32 KiB (2 pages) RO and RW — the head
    // failure was a 2-page (0x8000) RO mapping.
    test("ro16k", 16 * 1024, libc::PROT_READ, false);
    test("rw16k", 16 * 1024, libc::PROT_READ | libc::PROT_WRITE, false);
    test("ro32k", 32 * 1024, libc::PROT_READ, false);
    test("rw32k", 32 * 1024, libc::PROT_READ | libc::PROT_WRITE, false);
    // The exact head shape: a ~27 KiB file mapped at its real length.
    test("ro27k", 0x6994, libc::PROT_READ, false);
    test("ro27k_rdonlyfd", 0x6994, libc::PROT_READ, true);
}
