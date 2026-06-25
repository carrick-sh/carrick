//! mmap(/dev/zero) probe. A private mapping of /dev/zero is the classic
//! anonymous-zero-page idiom (predating MAP_ANONYMOUS): the mapping must
//! succeed and every byte must read back as zero. carrick routes character
//! devices specially, so a /dev/zero mmap that didn't fall back to a
//! zero-filled anonymous page would either fail or hand back garbage. This
//! probe pins both the success and the zero-fill. The harness diffs carrick vs
//! Linux line by line.
//!
//! Deterministic: two booleans only (mmap succeeded; first bytes are zero).
//! Never the mapping address.

fn main() {
    // /dev/zero is provided by the synthetic /dev on the empty run-elf rootfs
    // and exists in the Docker alpine image, so no seeding is needed.
    let fd = unsafe { libc::open(b"/dev/zero\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if fd < 0 {
        println!("open=ERR:{}", errno());
        return;
    }

    let len = 4096usize;
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };

    if p == libc::MAP_FAILED {
        println!("mmap_ok=false");
        println!("first_byte_zero=false");
        unsafe { libc::close(fd) };
        return;
    }
    println!("mmap_ok=true");

    // /dev/zero is all zeroes: the first 16 bytes of the mapping must read 0.
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, 16) };
    let all_zero = bytes.iter().all(|&b| b == 0);
    println!("first_byte_zero={}", all_zero);

    unsafe {
        libc::munmap(p, len);
        libc::close(fd);
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
