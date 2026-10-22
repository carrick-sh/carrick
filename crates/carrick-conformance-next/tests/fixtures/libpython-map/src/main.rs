//! Clean-room mmap(2) loader layout; no loader implementation sources.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

const PAGE: usize = 4096;
const RESERVE: usize = 0x65ee48;
const TEXT: usize = 0x64ee48;
const DATA_DELTA: usize = 0x47a000;
const DATA_LEN: usize = 0x1d4000;
const ROUNDED: usize = 0x65f000;

struct Mapping(*mut libc::c_void);
impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0, ROUNDED) };
    }
}
fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
fn map(
    file: &File,
    address: *mut libc::c_void,
    len: usize,
    prot: i32,
    fixed: bool,
    offset: usize,
    name: &str,
) -> io::Result<*mut libc::c_void> {
    let result = unsafe {
        libc::mmap(
            address,
            len,
            prot,
            libc::MAP_PRIVATE | 0x800 | if fixed { libc::MAP_FIXED } else { 0 },
            file.as_raw_fd(),
            offset as libc::off_t,
        )
    };
    let error = if result == libc::MAP_FAILED {
        errno()
    } else {
        0
    };
    println!("{name}_errno={error}");
    if error != 0 {
        Err(io::Error::from_raw_os_error(error))
    } else {
        Ok(result)
    }
}
#[allow(
    clippy::disallowed_methods,
    reason = "standalone Linux guest fixture; these are guest file operations, not carrier services"
)]
fn run(offset: usize) -> io::Result<()> {
    let path = format!("/tmp/libpython-map-{}-{offset:x}", std::process::id());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)?;
    std::fs::remove_file(path)?;
    let contents: Vec<_> = (0..ROUNDED)
        .map(|i| ((i / PAGE * 17 + i % PAGE) % 251) as u8)
        .collect();
    file.write_all_at(&contents, 0)?;
    let base = map(
        &file,
        std::ptr::null_mut(),
        RESERVE,
        libc::PROT_NONE,
        false,
        0,
        "reservation",
    )?;
    let _mapping = Mapping(base);
    map(
        &file,
        base,
        TEXT,
        libc::PROT_READ | libc::PROT_EXEC,
        true,
        0,
        "text",
    )?;
    // The trace omits the two trim addresses. Trim only unused suffix pages;
    // the whole data target remains covered by the file-backed reservation.
    for delta in [0x65e000, 0x65d000] {
        let rc = unsafe { libc::munmap(base.byte_add(delta), PAGE) };
        println!("trim_errno={}", if rc == 0 { 0 } else { errno() });
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let data = unsafe { base.byte_add(DATA_DELTA) };
    let rc = unsafe { libc::mprotect(data, DATA_LEN, libc::PROT_NONE) };
    println!("protect_errno={}", if rc == 0 { 0 } else { errno() });
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    map(
        &file,
        data,
        DATA_LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        true,
        offset,
        "data",
    )?;
    let bytes = unsafe { std::slice::from_raw_parts_mut(data.cast::<u8>(), DATA_LEN) };
    assert_eq!(bytes, &contents[offset..offset + DATA_LEN]);
    for i in (0..DATA_LEN).step_by(PAGE) {
        bytes[i] ^= 0xff;
    }
    let mut observed = vec![0; ROUNDED];
    file.read_exact_at(&mut observed, 0)?;
    assert_eq!(observed, contents, "private stores reached the file");
    assert_eq!(
        unsafe { *base.byte_add(DATA_DELTA - 1).cast::<u8>() },
        contents[DATA_DELTA - 1]
    );
    assert_eq!(
        unsafe { *base.byte_add(DATA_DELTA + DATA_LEN).cast::<u8>() },
        contents[DATA_DELTA + DATA_LEN]
    );
    println!("contents_private_neighbors=ok");
    Ok(())
}
fn main() -> io::Result<()> {
    println!(
        "source_sha256={}",
        option_env!("CARRICK_LIBPYTHON_MAP_SOURCE_SHA256").unwrap_or("unrecorded")
    );
    // Both the congruent and incongruent 4 KiB file offsets are legal on Linux.
    for offset in [0x47a000, 0x479000] {
        println!("file_offset={offset}");
        run(offset)?;
    }
    Ok(())
}
