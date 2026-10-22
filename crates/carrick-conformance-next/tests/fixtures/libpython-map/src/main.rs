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
    extra_flags: i32,
    offset: usize,
    name: &str,
) -> io::Result<*mut libc::c_void> {
    let result = unsafe {
        libc::mmap(
            address,
            len,
            prot,
            libc::MAP_PRIVATE | 0x800 | extra_flags,
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
fn run(offset: usize, anonymous_reservation: bool, source: Option<&str>) -> io::Result<()> {
    let (file, contents) = if let Some(path) = source {
        // An OCI lower-layer file takes the production immutable-file path.
        // The static probe can open libpython even while its loader is broken.
        let file = File::open(path)?;
        let inspected_len = (DATA_DELTA + DATA_LEN + 1).max(offset + DATA_LEN);
        let mut bytes = vec![0; inspected_len];
        file.read_exact_at(&mut bytes, 0)?;
        (file, bytes)
    } else {
        let path = format!("/tmp/libpython-map-{}-{offset:x}", std::process::id());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        std::fs::remove_file(path)?;
        let bytes: Vec<_> = (0..ROUNDED)
            .map(|i| ((i / PAGE * 17 + i % PAGE) % 251) as u8)
            .collect();
        file.write_all_at(&bytes, 0)?;
        (file, bytes)
    };
    let reservation = map(
        &file,
        std::ptr::null_mut(),
        RESERVE,
        libc::PROT_NONE,
        if anonymous_reservation {
            libc::MAP_ANONYMOUS
        } else {
            0
        },
        0,
        "reservation",
    )?;
    let _mapping = Mapping(reservation);
    let base = ((reservation as usize + 0xffff) & !0xffff) as *mut libc::c_void;
    map(
        &file,
        base,
        TEXT,
        libc::PROT_READ | libc::PROT_EXEC,
        libc::MAP_FIXED,
        0,
        "text",
    )?;
    // Align text within the reservation, then trim its prefix and suffix.
    // If Linux already aligned the reservation, split the unused suffix so
    // both trim calls remain real, nonempty munmaps.
    let prefix = base as usize - reservation as usize;
    let text_end = base as usize + 0x64f000;
    let reservation_end = reservation as usize + ROUNDED;
    let trims = if prefix != 0 {
        [
            (reservation as usize, prefix),
            (text_end, reservation_end - text_end),
        ]
    } else {
        [
            (text_end, PAGE),
            (text_end + PAGE, reservation_end - text_end - PAGE),
        ]
    };
    for (address, len) in trims {
        let rc = unsafe { libc::munmap(address as *mut libc::c_void, len) };
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
        libc::MAP_FIXED,
        offset,
        "data",
    )?;
    let bytes = unsafe { std::slice::from_raw_parts_mut(data.cast::<u8>(), DATA_LEN) };
    assert_eq!(bytes, &contents[offset..offset + DATA_LEN]);
    for i in (0..DATA_LEN).step_by(PAGE) {
        bytes[i] ^= 0xff;
    }
    let mut observed = vec![0; contents.len()];
    file.read_exact_at(&mut observed, 0)?;
    assert_eq!(observed, contents, "private stores reached the file");
    for i in (0..DATA_LEN).step_by(PAGE) {
        assert_eq!(
            bytes[i],
            contents[offset + i] ^ 0xff,
            "private store was lost"
        );
    }
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
    let source = std::env::args().nth(1);
    for anonymous_reservation in [true, false] {
        for offset in [0x47a000, 0x479000] {
            println!(
                "reservation_flags={}",
                0x802 | if anonymous_reservation { 0x20 } else { 0 }
            );
            println!("file_offset={offset}");
            run(offset, anonymous_reservation, source.as_deref())?;
        }
    }
    Ok(())
}
