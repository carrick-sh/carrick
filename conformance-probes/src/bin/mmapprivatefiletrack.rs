//! `MAP_PRIVATE` file-tracking probe: a private mapping's copy-on-write copy
//! is created per page on first store, so a page the mapping has NOT dirtied
//! keeps reading the file's live page cache and observes a later write(2) to
//! the file, while a dirtied page keeps its private copy. Exercised against
//! both a `memfd` and a regular file so the two inode kinds are recorded
//! side by side.
//!
//! Covers, per inode kind:
//! 1. The mapping sees the file's contents at map time.
//! 2. A store through the mapping stays out of the file.
//! 3. A `pwrite` to a page the mapping has only read is visible through the
//!    mapping (the clean page still tracks the file).
//! 4. A `pwrite` to a page the mapping has dirtied is NOT visible through the
//!    mapping (the private copy is detached).
//!
//! Deterministic: booleans only via `report!`; no fork, bounded by an alarm.

use conformance_probes::{arm_alarm_ms, disarm_alarm, report};
use std::ffi::CString;

const MFD_CLOEXEC: u32 = 0x0001;
const PAGE: usize = 4096;
const FILE_LEN: usize = 4 * PAGE;

struct FdGuard(i32);

impl FdGuard {
    fn get(&self) -> i32 {
        self.0
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

struct MapGuard {
    addr: *mut u8,
    len: usize,
}

impl MapGuard {
    unsafe fn new(fd: i32, len: usize) -> Self {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        Self {
            addr: if addr == libc::MAP_FAILED {
                std::ptr::null_mut()
            } else {
                addr as *mut u8
            },
            len,
        }
    }
    fn valid(&self) -> bool {
        !self.addr.is_null()
    }
    unsafe fn load(&self, off: usize) -> u8 {
        if self.valid() {
            self.addr.add(off).read_volatile()
        } else {
            0
        }
    }
    unsafe fn store(&self, off: usize, byte: u8) {
        if self.valid() {
            self.addr.add(off).write_volatile(byte);
        }
    }
}

impl Drop for MapGuard {
    fn drop(&mut self) {
        if self.valid() {
            unsafe {
                libc::munmap(self.addr as *mut libc::c_void, self.len);
            }
        }
    }
}

unsafe fn memfd(name: &str) -> FdGuard {
    let name = CString::new(name).unwrap_or_default();
    FdGuard(libc::syscall(libc::SYS_memfd_create, name.as_ptr(), MFD_CLOEXEC) as i32)
}

unsafe fn regular_file() -> FdGuard {
    let path = CString::new(format!("/tmp/mmapprivatefiletrack.{}", libc::getpid()))
        .unwrap_or_default();
    let fd = libc::open(
        path.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
        0o600,
    );
    if fd >= 0 {
        libc::unlink(path.as_ptr());
    }
    FdGuard(fd)
}

unsafe fn pread_byte(fd: i32, off: usize) -> Option<u8> {
    let mut byte = [0u8; 1];
    let rc = libc::pread(
        fd,
        byte.as_mut_ptr() as *mut libc::c_void,
        1,
        off as libc::off_t,
    );
    (rc == 1).then_some(byte[0])
}

unsafe fn pwrite_byte(fd: i32, off: usize, byte: u8) -> bool {
    libc::pwrite(fd, (&byte as *const u8).cast(), 1, off as libc::off_t) == 1
}

struct Outcome {
    created: bool,
    map_ok: bool,
    initial_contents: bool,
    store_not_in_file: bool,
    clean_page_sees_file_write: bool,
    dirty_page_keeps_cow_copy: bool,
}

unsafe fn exercise(fd: &FdGuard) -> Outcome {
    let created = fd.get() >= 0
        && libc::ftruncate(fd.get(), FILE_LEN as libc::off_t) == 0
        && pwrite_byte(fd.get(), 0, 0x5a)
        && pwrite_byte(fd.get(), PAGE + 7, 0x6b);
    let map = MapGuard::new(fd.get(), FILE_LEN);
    let map_ok = map.valid();
    // Read both pages first so page 1 is resident-but-clean before the file
    // write lands on it.
    let initial_contents = map.load(0) == 0x5a && map.load(PAGE + 7) == 0x6b;
    map.store(0, 0x22);
    let file_write_clean = pwrite_byte(fd.get(), PAGE + 8, 0x33);
    let file_write_dirty = pwrite_byte(fd.get(), 1, 0x44);
    Outcome {
        created,
        map_ok,
        initial_contents,
        store_not_in_file: pread_byte(fd.get(), 0) == Some(0x5a) && map.load(0) == 0x22,
        clean_page_sees_file_write: file_write_clean && map.load(PAGE + 8) == 0x33,
        dirty_page_keeps_cow_copy: file_write_dirty
            && pread_byte(fd.get(), 1) == Some(0x44)
            && map.load(1) == 0
            && map.load(0) == 0x22,
    }
}

fn main() {
    unsafe {
        arm_alarm_ms(5000);

        let memfd = memfd("privatetrack");
        let m = exercise(&memfd);
        report!(
            memfd_created = m.created,
            memfd_private_map_ok = m.map_ok,
            memfd_initial_contents = m.initial_contents,
            memfd_store_not_in_file = m.store_not_in_file,
            memfd_clean_page_sees_file_write = m.clean_page_sees_file_write,
            memfd_dirty_page_keeps_cow_copy = m.dirty_page_keeps_cow_copy,
        );

        let file = regular_file();
        let f = exercise(&file);
        report!(
            file_created = f.created,
            file_private_map_ok = f.map_ok,
            file_initial_contents = f.initial_contents,
            file_store_not_in_file = f.store_not_in_file,
            file_clean_page_sees_file_write = f.clean_page_sees_file_write,
            file_dirty_page_keeps_cow_copy = f.dirty_page_keeps_cow_copy,
        );

        disarm_alarm();
    }
}
