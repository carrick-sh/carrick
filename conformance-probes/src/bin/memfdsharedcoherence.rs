//! memfd file/mapping coherence probe: a memfd is one inode, and every view
//! of it — read/pread/pwrite on any fd, every `MAP_SHARED` mapping in every
//! process that inherited one, and the map-time snapshot of a `MAP_PRIVATE`
//! mapping — must observe the same bytes.
//!
//! Covers:
//! 1. A store through a `MAP_SHARED` mapping is visible to `pread` on the fd,
//!    on a `dup` of the fd, and through a second `MAP_SHARED` mapping.
//! 2. A `pwrite` on the fd is visible through an existing `MAP_SHARED` mapping.
//! 3. A forked child's store through the inherited mapping and its `pwrite`
//!    are both visible to the parent after `waitpid`.
//! 4. `MAP_PRIVATE` sees the file's contents at map time, keeps its own
//!    copy-on-write bytes out of the file, and a dirtied page ignores a later
//!    file write. (Whether a CLEAN private page tracks a later file write is
//!    `mmapprivatefiletrack`'s question.)
//! 5. Stores persist past `msync`, `munmap`, and closing the last fd while a
//!    mapping is still live.
//!
//! Deterministic: prints booleans only via `report!`; the one fork is
//! bounded by `waitpid` plus an alarm.

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
    fn close(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
            self.0 = -1;
        }
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        self.close();
    }
}

struct MapGuard {
    addr: *mut u8,
    len: usize,
}

impl MapGuard {
    unsafe fn new(fd: i32, prot: i32, flags: i32, len: usize) -> Self {
        let addr = libc::mmap(std::ptr::null_mut(), len, prot, flags, fd, 0);
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
    fn unmap(&mut self) {
        if self.valid() {
            unsafe {
                libc::munmap(self.addr as *mut libc::c_void, self.len);
            }
            self.addr = std::ptr::null_mut();
        }
    }
}

impl Drop for MapGuard {
    fn drop(&mut self) {
        self.unmap();
    }
}

unsafe fn memfd(name: &str) -> FdGuard {
    let name = CString::new(name).unwrap_or_default();
    let fd = libc::syscall(libc::SYS_memfd_create, name.as_ptr(), MFD_CLOEXEC) as i32;
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

fn main() {
    unsafe {
        arm_alarm_ms(5000);

        // 1 + 2: fd views and shared mappings of one memfd agree.
        let fd = memfd("coherence");
        let created = fd.get() >= 0 && libc::ftruncate(fd.get(), FILE_LEN as libc::off_t) == 0;
        let map_a = MapGuard::new(
            fd.get(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            FILE_LEN,
        );
        let map_b = MapGuard::new(
            fd.get(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            FILE_LEN,
        );
        let dup_fd = FdGuard(libc::dup(fd.get()));
        report!(
            memfd_created = created,
            shared_map_ok = map_a.valid() && map_b.valid(),
            initial_zero = map_a.load(0) == 0 && pread_byte(fd.get(), PAGE + 7) == Some(0),
        );

        map_a.store(0, 0x5a);
        map_a.store(PAGE + 7, 0x6b);
        report!(
            store_visible_to_pread =
                pread_byte(fd.get(), 0) == Some(0x5a) && pread_byte(fd.get(), PAGE + 7) == Some(0x6b),
            store_visible_to_dup_pread = pread_byte(dup_fd.get(), PAGE + 7) == Some(0x6b),
            store_visible_in_second_map = map_b.load(0) == 0x5a && map_b.load(PAGE + 7) == 0x6b,
        );

        let pwrite_ok = pwrite_byte(fd.get(), 2 * PAGE + 100, 0x3c)
            && pwrite_byte(dup_fd.get(), 3 * PAGE + 1, 0x4d);
        report!(
            pwrite_ok = pwrite_ok,
            pwrite_visible_in_map =
                map_a.load(2 * PAGE + 100) == 0x3c && map_b.load(3 * PAGE + 1) == 0x4d,
        );

        // 3: fork inherits the mapping and the fd; the child's writes land in
        // the same inode the parent reads.
        let child = libc::fork();
        if child == 0 {
            map_a.store(200, 0x99);
            let ok = pwrite_byte(fd.get(), 300, 0x88);
            libc::_exit(if ok { 0 } else { 1 });
        }
        let mut status = 0;
        let waited = child > 0 && libc::waitpid(child, &mut status, 0) == child;
        report!(
            fork_child_exited_ok =
                waited && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            fork_child_store_visible_to_parent =
                map_a.load(200) == 0x99 && pread_byte(fd.get(), 200) == Some(0x99),
            fork_child_pwrite_visible_to_parent =
                map_b.load(300) == 0x88 && pread_byte(fd.get(), 300) == Some(0x88),
        );

        // 4: MAP_PRIVATE copy-on-write against the same inode.
        let map_private = MapGuard::new(
            fd.get(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            FILE_LEN,
        );
        report!(
            private_map_ok = map_private.valid(),
            private_map_initial_contents =
                map_private.load(0) == 0x5a && map_private.load(PAGE + 7) == 0x6b,
        );
        map_private.store(0, 0x22);
        let file_write_on_dirty_page = pwrite_byte(fd.get(), 1, 0x33);
        report!(
            private_store_not_in_file = pread_byte(fd.get(), 0) == Some(0x5a) && map_a.load(0) == 0x5a,
            private_store_visible_privately = map_private.load(0) == 0x22,
            private_dirty_page_keeps_cow_copy = file_write_on_dirty_page
                && map_a.load(1) == 0x33
                && map_private.load(1) == 0
                && map_private.load(0) == 0x22,
        );

        // 5: persistence past msync/munmap/close.
        let msync_rc = libc::msync(map_a.addr as *mut libc::c_void, FILE_LEN, libc::MS_SYNC);
        let mut map_b = map_b;
        map_b.unmap();
        let mut fd = fd;
        let mut dup_fd = dup_fd;
        fd.close();
        dup_fd.close();
        map_a.store(PAGE, 0x77);
        report!(
            msync_ok = msync_rc == 0,
            munmap_keeps_other_map = map_a.load(0) == 0x5a && map_a.load(200) == 0x99,
            map_outlives_last_fd = map_a.load(PAGE) == 0x77 && map_a.load(300) == 0x88,
        );

        disarm_alarm();
    }
}
