//! MAP_SHARED file writeback across fork.
//!
//! `forkshared` proves mmap-to-mmap visibility across a process tree. This probe
//! additionally reads the backing file after parent and child writes, pinning the
//! file-page-cache side of the contract that x86 backends emulate with either a
//! real host MAP_SHARED alias (KVM/HVF) or explicit file flush/refresh hooks
//! (bhyve).

use conformance_probes::{reap, report};
use std::sync::atomic::{compiler_fence, Ordering};

const PAGE: usize = 4096;
const PARENT_PRE: u64 = 0x1111_2222_3333_4444;
const CHILD_POST: u64 = 0x5555_6666_7777_8888;
const PARENT_POST: u64 = 0x9999_AAAA_BBBB_CCCC;

unsafe fn put(map: *mut u64, idx: usize, value: u64) {
    std::ptr::write_volatile(map.add(idx), value);
    compiler_fence(Ordering::SeqCst);
}

unsafe fn get(map: *mut u64, idx: usize) -> u64 {
    compiler_fence(Ordering::SeqCst);
    std::ptr::read_volatile(map.add(idx))
}

unsafe fn read_word(fd: i32, idx: usize) -> Option<u64> {
    let mut value = 0u64;
    let n = libc::pread(
        fd,
        &mut value as *mut u64 as *mut libc::c_void,
        std::mem::size_of::<u64>(),
        (idx * std::mem::size_of::<u64>()) as libc::off_t,
    );
    if n == std::mem::size_of::<u64>() as isize {
        Some(value)
    } else {
        None
    }
}

fn main() {
    unsafe {
        libc::mkdir(c"/tmp".as_ptr(), 0o777);
        let path = c"/tmp/mmapfileforkwriteback_probe";
        let fd = libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        let setup_open = fd >= 0;
        report!(setup_open = setup_open);
        if !setup_open {
            report!(
                setup_truncate = false,
                setup_mmap = false,
                child_saw_parent_pre = false,
                parent_saw_child_map = false,
                file_saw_child_write = false,
                file_saw_parent_post = false,
            );
            return;
        }

        let setup_truncate = libc::ftruncate(fd, PAGE as libc::off_t) == 0;
        report!(setup_truncate = setup_truncate);
        if !setup_truncate {
            libc::close(fd);
            report!(
                setup_mmap = false,
                child_saw_parent_pre = false,
                parent_saw_child_map = false,
                file_saw_child_write = false,
                file_saw_parent_post = false,
            );
            return;
        }

        let map = libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        ) as *mut u64;
        let setup_mmap = map != libc::MAP_FAILED as *mut u64;
        report!(setup_mmap = setup_mmap);
        if !setup_mmap {
            libc::close(fd);
            report!(
                child_saw_parent_pre = false,
                parent_saw_child_map = false,
                file_saw_child_write = false,
                file_saw_parent_post = false,
            );
            return;
        }

        put(map, 0, PARENT_PRE);

        let pid = libc::fork();
        if pid == 0 {
            let child_saw_parent_pre = get(map, 0) == PARENT_PRE;
            put(map, 1, CHILD_POST);
            libc::_exit(if child_saw_parent_pre { 0 } else { 7 });
        }

        let (wait_rc, status) = reap(pid);
        let child_saw_parent_pre =
            wait_rc == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        report!(child_saw_parent_pre = child_saw_parent_pre);

        let parent_saw_child_map = get(map, 1) == CHILD_POST;
        let file_saw_child_write = read_word(fd, 1) == Some(CHILD_POST);
        put(map, 2, PARENT_POST);
        let file_saw_parent_post = read_word(fd, 2) == Some(PARENT_POST);

        report!(
            parent_saw_child_map = parent_saw_child_map,
            file_saw_child_write = file_saw_child_write,
            file_saw_parent_post = file_saw_parent_post,
        );

        libc::munmap(map as *mut libc::c_void, PAGE);
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
}
