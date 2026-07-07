//! Exec-time reduction of LTP `tst_checkpoint` reattach.
//!
//! `ltpcheckpoint` covers the basic parent/child MAP_SHARED futex handshake
//! before exec. `setpgid03` exercises a stricter shape: the child `execve`s a
//! helper, the helper reopens an existing `/dev/shm` checkpoint file, mmaps it,
//! and then `FUTEX_WAKE`s a parent that is blocked in `FUTEX_WAIT`. The futex
//! word lives inside the checkpoint page, not at byte zero, so model that layout
//! explicitly.

use conformance_probes::{errno, report};
use std::ffi::CString;

const FUTEX_WAIT: libc::c_int = 0;
const FUTEX_WAKE: libc::c_int = 1;
const PAGE_SIZE: usize = 4096;

#[repr(C)]
struct CheckpointPage {
    _prefix: [u8; 0x4c],
    word: u32,
}

unsafe fn futex_op(
    addr: *mut u32,
    op: libc::c_int,
    val: u32,
    timeout: *const libc::timespec,
) -> libc::c_long {
    libc::syscall(libc::SYS_futex, addr, op, val, timeout)
}

unsafe fn checkpoint_word(map: *mut libc::c_void) -> *mut u32 {
    &mut (*(map as *mut CheckpointPage)).word as *mut u32
}

unsafe fn map_checkpoint(path: &CString) -> Result<(*mut libc::c_void, i32), i32> {
    let fd = libc::open(path.as_ptr(), libc::O_RDWR, 0);
    if fd < 0 {
        return Err(errno());
    }
    let map = libc::mmap(
        std::ptr::null_mut(),
        PAGE_SIZE,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );
    let _ = libc::close(fd);
    if map == libc::MAP_FAILED {
        return Err(errno());
    }
    Ok((map, fd))
}

unsafe fn child_mode(path: &CString) -> ! {
    let Ok((map, _fd)) = map_checkpoint(path) else {
        libc::_exit(2);
    };
    let word = checkpoint_word(map);
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    for _ in 0..2500 {
        let woke = futex_op(word, FUTEX_WAKE, i32::MAX as u32, std::ptr::null());
        if woke >= 1 {
            libc::_exit(0);
        }
        let _ = libc::nanosleep(&ts, std::ptr::null_mut());
    }
    libc::_exit(3);
}

unsafe fn exec_child(self_path: &CString, path: &CString) -> ! {
    let mode = CString::new("--child").unwrap();
    let argv = [
        self_path.as_ptr(),
        mode.as_ptr(),
        path.as_ptr(),
        std::ptr::null(),
    ];
    libc::execv(self_path.as_ptr(), argv.as_ptr());
    libc::_exit(127);
}

fn main() {
    unsafe {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--child") {
            let Some(path) = args.get(2).and_then(|s| CString::new(s.as_str()).ok()) else {
                libc::_exit(126);
            };
            child_mode(&path);
        }

        let self_path = match args.first().and_then(|s| CString::new(s.as_str()).ok()) {
            Some(path) => path,
            None => {
                report!(
                    shm_create_ok = false,
                    shm_mmap_ok = false,
                    exec_child_woke_parent_wait = false,
                    exec_child_exit_ok = false,
                );
                return;
            }
        };

        let path_string = format!("/dev/shm/carrick_ltpcheckpointexec_{}", libc::getpid());
        let path = CString::new(path_string).unwrap();
        let _ = libc::unlink(path.as_ptr());

        let fd = libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        let shm_create_ok = fd >= 0;
        report!(shm_create_ok = shm_create_ok);
        if fd < 0 {
            report!(
                shm_mmap_ok = false,
                exec_child_woke_parent_wait = false,
                exec_child_exit_ok = false,
            );
            return;
        }
        let _ = libc::ftruncate(fd, PAGE_SIZE as libc::off_t);
        let _ = libc::chmod(path.as_ptr(), 0o666);
        let map = libc::mmap(
            std::ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        let _ = libc::close(fd);
        let shm_mmap_ok = map != libc::MAP_FAILED;
        report!(shm_mmap_ok = shm_mmap_ok);
        if !shm_mmap_ok {
            let _ = libc::unlink(path.as_ptr());
            report!(
                exec_child_woke_parent_wait = false,
                exec_child_exit_ok = false,
            );
            return;
        }

        let word = checkpoint_word(map);
        std::ptr::write_volatile(word, 0);

        let child = libc::fork();
        if child == 0 {
            exec_child(&self_path, &path);
        }
        if child < 0 {
            let _ = libc::munmap(map, PAGE_SIZE);
            let _ = libc::unlink(path.as_ptr());
            report!(
                exec_child_woke_parent_wait = false,
                exec_child_exit_ok = false,
            );
            return;
        }

        let wait_timeout = libc::timespec {
            tv_sec: 3,
            tv_nsec: 0,
        };
        let wait_rc = futex_op(word, FUTEX_WAIT, 0, &wait_timeout);

        let mut status = 0i32;
        let _ = libc::wait4(child, &mut status, 0, std::ptr::null_mut());
        let child_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        report!(
            exec_child_woke_parent_wait = wait_rc == 0 && child_ok,
            exec_child_exit_ok = child_ok,
        );

        let _ = libc::munmap(map, PAGE_SIZE);
        let _ = libc::unlink(path.as_ptr());
    }
}
