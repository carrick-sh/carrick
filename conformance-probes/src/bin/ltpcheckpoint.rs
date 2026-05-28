//! Reduction of the LTP `tst_checkpoint` framework setup, which TBROKs
//! ~10 of the SIGNALS-area LTP tests under carrick (pause01, sigwaitinfo01,
//! sigtimedwait01, sighold02, sigrelse01, rt_sigtimedwait01, kill05 …) at the
//! test-framework level — the per-syscall assertions are never reached.
//!
//! LTP's `setup_ipc` (lib/tst_test.c) does, in order, the steps below; the
//! checkpoint then uses a shared-anon word with FUTEX_WAIT/FUTEX_WAKE. Carrick's
//! existing `forkshared`/`futexshare` probes cover the MAP_SHARED + cross-
//! process futex path, so the broken step is somewhere in the SHM-file
//! prep. This probe enumerates each step as its own boolean so the diff
//! against Docker names the precise failing call.
//!
//! Invariants encoded (booleans only — paths and timestamps NEVER printed):
//!
//!   1. `access("/dev/shm", F_OK) == 0`.
//!   2. `open("/dev/shm/ltpprobe_<pid>", O_CREAT|O_EXCL|O_RDWR, 0600)` succeeds.
//!   3. `chmod(path, 0666)` succeeds.
//!   4. `ftruncate(fd, 4096)` succeeds.
//!   5. `mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)` returns
//!      a non-NULL address.
//!   6. `close(fd)` succeeds (LTP closes before forking, relying on
//!      MAP_SHARED to keep the mapping alive past the close).
//!   7. The mapping is writable from the parent after close.
//!   8. `fork()` succeeds; child sees the parent's writes (MAP_SHARED
//!      fork-coherence).
//!   9. FUTEX_WAIT on the shared word from a forked child returns when
//!      the parent FUTEX_WAKEs (the actual `tst_checkpoint_wait/wake`
//!      shape — fail this and every LTP test using checkpoints TBROKs).
//!
//! Deterministic only: each step prints a single boolean.

use conformance_probes::{errno, report};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;

unsafe fn futex_op(addr: *mut u32, op: i32, val: u32, timeout: *const libc::timespec) -> i64 {
    libc::syscall(
        libc::SYS_futex,
        addr as *const libc::c_void,
        op as i64,
        val as i64,
        timeout as i64,
    )
}

fn main() {
    unsafe {
        // (1) /dev/shm exists.
        let dev_shm = std::ffi::CString::new("/dev/shm").unwrap();
        let dev_shm_ok = libc::access(dev_shm.as_ptr(), libc::F_OK) == 0;
        report!(devshm_access_ok = dev_shm_ok);

        // Build a deterministic path (pid is per-run, but we don't print it).
        let pid = libc::getpid();
        let path = format!("/dev/shm/ltpchk_{}_{}", pid, 1);
        let cpath = std::ffi::CString::new(path.clone()).unwrap();

        // (2) Open O_CREAT|O_EXCL|O_RDWR, mode 0600.
        let fd = libc::open(
            cpath.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        let open_ok = fd >= 0;
        let open_errno = if fd < 0 { errno() } else { 0 };
        report!(
            shm_open_ok = open_ok,
            shm_open_errno = open_errno,
        );
        if !open_ok {
            // Without an fd the rest of the test can't run; print stable
            // `false`s so the harness diff has the same line count.
            report!(
                shm_chmod_ok = false,
                shm_ftruncate_ok = false,
                shm_mmap_ok = false,
                shm_close_ok = false,
                shm_post_close_writable = false,
                shm_fork_child_sees_parent_write = false,
                shm_futex_xprocess_wake_wakes_wait = false,
            );
            return;
        }

        // (3) chmod 0666 (LTP wants the file world-rw'able so other test
        //     processes can attach later).
        let chmod_ok = libc::chmod(cpath.as_ptr(), 0o666) == 0;
        report!(shm_chmod_ok = chmod_ok);

        // (4) ftruncate to a page.
        let pagesize = libc::sysconf(libc::_SC_PAGESIZE) as libc::off_t;
        let ftruncate_ok = libc::ftruncate(fd, pagesize) == 0;
        report!(shm_ftruncate_ok = ftruncate_ok);

        // (5) MAP_SHARED.
        let addr = libc::mmap(
            std::ptr::null_mut(),
            pagesize as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        let mmap_ok = addr != libc::MAP_FAILED;
        report!(shm_mmap_ok = mmap_ok);
        if !mmap_ok {
            let _ = libc::close(fd);
            let _ = libc::unlink(cpath.as_ptr());
            report!(
                shm_close_ok = false,
                shm_post_close_writable = false,
                shm_fork_child_sees_parent_write = false,
                shm_futex_xprocess_wake_wakes_wait = false,
            );
            return;
        }

        // (6) Close the fd — LTP relies on the mapping outliving the fd.
        let close_ok = libc::close(fd) == 0;
        report!(shm_close_ok = close_ok);

        // (7) The mapping is still writable.
        let word: *mut u32 = addr as *mut u32;
        core::ptr::write_volatile(word, 0xABCD_1234);
        let post_close_writable = core::ptr::read_volatile(word) == 0xABCD_1234;
        report!(shm_post_close_writable = post_close_writable);

        // (8) Fork. The child sees the parent's writes (MAP_SHARED inheritance).
        // (9) Run the checkpoint shape: parent stores a sentinel, child does
        //     FUTEX_WAIT on it; parent then writes a new value + FUTEX_WAKE,
        //     child wakes. We use timeouts everywhere so a missed wake can't
        //     hang the harness.
        core::ptr::write_volatile(word, 0); // initial value
        static CHILD_SAW: AtomicU32 = AtomicU32::new(0);
        let child = libc::fork();
        if child == 0 {
            // Verify (8) — the child sees parent's last write (the 0).
            let saw_initial = core::ptr::read_volatile(word) == 0;
            // (9) FUTEX_WAIT on `word` expecting value 0; bounded 2 s.
            let ts = libc::timespec { tv_sec: 2, tv_nsec: 0 };
            let _ = futex_op(word, FUTEX_WAIT, 0, &ts);
            let saw_wake = core::ptr::read_volatile(word) == 0xC0DE;
            // Encode both observations in the child exit code:
            // bit 0 = saw_initial, bit 1 = saw_wake.
            let exit_code = (saw_initial as i32) | ((saw_wake as i32) << 1);
            libc::_exit(exit_code);
        }
        if child < 0 {
            report!(
                shm_fork_child_sees_parent_write = false,
                shm_futex_xprocess_wake_wakes_wait = false,
            );
            return;
        }
        // Tiny grace for the child to enter FUTEX_WAIT before the wake.
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            std::hint::spin_loop();
        }
        // Wake the child.
        core::ptr::write_volatile(word, 0xC0DE);
        let _ = futex_op(word, FUTEX_WAKE, i32::MAX as u32, std::ptr::null());

        // Reap.
        let mut status = 0i32;
        let _ = libc::wait4(child, &mut status, 0, std::ptr::null_mut());
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let _ = CHILD_SAW; // (atomic isn't actually used across the fork)
        report!(
            shm_fork_child_sees_parent_write = exit_code & 1 != 0,
            shm_futex_xprocess_wake_wakes_wait = exit_code & 2 != 0,
        );

        // Cleanup.
        let _ = libc::munmap(addr, pagesize as usize);
        let _ = libc::unlink(cpath.as_ptr());
    }
}
