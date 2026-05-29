//! `shmat(2)` SHM_RDONLY enforcement — Linux maps the segment read-only, so a
//! store through the mapping faults (SIGSEGV/SEGV_ACCERR). carrick (pre-fix)
//! ignores the flag entirely (`dispatch/sysv.rs` shmat drops `_flag` and always
//! sets `host_prot = PROT_READ|PROT_WRITE`), maps the alias RW at both the host
//! page and stage-1, and the store silently succeeds — the exact divergence
//! this pins.
//!
//! Method (crash-class → isolated in a forked child, parent reports the wait
//! status; every wait is bounded by the blocking `reap`):
//!   * Parent creates a private segment, attaches RW, writes a sentinel byte.
//!     Positive control — proves shmget/shmat/RW-store work at all, so a `false`
//!     on the RDONLY assertions is the real bug, not setup noise.
//!   * Child A: `shmat(id, NULL, SHM_RDONLY)`. It must (a) succeed (addr valid),
//!     (b) READ the parent's sentinel back through the read-only view (shared
//!     coherence still works read-side), then (c) STORE through it. On Linux the
//!     store faults → the child dies by SIGSEGV. It reports (a)+(b) to the parent
//!     over a pipe BEFORE the faulting store, so the parent observes both the
//!     pre-fault state and the crash. SIGSEGV is set to SIG_DFL + unblocked in
//!     the child so a write actually kills it (never returns).
//!   * Child B (control): `shmat(id, NULL, 0)` (RW) then the SAME store. On Linux
//!     this exits 0 — confirms the SIGSEGV in child A is the RDONLY flag, not an
//!     unconditionally broken mapping.
//!
//! NULL addr_hint is used deliberately: addr placement (MAP_FIXED honoring a
//! caller addr / SHM_REMAP) is an architectural gap (carrick chooses the alias
//! VA), so this probe does NOT assert addr-respecting behavior — only the prot
//! side, which is achievable. Deterministic output: booleans only.
//!
//! Bounded-wait note: the pipe read is bounded by child A's lifetime — the child
//! writes its byte and closes the write end BEFORE the faulting store, and the
//! parent has already closed its own copy of the write end, so once the child
//! dies the parent's read returns the byte then EOF (never blocks forever).

use conformance_probes::{reap, report};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
// Linux uapi/linux/shm.h: SHM_RDONLY == 010000.
const SHM_RDONLY: i32 = 0o10000;
const SENTINEL: u8 = 0xA5;

unsafe fn shmget(key: i32, size: usize, flags: i32) -> i64 {
    libc::syscall(libc::SYS_shmget, key as i64, size as i64, flags as i64)
}

unsafe fn shmat(shmid: i32, addr: *const libc::c_void, flag: i32) -> *mut libc::c_void {
    libc::syscall(libc::SYS_shmat, shmid as i64, addr, flag as i64) as *mut libc::c_void
}

unsafe fn shmctl(shmid: i32, cmd: i32, buf: *mut libc::c_void) -> i64 {
    libc::syscall(libc::SYS_shmctl, shmid as i64, cmd as i64, buf)
}

/// Force SIGSEGV to its default (fatal) disposition and unblock it, so a store
/// into a read-only mapping actually terminates the child rather than being
/// caught/ignored by an inherited disposition.
unsafe fn make_sigsegv_fatal() {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = libc::SIG_DFL;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(libc::SIGSEGV, &sa, core::ptr::null_mut());
    let mut set: libc::sigset_t = core::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, libc::SIGSEGV);
    libc::sigprocmask(libc::SIG_UNBLOCK, &set, core::ptr::null_mut());
}

fn main() {
    unsafe {
        // --- Positive control: segment + RW attach + sentinel store. ---
        let shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o666);
        let setup_ok = shmid >= 0;
        if !setup_ok {
            report!(
                setup_ok = false,
                rdonly_attach_ok = false,
                rdonly_read_coherent = false,
                rdonly_store_faults = false,
                rw_attach_store_ok = false,
            );
            return;
        }
        let rw = shmat(shmid as i32, core::ptr::null(), 0);
        let rw_ok = rw as isize != -1 && !rw.is_null();
        if rw_ok {
            core::ptr::write_volatile(rw as *mut u8, SENTINEL);
            std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        }
        report!(setup_ok = rw_ok);

        // --- Child A: SHM_RDONLY attach; read OK, store must fault. ---
        let mut pipefd = [0i32; 2];
        let have_pipe = libc::pipe(pipefd.as_mut_ptr()) == 0;
        let pid_a = libc::fork();
        if pid_a == 0 {
            if have_pipe {
                libc::close(pipefd[0]);
            }
            make_sigsegv_fatal();
            let addr = shmat(shmid as i32, core::ptr::null(), SHM_RDONLY);
            let attached = addr as isize != -1 && !addr.is_null();
            // Read coherence: the parent's sentinel is visible read-side.
            let read_ok =
                attached && core::ptr::read_volatile(addr as *const u8) == SENTINEL;
            // Tell the parent the pre-fault state (bit0=attached, bit1=read_ok),
            // flushed BEFORE the store so the byte survives even if the store
            // crashes us instantly.
            if have_pipe {
                let byte = (attached as u8) | ((read_ok as u8) << 1);
                libc::write(pipefd[1], &byte as *const u8 as *const libc::c_void, 1);
                libc::close(pipefd[1]);
            }
            // The faulting store. Linux: SIGSEGV (read-only mapping). If the
            // host wrongly allows it, _exit(0) so the parent's WIFSIGNALED is
            // false and the diff still flags the divergence.
            if attached {
                core::ptr::write_volatile(addr as *mut u8, 0x5A);
            }
            libc::_exit(0);
        }
        let mut pre = 0u8;
        if have_pipe {
            libc::close(pipefd[1]);
            // Single bounded read; child writes exactly one byte before the store.
            let n = libc::read(pipefd[0], &mut pre as *mut u8 as *mut libc::c_void, 1);
            if n <= 0 {
                pre = 0;
            }
            libc::close(pipefd[0]);
        }
        let (ra, status_a) = if pid_a > 0 { reap(pid_a) } else { (-1, 0) };
        let reaped_a = ra == pid_a && pid_a > 0;
        let attached = pre & 1 != 0;
        let read_coherent = pre & 0b10 != 0;
        let store_faults =
            reaped_a && libc::WIFSIGNALED(status_a) && libc::WTERMSIG(status_a) == libc::SIGSEGV;
        report!(
            rdonly_attach_ok = attached,
            rdonly_read_coherent = read_coherent,
            rdonly_store_faults = store_faults,
        );

        // --- Child B (control): RW attach + same store → clean exit. ---
        let pid_b = libc::fork();
        if pid_b == 0 {
            make_sigsegv_fatal();
            let addr = shmat(shmid as i32, core::ptr::null(), 0);
            if addr as isize == -1 || addr.is_null() {
                libc::_exit(1);
            }
            core::ptr::write_volatile(addr as *mut u8, 0x33);
            libc::_exit(0);
        }
        let (rb, status_b) = if pid_b > 0 { reap(pid_b) } else { (-1, 0) };
        let rw_store_ok = rb == pid_b
            && pid_b > 0
            && libc::WIFEXITED(status_b)
            && libc::WEXITSTATUS(status_b) == 0;
        report!(rw_attach_store_ok = rw_store_ok);

        // Cleanup (return value not asserted — not part of the invariant).
        shmctl(shmid as i32, IPC_RMID, core::ptr::null_mut());
    }
}