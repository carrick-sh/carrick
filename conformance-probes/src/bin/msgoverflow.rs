//! SysV msgsnd/msgrcv compute the host staging buffer as `8 + msgsz` with an
//! UNCHECKED add and no MSGMAX clamp (dispatch/sysv.rs:568/593). On Linux,
//! msgsz greater than MSGMAX is rejected with EINVAL before any copy.
//!
//! This probe sends a huge msgsz and records the GUEST-VISIBLE result. It
//! settles, empirically, whether the unchecked `8 + msgsz` is a live
//! host-memory-safety hole in the production (release) build or whether the
//! host kernel's own MSGMAX validation masks it:
//!   * If carrick returns EINVAL (like Linux), the overflow is masked by the
//!     host msgsnd's MSGMAX check (no guest-visible divergence; the bug is a
//!     latent unchecked-add to harden, not an exploitable OOB).
//!   * If carrick crashes / returns something other than EINVAL, the overflow
//!     is observable and the finding stands at higher severity.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        let qid = libc::msgget(libc::IPC_PRIVATE, 0o666 | libc::IPC_CREAT);
        if qid < 0 {
            report!(msgget_ok = false, msgget_errno = errno());
            return;
        }

        // A valid System V message: mtype (long) followed by text.
        let mut buf = [0u8; 16];
        buf[0] = 1; // mtype = 1 (little-endian low byte)
        buf[8] = b'A';
        buf[9] = b'B';

        // msgsz so large that `8 + msgsz` overflows usize.
        let huge: libc::size_t = 0xFFFF_FFFF_FFFF_FFF8;
        let snd = libc::msgsnd(
            qid,
            buf.as_ptr() as *const libc::c_void,
            huge,
            libc::IPC_NOWAIT,
        );
        let snd_errno = if snd < 0 { errno() } else { 0 };

        // Confirm the queue is still usable with a sane size.
        let ok = libc::msgsnd(qid, buf.as_ptr() as *const libc::c_void, 2, libc::IPC_NOWAIT);

        report!(
            huge_msgsnd_failed = snd < 0,
            huge_msgsnd_einval = snd_errno == libc::EINVAL,
            small_msgsnd_ok = ok == 0,
        );
        libc::msgctl(qid, libc::IPC_RMID, core::ptr::null_mut());
    }
}
