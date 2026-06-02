//! `signalfd` read delivers pending masked signals (audit H4): a read on a
//! signalfd must drain pending signals that match the fd's mask into
//! `struct signalfd_siginfo` records. carrick previously returned EINVAL on the
//! read, making the API unusable.
//!
//! Invariants encoded (carrick must match Linux line-for-line):
//!   - read() returns sizeof(struct signalfd_siginfo) == 128.
//!   - the record's ssi_signo is the raised signal (SIGUSR1).
//!   - a buffer smaller than one record → EINVAL.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        // Block SIGUSR1 so a raise stays pending (signalfd reads the pending set).
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());

        let sfd = libc::signalfd(-1, &mask, 0);
        report!(signalfd_ok = sfd >= 0);

        libc::raise(libc::SIGUSR1);

        let mut si: libc::signalfd_siginfo = std::mem::zeroed();
        let n = libc::read(
            sfd,
            &mut si as *mut libc::signalfd_siginfo as *mut libc::c_void,
            std::mem::size_of::<libc::signalfd_siginfo>(),
        );
        report!(read_returns_full_record = n == 128);
        report!(ssi_signo_is_sigusr1 = si.ssi_signo as i32 == libc::SIGUSR1);

        // A too-small buffer is EINVAL.
        let mut tiny = [0u8; 64];
        let r = libc::read(sfd, tiny.as_mut_ptr() as *mut libc::c_void, tiny.len());
        report!(short_buffer_einval = r == -1 && errno() == libc::EINVAL);

        libc::close(sfd);
    }
}
