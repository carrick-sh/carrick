//! PTY line-discipline ISIG signal delivery probe.
//!
//! Verifies that master writes of VINTR, VSUSP, VQUIT deliver SIGINT,
//! SIGTSTP, SIGQUIT to the slave's foreground process group when ISIG is set,
//! that bytes pass through when ISIG is disabled, that VLNEXT quotes signals,
//! and that TIOCSIG delivers signals to the foreground group.

use conformance_probes::{errno, install_handler, pipe2, reap, report};
use std::ffi::CStr;
use std::sync::atomic::{AtomicI32, Ordering};

static SIG_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(signum: i32) {
    let fd = SIG_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = match signum {
            libc::SIGINT => b'I',
            libc::SIGTSTP => b'T',
            libc::SIGQUIT => b'Q',
            _ => b'?',
        };
        unsafe {
            libc::write(fd, &byte as *const u8 as *const libc::c_void, 1);
        }
    }
}

/// Read exactly `buf.len()` bytes, but never wait more than 5 s per byte: a
/// runtime that fails to deliver a line-discipline signal must show up as a
/// false report line, not as a wedged probe holding the gate. On timeout the
/// remaining bytes are filled with 0xff (no signal has that number).
fn read_exact_bytes(fd: i32, buf: &mut [u8]) {
    let mut total = 0;
    while total < buf.len() {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pfd, 1, 5_000) };
        if ready < 0 && errno() == libc::EINTR {
            continue;
        }
        if ready == 0 {
            for b in &mut buf[total..] {
                *b = 0xff;
            }
            return;
        }
        let n = unsafe {
            libc::read(
                fd,
                buf[total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - total,
            )
        };
        if n < 0 && errno() == libc::EINTR {
            continue;
        }
        assert!(n > 0, "read failed on fd {fd}");
        total += n as usize;
    }
}

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");

        let name_ptr = libc::ptsname(master);
        assert!(!name_ptr.is_null(), "ptsname returned NULL");
        let slave_name = CStr::from_ptr(name_ptr).to_owned();

        let (sig_r, sig_w) = pipe2();
        let (ack_r, ack_w) = pipe2();

        let child = libc::fork();
        assert!(child >= 0, "fork failed");

        if child == 0 {
            libc::close(master);
            libc::close(sig_r);
            libc::close(ack_r);

            assert!(libc::setsid() > 0, "setsid failed");

            let slave = libc::open(slave_name.as_ptr(), libc::O_RDWR);
            assert!(slave >= 0, "open slave failed");

            assert_eq!(libc::ioctl(slave, libc::TIOCSCTTY, 0), 0, "TIOCSCTTY failed");

            let mut tio: libc::termios = core::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave, &mut tio), 0, "tcgetattr failed");
            // Disable echo, keep canonical and ISIG
            tio.c_lflag &= !(libc::ECHO as libc::tcflag_t);
            tio.c_lflag |= (libc::ICANON | libc::IEXTEN | libc::ISIG) as libc::tcflag_t;
            assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &tio), 0, "tcsetattr failed");

            assert_eq!(libc::tcsetpgrp(slave, libc::getpgrp()), 0, "tcsetpgrp failed");

            SIG_WRITE_FD.store(sig_w, Ordering::Relaxed);
            assert!(install_handler(libc::SIGINT, on_signal, 0));
            assert!(install_handler(libc::SIGTSTP, on_signal, 0));
            assert!(install_handler(libc::SIGQUIT, on_signal, 0));

            // Notify parent ready
            assert_eq!(libc::write(ack_w, b"1".as_ptr().cast(), 1), 1);

            loop {
                let mut buf = [0u8; 16];
                let n = libc::read(slave, buf.as_mut_ptr().cast(), buf.len());
                if n < 0 && errno() == libc::EINTR {
                    continue;
                }
                if n <= 0 {
                    break;
                }
                let slice = &buf[..n as usize];
                if slice.starts_with(b"X") {
                    break;
                }
                if slice.starts_with(b"D") {
                    let mut t: libc::termios = core::mem::zeroed();
                    libc::tcgetattr(slave, &mut t);
                    t.c_lflag &= !(libc::ISIG as libc::tcflag_t);
                    libc::tcsetattr(slave, libc::TCSANOW, &t);
                    let _ = libc::write(ack_w, b"D".as_ptr().cast(), 1);
                    continue;
                }
                if slice.starts_with(b"S") {
                    let mut sig: i32 = libc::SIGINT;
                    let rc = libc::ioctl(slave, 0x40045436, &mut sig as *mut i32);
                    let _ = libc::write(
                        ack_w,
                        if rc == 0 { b"S" } else { b"F" }.as_ptr().cast(),
                        1,
                    );
                    continue;
                }
                let _ = libc::write(ack_w, slice.as_ptr().cast(), slice.len());
            }

            libc::close(slave);
            libc::close(sig_w);
            libc::close(ack_w);
            libc::_exit(0);
        }

        libc::close(sig_w);
        libc::close(ack_w);

        let mut ready = [0u8; 1];
        read_exact_bytes(ack_r, &mut ready);
        assert_eq!(ready[0], b'1');

        // 1. Write ^C (0x03) -> expect SIGINT ('I')
        assert_eq!(libc::write(master, b"\x03".as_ptr().cast(), 1), 1);
        let mut got_int = [0u8; 1];
        read_exact_bytes(sig_r, &mut got_int);

        // 2. Write ^Z (0x1a) -> expect SIGTSTP ('T')
        assert_eq!(libc::write(master, b"\x1a".as_ptr().cast(), 1), 1);
        let mut got_susp = [0u8; 1];
        read_exact_bytes(sig_r, &mut got_susp);

        // 3. Write ^\ (0x1c) -> expect SIGQUIT ('Q')
        assert_eq!(libc::write(master, b"\x1c".as_ptr().cast(), 1), 1);
        let mut got_quit = [0u8; 1];
        read_exact_bytes(sig_r, &mut got_quit);

        // 4. Normal character 'A\n' passes through as data
        assert_eq!(libc::write(master, b"A\n".as_ptr().cast(), 2), 2);
        let mut got_normal = [0u8; 2];
        read_exact_bytes(ack_r, &mut got_normal);

        // 5. VLNEXT quotes ^C: write "\x16\x03\n"
        assert_eq!(libc::write(master, b"\x16\x03\n".as_ptr().cast(), 3), 3);
        let mut got_quoted = [0u8; 2];
        read_exact_bytes(ack_r, &mut got_quoted);

        // 6. Disable ISIG on slave, then write "\x03\n" -> must arrive as data
        assert_eq!(libc::write(master, b"D\n".as_ptr().cast(), 2), 2);
        let mut got_d_ack = [0u8; 1];
        read_exact_bytes(ack_r, &mut got_d_ack);
        assert_eq!(got_d_ack[0], b'D');

        assert_eq!(libc::write(master, b"\x03\n".as_ptr().cast(), 2), 2);
        let mut got_raw = [0u8; 2];
        read_exact_bytes(ack_r, &mut got_raw);

        // 7. TIOCSIG ioctl on slave delivers signal
        assert_eq!(libc::write(master, b"S\n".as_ptr().cast(), 2), 2);
        let mut tiocsig_ack = [0u8; 1];
        read_exact_bytes(ack_r, &mut tiocsig_ack);
        let mut got_tiocsig = [0u8; 1];
        read_exact_bytes(sig_r, &mut got_tiocsig);

        // 8. Exit child
        assert_eq!(libc::write(master, b"X\n".as_ptr().cast(), 2), 2);
        let (reaped, status) = reap(child);

        report!(
            vintr_delivered_sigint = got_int[0] == b'I',
            vsusp_delivered_sigtstp = got_susp[0] == b'T',
            vquit_delivered_sigquit = got_quit[0] == b'Q',
            normal_data_passed = &got_normal == b"A\n",
            vlnext_quoted_signal = &got_quoted == b"\x03\n",
            disabled_isig_passed_data = &got_raw == b"\x03\n",
            tiocsig_delivered_sigint = tiocsig_ack[0] == b'S' && got_tiocsig[0] == b'I',
            child_clean_exit = reaped == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        );

        libc::close(master);
        libc::close(sig_r);
        libc::close(ack_r);
    }
}
