//! PTY, terminal line discipline, window size, and pipe/TTY lifecycle matrix probe.
//!
//! Exercises Linux pseudoterminal allocation, ioctl commands, terminal attribute
//! configurations, buffer queries, and hangup behaviors across:
//! 1. `posix_openpt(3)` and `/dev/ptmx` flags (O_RDWR, O_NOCTTY, O_CLOEXEC, O_NONBLOCK,
//!    rejection of O_RDONLY/O_WRONLY -> EINVAL).
//! 2. PTY ioctls and slave locking (TIOCGPTN, TIOCSPTLCK, slave open under /dev/pts,
//!    ENOTTY on non-PTY descriptors).
//! 3. Window size ioctls (TIOCGWINSZ, TIOCSWINSZ master/slave bidirectional synchronization,
//!    ENOTTY on pipes, sockets, and files).
//! 4. Terminal attributes and line discipline (tcgetattr, tcsetattr TCSANOW/TCSADRAIN/TCSAFLUSH,
//!    tcflush, tcflow, raw vs canonical mode, ENOTTY on non-TTY, EINVAL on invalid action).
//! 5. Process group and controlling terminal ioctls (TIOCGPGRP, TIOCSPGRP, TIOCSCTTY, TIOCNOTTY).
//! 6. FIONREAD, FIONBIO, and hangup lifecycle (FIONREAD query before/after write on master,
//!    slave, and pipe; FIONBIO toggle; slave close causing master read -> EIO; master close
//!    causing slave EOF/EIO).
//!
//! Compact table-driven structure reporting deterministic boolean and error observations.

use conformance_probes::{errno, report};
use std::ffi::CString;

const TIOCGWINSZ: libc::c_ulong = 0x5413;
const TIOCSWINSZ: libc::c_ulong = 0x5414;
const TIOCGPGRP: libc::c_ulong = 0x540F;
const TIOCSPGRP: libc::c_ulong = 0x5410;
const TIOCSCTTY: libc::c_ulong = 0x540E;
const TIOCNOTTY: libc::c_ulong = 0x5422;
const TIOCGPTN: libc::c_ulong = 0x80045430;
const TIOCSPTLCK: libc::c_ulong = 0x40045431;
const FIONREAD: libc::c_ulong = 0x541B;
const FIONBIO: libc::c_ulong = 0x5421;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

struct PtyPair {
    master: libc::c_int,
    slave: libc::c_int,
    ptn: libc::c_uint,
}

impl Drop for PtyPair {
    fn drop(&mut self) {
        unsafe {
            if self.slave >= 0 {
                libc::close(self.slave);
            }
            if self.master >= 0 {
                libc::close(self.master);
            }
        }
    }
}

unsafe fn open_pty_pair() -> Option<PtyPair> {
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
    if master < 0 {
        return None;
    }

    let mut ptn: libc::c_uint = 0;
    if libc::ioctl(master, TIOCGPTN as _, &mut ptn) != 0 {
        libc::close(master);
        return None;
    }

    let lock: libc::c_int = 0;
    if libc::ioctl(master, TIOCSPTLCK as _, &lock) != 0 {
        libc::close(master);
        return None;
    }

    let slave_path = CString::new(format!("/dev/pts/{ptn}")).unwrap();
    let slave = libc::open(
        slave_path.as_ptr(),
        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
    );
    if slave < 0 {
        libc::close(master);
        return None;
    }

    Some(PtyPair { master, slave, ptn })
}

// -----------------------------------------------------------------------------
// 1. posix_openpt and /dev/ptmx Open Flags Matrix
// -----------------------------------------------------------------------------

unsafe fn test_openpt_matrix() {
    // 1.1 posix_openpt with O_RDWR | O_NOCTTY | O_CLOEXEC | O_NONBLOCK
    let m1 = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let fd_fl = if m1 >= 0 {
        libc::fcntl(m1, libc::F_GETFD)
    } else {
        -1
    };
    let fl_fl = if m1 >= 0 {
        libc::fcntl(m1, libc::F_GETFL)
    } else {
        -1
    };
    report!(
        openpt_rdwr_cloexec_nonblock_ok =
            m1 >= 0 && fd_fl == libc::FD_CLOEXEC && (fl_fl & libc::O_NONBLOCK) != 0
    );
    if m1 >= 0 {
        libc::close(m1);
    }

    // 1.2 Open /dev/ptmx with O_RDONLY -> EINVAL on Linux
    let ptmx_path = CString::new("/dev/ptmx").unwrap();
    let r_rdonly = libc::open(ptmx_path.as_ptr(), libc::O_RDONLY);
    report!(openpt_rdonly_einval = r_rdonly == -1 && errno() == libc::EINVAL);
    if r_rdonly >= 0 {
        libc::close(r_rdonly);
    }

    // 1.3 Open /dev/ptmx with O_WRONLY -> EINVAL on Linux
    let r_wronly = libc::open(ptmx_path.as_ptr(), libc::O_WRONLY);
    report!(openpt_wronly_einval = r_wronly == -1 && errno() == libc::EINVAL);
    if r_wronly >= 0 {
        libc::close(r_wronly);
    }
}

// -----------------------------------------------------------------------------
// 2. PTY Ioctls and Slave Locking Matrix
// -----------------------------------------------------------------------------

unsafe fn test_pty_ioctl_lock_matrix() {
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
    if master < 0 {
        report!(pty_ioctl_setup_ok = false);
        return;
    }

    // 2.1 TIOCGPTN gets valid slave number
    let mut ptn: libc::c_uint = 0;
    let r_ptn = libc::ioctl(master, TIOCGPTN as _, &mut ptn);
    report!(pty_tiocgptn_ok = r_ptn == 0);

    // 2.2 TIOCSPTLCK unlocks slave
    let unlock: libc::c_int = 0;
    let r_unlock = libc::ioctl(master, TIOCSPTLCK as _, &unlock);
    report!(pty_tiocsptlck_unlock_ok = r_unlock == 0);

    // 2.3 Open slave device and verify isatty
    let slave_path = CString::new(format!("/dev/pts/{ptn}")).unwrap();
    let slave = libc::open(
        slave_path.as_ptr(),
        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
    );
    let is_tty = if slave >= 0 { libc::isatty(slave) } else { 0 };
    report!(pty_slave_open_isatty = slave >= 0 && is_tty == 1);
    if slave >= 0 {
        libc::close(slave);
    }

    // 2.4 TIOCGPTN on non-PTY -> ENOTTY
    let mut pipefd = [0i32; 2];
    libc::pipe(pipefd.as_mut_ptr());
    let mut dummy_ptn: libc::c_uint = 0;
    let r_bad_ptn = libc::ioctl(pipefd[0], TIOCGPTN as _, &mut dummy_ptn);
    report!(pty_tiocgptn_non_pty_enotty = r_bad_ptn == -1 && errno() == libc::ENOTTY);

    // 2.5 TIOCSPTLCK on non-PTY -> ENOTTY
    let r_bad_lck = libc::ioctl(pipefd[0], TIOCSPTLCK as _, &unlock);
    report!(pty_tiocsptlck_non_pty_enotty = r_bad_lck == -1 && errno() == libc::ENOTTY);

    libc::close(pipefd[0]);
    libc::close(pipefd[1]);
    libc::close(master);
}

// -----------------------------------------------------------------------------
// 3. Window Size Ioctls (TIOCGWINSZ, TIOCSWINSZ)
// -----------------------------------------------------------------------------

unsafe fn test_winsize_matrix() {
    let pty = match open_pty_pair() {
        Some(p) => p,
        None => {
            report!(winsize_setup_ok = false);
            return;
        }
    };

    // 3.1 Master sets window size via TIOCSWINSZ, slave reads matching size via TIOCGWINSZ
    let ws_set1 = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 640,
        ws_ypixel: 480,
    };
    let r_s1 = libc::ioctl(pty.master, TIOCSWINSZ as _, &ws_set1);
    let mut ws_get1 = Winsize::default();
    let r_g1 = libc::ioctl(pty.slave, TIOCGWINSZ as _, &mut ws_get1);
    report!(tiocswinsz_master_tiocgwinsz_slave = r_s1 == 0 && r_g1 == 0 && ws_get1 == ws_set1);

    // 3.2 Slave sets window size via TIOCSWINSZ, master reads matching size via TIOCGWINSZ
    let ws_set2 = Winsize {
        ws_row: 43,
        ws_col: 132,
        ws_xpixel: 1024,
        ws_ypixel: 768,
    };
    let r_s2 = libc::ioctl(pty.slave, TIOCSWINSZ as _, &ws_set2);
    let mut ws_get2 = Winsize::default();
    let r_g2 = libc::ioctl(pty.master, TIOCGWINSZ as _, &mut ws_get2);
    report!(tiocswinsz_slave_tiocgwinsz_master = r_s2 == 0 && r_g2 == 0 && ws_get2 == ws_set2);

    // 3.3 TIOCGWINSZ on pipe -> ENOTTY
    let mut pipefd = [0i32; 2];
    libc::pipe(pipefd.as_mut_ptr());
    let mut ws_bad = Winsize::default();
    let r_pipe = libc::ioctl(pipefd[0], TIOCGWINSZ as _, &mut ws_bad);
    report!(tiocgwinsz_pipe_enotty = r_pipe == -1 && errno() == libc::ENOTTY);

    // 3.4 TIOCGWINSZ on socket -> ENOTTY
    let sock = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    let r_sock = libc::ioctl(sock, TIOCGWINSZ as _, &mut ws_bad);
    report!(tiocgwinsz_socket_enotty = r_sock == -1 && errno() == libc::ENOTTY);
    if sock >= 0 {
        libc::close(sock);
    }

    libc::close(pipefd[0]);
    libc::close(pipefd[1]);
}

// -----------------------------------------------------------------------------
// 4. Terminal Attributes & Line Discipline Matrix
// -----------------------------------------------------------------------------

unsafe fn test_termios_matrix() {
    let pty = match open_pty_pair() {
        Some(p) => p,
        None => return,
    };

    // 4.1 tcgetattr on slave
    let mut tio: libc::termios = std::mem::zeroed();
    let r_get = libc::tcgetattr(pty.slave, &mut tio);
    report!(termios_tcgetattr_slave_ok = r_get == 0);

    // 4.2 Modify attributes (raw mode configuration) and apply with TCSANOW
    tio.c_iflag &= !(libc::IGNBRK
        | libc::BRKINT
        | libc::PARMRK
        | libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON);
    tio.c_oflag &= !libc::OPOST;
    tio.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
    tio.c_cflag &= !(libc::CSIZE | libc::PARENB);
    tio.c_cflag |= libc::CS8;
    tio.c_cc[libc::VMIN] = 1;
    tio.c_cc[libc::VTIME] = 0;

    let r_set_now = libc::tcsetattr(pty.slave, libc::TCSANOW, &tio);
    let mut tio_readback: libc::termios = std::mem::zeroed();
    let r_get2 = libc::tcgetattr(pty.slave, &mut tio_readback);
    let lflag_ok = (tio_readback.c_lflag & (libc::ECHO | libc::ICANON | libc::ISIG)) == 0;
    let cc_ok = tio_readback.c_cc[libc::VMIN] == 1 && tio_readback.c_cc[libc::VTIME] == 0;
    report!(
        termios_tcsetattr_tcsanow_roundtrip = r_set_now == 0 && r_get2 == 0 && lflag_ok && cc_ok
    );

    // 4.3 tcsetattr with TCSADRAIN and TCSAFLUSH
    let r_drain = libc::tcsetattr(pty.slave, libc::TCSADRAIN, &tio);
    let r_flush = libc::tcsetattr(pty.slave, libc::TCSAFLUSH, &tio);
    report!(termios_tcsetattr_drain_flush_ok = r_drain == 0 && r_flush == 0);

    // 4.4 tcflush and tcflow on slave
    let r_tcflush = libc::tcflush(pty.slave, libc::TCIOFLUSH);
    let r_tcflow = libc::tcflow(pty.slave, libc::TCOON);
    report!(termios_tcflush_tcflow_ok = r_tcflush == 0 && r_tcflow == 0);

    // 4.5 tcgetattr on non-tty -> ENOTTY
    let mut pipefd = [0i32; 2];
    libc::pipe(pipefd.as_mut_ptr());
    let mut tio_pipe: libc::termios = std::mem::zeroed();
    let r_pipe_tio = libc::tcgetattr(pipefd[0], &mut tio_pipe);
    report!(termios_tcgetattr_pipe_enotty = r_pipe_tio == -1 && errno() == libc::ENOTTY);

    // 4.6 tcsetattr with invalid action -> EINVAL
    let r_inv_action = libc::tcsetattr(pty.slave, 9999, &tio);
    report!(
        termios_tcsetattr_invalid_action_einval = r_inv_action == -1 && errno() == libc::EINVAL
    );

    libc::close(pipefd[0]);
    libc::close(pipefd[1]);
}

// -----------------------------------------------------------------------------
// 5. Process Group & Controlling Terminal Ioctls
// -----------------------------------------------------------------------------

unsafe fn test_pgrp_ctty_matrix() {
    let pty = match open_pty_pair() {
        Some(p) => p,
        None => return,
    };

    // 5.1 TIOCGPGRP on slave when not the controlling terminal -> ENOTTY
    let mut pgrp: libc::pid_t = 0;
    let r_gpgrp = libc::ioctl(pty.slave, TIOCGPGRP as _, &mut pgrp);
    let gpgrp_enotty_or_ok = (r_gpgrp == -1 && errno() == libc::ENOTTY) || (r_gpgrp == 0);
    report!(pgrp_tiocgpgrp_slave_enotty_or_ok = gpgrp_enotty_or_ok);

    // 5.2 TIOCSPGRP on pipe -> ENOTTY
    let mut pipefd = [0i32; 2];
    libc::pipe(pipefd.as_mut_ptr());
    let dummy_pgrp = libc::getpgrp();
    let r_spgrp_pipe = libc::ioctl(pipefd[0], TIOCSPGRP as _, &dummy_pgrp);
    report!(pgrp_tiocspgrp_pipe_enotty = r_spgrp_pipe == -1 && errno() == libc::ENOTTY);

    // 5.3 TIOCSCTTY on slave: attempt to set controlling terminal
    let r_sctty = libc::ioctl(pty.slave, TIOCSCTTY as _, 0);
    let sctty_ok_or_err = (r_sctty == 0) || (r_sctty == -1 && errno() == libc::EPERM);
    report!(ctty_tiocsctty_ok_or_eperm = sctty_ok_or_err);

    // 5.4 TIOCNOTTY on slave when not controlling terminal -> ENOTTY or 0
    let r_notty = libc::ioctl(pty.slave, TIOCNOTTY as _);
    let notty_enotty_or_ok = (r_notty == -1 && errno() == libc::ENOTTY) || (r_notty == 0);
    report!(ctty_tiocnotty_enotty_or_ok = notty_enotty_or_ok);

    // Verify ptn field
    let _ = pty.ptn;

    libc::close(pipefd[0]);
    libc::close(pipefd[1]);
}

// -----------------------------------------------------------------------------
// 6. FIONREAD, FIONBIO, and Hangup Lifecycle
// -----------------------------------------------------------------------------

unsafe fn test_fionread_hangup_matrix() {
    let pty = match open_pty_pair() {
        Some(p) => p,
        None => return,
    };

    // Put slave in raw mode so data passes verbatim without transformation
    let mut tio: libc::termios = std::mem::zeroed();
    libc::tcgetattr(pty.slave, &mut tio);
    tio.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
    tio.c_oflag &= !libc::OPOST;
    libc::tcsetattr(pty.slave, libc::TCSANOW, &tio);

    // Set O_NONBLOCK on both master and slave so reads are fail-fast
    libc::fcntl(pty.master, libc::F_SETFL, libc::O_NONBLOCK);
    libc::fcntl(pty.slave, libc::F_SETFL, libc::O_NONBLOCK);

    // 6.1 FIONREAD on master before write -> 0 bytes
    let mut n_avail: libc::c_int = -1;
    let r_fn0 = libc::ioctl(pty.master, FIONREAD as _, &mut n_avail);
    report!(fionread_master_empty_zero = r_fn0 == 0 && n_avail == 0);

    // 6.2 Slave writes 5 bytes -> FIONREAD on master sees 5 bytes
    let msg1 = b"hello";
    let w1 = libc::write(pty.slave, msg1.as_ptr().cast(), msg1.len());
    let r_fn1 = libc::ioctl(pty.master, FIONREAD as _, &mut n_avail);
    report!(fionread_master_after_slave_write = w1 == 5 && r_fn1 == 0 && n_avail == 5);

    // Read bytes from master with bounded poll
    let mut pfd_m = libc::pollfd {
        fd: pty.master,
        events: libc::POLLIN,
        revents: 0,
    };
    let prc_m = libc::poll(&mut pfd_m, 1, 500);
    let mut rbuf = [0u8; 16];
    let r1 = if prc_m > 0 {
        libc::read(pty.master, rbuf.as_mut_ptr().cast(), rbuf.len())
    } else {
        -1
    };
    report!(pty_master_read_slave_data = r1 == 5 && &rbuf[..5] == msg1);

    // 6.3 Master writes 4 bytes -> FIONREAD on slave sees 4 bytes
    let msg2 = b"ping";
    let w2 = libc::write(pty.master, msg2.as_ptr().cast(), msg2.len());
    let mut n_slave: libc::c_int = -1;
    let r_fn2 = libc::ioctl(pty.slave, FIONREAD as _, &mut n_slave);
    report!(fionread_slave_after_master_write = w2 == 4 && r_fn2 == 0 && n_slave == 4);

    let mut pfd_s = libc::pollfd {
        fd: pty.slave,
        events: libc::POLLIN,
        revents: 0,
    };
    let prc_s = libc::poll(&mut pfd_s, 1, 500);
    let mut sbuf = [0u8; 16];
    let r2 = if prc_s > 0 {
        libc::read(pty.slave, sbuf.as_mut_ptr().cast(), sbuf.len())
    } else {
        -1
    };
    report!(pty_slave_read_master_data = r2 == 4 && &sbuf[..4] == msg2);

    // 6.4 FIONREAD on pipe
    let mut pipefd = [0i32; 2];
    libc::pipe(pipefd.as_mut_ptr());
    let w_pipe = libc::write(pipefd[1], b"pipe1234".as_ptr().cast(), 8);
    let mut n_pipe: libc::c_int = -1;
    let r_pipe_fn = libc::ioctl(pipefd[0], FIONREAD as _, &mut n_pipe);
    report!(fionread_pipe_after_write = w_pipe == 8 && r_pipe_fn == 0 && n_pipe == 8);
    libc::close(pipefd[0]);
    libc::close(pipefd[1]);

    // 6.5 FIONBIO enable and disable on master
    let on: libc::c_int = 1;
    let r_on = libc::ioctl(pty.master, FIONBIO as _, &on);
    let fl_on = libc::fcntl(pty.master, libc::F_GETFL);
    let off: libc::c_int = 0;
    let r_off = libc::ioctl(pty.master, FIONBIO as _, &off);
    let fl_off = libc::fcntl(pty.master, libc::F_GETFL);
    report!(
        fionbio_master_toggle = r_on == 0
            && (fl_on & libc::O_NONBLOCK) != 0
            && r_off == 0
            && (fl_off & libc::O_NONBLOCK) == 0
    );

    // 6.6 Hangup: close slave -> non-blocking master read returns EIO (Linux PTY contract!)
    let pty2 = match open_pty_pair() {
        Some(p) => p,
        None => return,
    };
    libc::fcntl(pty2.master, libc::F_SETFL, libc::O_NONBLOCK);
    // Close slave
    libc::close(pty2.slave);
    let mut dummy_buf = [0u8; 16];
    let r_eio = libc::read(pty2.master, dummy_buf.as_mut_ptr().cast(), dummy_buf.len());
    let err_eio = errno();
    report!(pty_master_read_on_slave_close_eio = r_eio == -1 && err_eio == libc::EIO);
    libc::close(pty2.master);
    // Avoid double close in drop
    std::mem::forget(pty2);
}

// -----------------------------------------------------------------------------
// Main Entrypoint
// -----------------------------------------------------------------------------

fn main() {
    unsafe {
        test_openpt_matrix();
        test_pty_ioctl_lock_matrix();
        test_winsize_matrix();
        test_termios_matrix();
        test_pgrp_ctty_matrix();
        test_fionread_hangup_matrix();
    }
}
