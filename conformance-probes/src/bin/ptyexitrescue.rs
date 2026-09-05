//! Unread pty slave output must survive child exit and remain readable on master.
//!
//! On Linux, when a child writes to a pty slave and exits without the parent
//! having read the data, the unread bytes remain buffered in the pty line
//! discipline and can be read by the parent from the master descriptor after
//! reaping the child.
//!
//! On Carrick prior to the fix, when the exiting child closed its slave fd,
//! `SyscallDispatcher::rescue_pty_master_before_slave_close` attempted to stage
//! the pushback bytes into the child's retiring `FileTable`, triggering a carrier
//! abort ("mutation reached a draining FileTable generation"). Even without the
//! abort, staging pushback into the child's table made the bytes inaccessible
//! to the parent.
//!
//! Round 1 exercises explicit slave write followed by child exit.
//! Round 2 exercises `pty.fork()` semantics where the child duplicates the slave
//! to stdio (fds 0/1/2), closes the master, writes to stdout, and exits.
//!
//! Expected Linux output:
//! setup_ok=true
//! parent_alive_after_child_slave_close=true
//! parent_reads_child_output_after_exit=true
//! payload_intact=true
//! r2_setup_ok=true
//! r2_parent_alive_after_child_exit=true
//! r2_parent_reads_child_output_after_exit=true
//! r2_payload_intact=true

use std::ffi::CStr;

use conformance_probes::{reap, report};

const R1_PAYLOAD: &[u8] = b"pty_rescue_round_1_payload\n";
const R2_PAYLOAD: &[u8] = b"pty_rescue_round_2_stdio_payload\n";

unsafe fn open_pty_pair() -> Option<(i32, i32)> {
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
    if master < 0 {
        return None;
    }
    if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
        libc::close(master);
        return None;
    }
    let name_ptr = libc::ptsname(master);
    if name_ptr.is_null() {
        libc::close(master);
        return None;
    }
    let name = CStr::from_ptr(name_ptr);
    let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0u32);
    if slave < 0 {
        libc::close(master);
        return None;
    }
    let mut tio: libc::termios = core::mem::zeroed();
    if libc::tcgetattr(slave, &mut tio) != 0 {
        libc::close(slave);
        libc::close(master);
        return None;
    }
    tio.c_lflag &= !((libc::ICANON | libc::ECHO) as libc::tcflag_t);
    // Raw output too: the line discipline's ONLCR would otherwise turn the
    // payload's trailing '\n' into "\r\n" on the master side (the first
    // Docker bless read `payload_intact=false` on Linux for exactly that).
    tio.c_oflag &= !(libc::OPOST as libc::tcflag_t);
    if libc::tcsetattr(slave, libc::TCSANOW, &tio) != 0 {
        libc::close(slave);
        libc::close(master);
        return None;
    }
    Some((master, slave))
}

unsafe fn read_payload(master: i32, expected: &[u8]) -> (bool, bool) {
    let mut pfd = libc::pollfd {
        fd: master,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut buf = vec![0u8; expected.len()];
    let mut total_read = 0;
    for _ in 0..20 {
        if total_read >= expected.len() {
            break;
        }
        let pr = libc::poll(&mut pfd, 1, 100);
        if pr > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP)) != 0 {
            let n = libc::read(
                master,
                buf[total_read..].as_mut_ptr().cast(),
                buf.len() - total_read,
            );
            if n > 0 {
                total_read += n as usize;
            } else if n == 0 {
                break;
            }
        }
    }
    let read_ok = total_read == expected.len();
    let payload_intact = read_ok && buf == expected;
    (read_ok, payload_intact)
}

fn main() {
    unsafe {
        libc::alarm(10);

        // --- Round 1: explicit slave write and exit ---
        let Some((r1_master, r1_slave)) = open_pty_pair() else {
            report!(setup_ok = false);
            return;
        };

        let child1 = libc::fork();
        if child1 < 0 {
            report!(setup_ok = false);
            libc::close(r1_slave);
            libc::close(r1_master);
            return;
        }
        if child1 == 0 {
            libc::alarm(3);
            libc::close(r1_master);
            let mut written = 0;
            while written < R1_PAYLOAD.len() {
                let n = libc::write(
                    r1_slave,
                    R1_PAYLOAD[written..].as_ptr().cast(),
                    R1_PAYLOAD.len() - written,
                );
                if n <= 0 {
                    libc::_exit(1);
                }
                written += n as usize;
            }
            libc::close(r1_slave);
            libc::_exit(0);
        }

        libc::close(r1_slave);
        let (reap_rc1, status1) = reap(child1);
        let r1_child_exit_ok =
            reap_rc1 == child1 && libc::WIFEXITED(status1) && libc::WEXITSTATUS(status1) == 0;
        let parent_alive_after_child_slave_close = r1_child_exit_ok;
        let (r1_read_ok, r1_payload_intact) = read_payload(r1_master, R1_PAYLOAD);
        libc::close(r1_master);

        // --- Round 2: pty.fork() semantics (stdio duplication) ---
        let Some((r2_master, r2_slave)) = open_pty_pair() else {
            report!(
                setup_ok = true,
                parent_alive_after_child_slave_close = parent_alive_after_child_slave_close,
                parent_reads_child_output_after_exit = r1_read_ok,
                payload_intact = r1_payload_intact,
                r2_setup_ok = false,
            );
            return;
        };

        let child2 = libc::fork();
        if child2 < 0 {
            report!(
                setup_ok = true,
                parent_alive_after_child_slave_close = parent_alive_after_child_slave_close,
                parent_reads_child_output_after_exit = r1_read_ok,
                payload_intact = r1_payload_intact,
                r2_setup_ok = false,
            );
            libc::close(r2_slave);
            libc::close(r2_master);
            return;
        }
        if child2 == 0 {
            libc::alarm(3);
            libc::close(r2_master);
            libc::dup2(r2_slave, 0);
            libc::dup2(r2_slave, 1);
            libc::dup2(r2_slave, 2);
            if r2_slave > 2 {
                libc::close(r2_slave);
            }
            let mut written = 0;
            while written < R2_PAYLOAD.len() {
                let n = libc::write(
                    1,
                    R2_PAYLOAD[written..].as_ptr().cast(),
                    R2_PAYLOAD.len() - written,
                );
                if n <= 0 {
                    libc::_exit(1);
                }
                written += n as usize;
            }
            libc::_exit(0);
        }

        libc::close(r2_slave);
        let (reap_rc2, status2) = reap(child2);
        let r2_child_exit_ok =
            reap_rc2 == child2 && libc::WIFEXITED(status2) && libc::WEXITSTATUS(status2) == 0;
        let r2_parent_alive = r2_child_exit_ok;
        let (r2_read_ok, r2_payload_intact) = read_payload(r2_master, R2_PAYLOAD);
        libc::close(r2_master);

        libc::alarm(0);

        report!(
            setup_ok = true,
            parent_alive_after_child_slave_close = parent_alive_after_child_slave_close,
            parent_reads_child_output_after_exit = r1_read_ok,
            payload_intact = r1_payload_intact,
            r2_setup_ok = true,
            r2_parent_alive_after_child_exit = r2_parent_alive,
            r2_parent_reads_child_output_after_exit = r2_read_ok,
            r2_payload_intact = r2_payload_intact,
        );
    }
}
