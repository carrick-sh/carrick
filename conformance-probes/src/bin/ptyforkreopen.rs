//! Closing a fork-inherited pty slave in the child must not remove the slave.
//!
//! Linux keeps `/dev/pts/N` available while the master is open. Carrick tracks
//! devpts entries with an owner pid; a fork child that closes its inherited
//! slave must not free the parent-owned entry in its copied table.

use conformance_probes::{reap, report};
use std::ffi::CStr;

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        let setup_master = master >= 0 && libc::grantpt(master) == 0 && libc::unlockpt(master) == 0;
        report!(setup_master = setup_master);
        if !setup_master {
            return;
        }

        let name_ptr = libc::ptsname(master);
        let setup_name = !name_ptr.is_null();
        report!(setup_name = setup_name);
        if !setup_name {
            libc::close(master);
            return;
        }
        let name = CStr::from_ptr(name_ptr).to_owned();
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0u32);
        let setup_slave = slave >= 0;
        report!(setup_slave = setup_slave);
        if !setup_slave {
            libc::close(master);
            return;
        }

        let mut tio: libc::termios = core::mem::zeroed();
        let raw_ok = libc::tcgetattr(slave, &mut tio) == 0;
        if raw_ok {
            tio.c_lflag &= !((libc::ECHO | libc::ICANON) as libc::tcflag_t);
            libc::tcsetattr(slave, libc::TCSANOW, &tio);
        }

        let child = libc::fork();
        if child == 0 {
            libc::close(slave);
            let reopened = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0u32);
            if reopened >= 0 {
                libc::close(reopened);
                libc::_exit(0);
            }
            libc::_exit(9);
        }

        let (wait_rc, status) = reap(child);
        let child_reopened_slave =
            wait_rc == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

        let payload = b"fork";
        let write_ok = libc::write(master, payload.as_ptr().cast(), payload.len())
            == payload.len() as isize;
        let mut buf = [0u8; 4];
        let read_ok = libc::read(slave, buf.as_mut_ptr().cast(), buf.len()) == buf.len() as isize;

        report!(
            child_reopened_slave = child_reopened_slave,
            parent_slave_still_reads = write_ok && read_ok && buf == *payload,
        );

        libc::close(slave);
        libc::close(master);
    }
}
