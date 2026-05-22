//! PTY round-trip probe: posix_openpt -> grantpt -> unlockpt -> ptsname ->
//! open slave -> write master/read slave (and reverse). Prints deterministic,
//! host-independent lines so carrick and real Linux match exactly.
//!
//! The slave device index (N in /dev/pts/N) is stripped — only the directory
//! prefix "/dev/pts" is printed, which is stable across both environments.

use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");

        assert_eq!(libc::grantpt(master), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");

        let name_ptr = libc::ptsname(master);
        assert!(!name_ptr.is_null(), "ptsname returned NULL");
        let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();

        // Print only the directory prefix so the device index N doesn't cause
        // spurious mismatches between runs / environments.
        let prefix = name.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        println!("slave_prefix={prefix}");

        // Re-call ptsname for the open — same pointer but still valid before
        // any other pty call.
        let name_ptr2 = libc::ptsname(master);
        assert!(!name_ptr2.is_null(), "ptsname (2nd call) returned NULL");
        let slave_fd = libc::open(
            name_ptr2,
            libc::O_RDWR | libc::O_NOCTTY,
            0u32,
        );
        assert!(slave_fd >= 0, "open slave failed");

        println!("slave_isatty={}", libc::isatty(slave_fd));

        // Put the slave in raw mode so the master read is deterministic:
        // no echo, no canonical processing transforming the data.
        let mut tio: libc::termios = std::mem::zeroed();
        libc::tcgetattr(slave_fd, &mut tio);
        tio.c_lflag &= !((libc::ECHO | libc::ICANON) as libc::tcflag_t);
        libc::tcsetattr(slave_fd, libc::TCSANOW, &tio);

        let mut master_f = std::fs::File::from_raw_fd(master);
        let mut slave_f = std::fs::File::from_raw_fd(slave_fd);

        // Master -> slave direction.
        master_f.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        slave_f.read_exact(&mut buf).unwrap();
        println!("slave_got={}", std::str::from_utf8(&buf).unwrap());

        // Slave -> master direction.
        slave_f.write_all(b"pong").unwrap();
        let mut buf2 = [0u8; 4];
        master_f.read_exact(&mut buf2).unwrap();
        println!("master_got={}", std::str::from_utf8(&buf2).unwrap());
    }
}
